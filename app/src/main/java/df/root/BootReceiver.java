package df.root;

import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.PowerManager;
import android.util.Log;

import df.root.exploit.ExploitOptions;
import df.root.exploit.ExploitResult;
import df.root.exploit.ExploitRunner;
import df.root.exploit.IReporter;

/**
 * Auto-root on boot. Safety rules learned in the field:
 *  - A failed run disables the receiver; the user re-enables it in the app.
 *  - Soft reboot at boot only ever happens when the user explicitly opted in
 *    on the Autorun card (same as pre-3.2 behaviour).
 *
 * The exploit library writes soft_reboot / su_manager / disable_modules into the
 * device-protected prefs itself, so this receiver only has to decide whether to
 * run and with which options.
 */
public class BootReceiver extends BroadcastReceiver implements IReporter {
    private static final String TAG = "dfroot";

    @Override
    public void report(String msg) {
        Log.i(TAG, msg.trim());
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        if (ExploitRunner.isAlreadyHooked()) {
            Log.i(TAG, "boot: already hooked, skipping");
            return;
        }
        Log.i(TAG, "boot: " + intent.getAction());
        final Context deCtx = context.createDeviceProtectedStorageContext();
        SharedPreferences sp = deCtx.getSharedPreferences(ExploitRunner.PREFS_NAME,
                Context.MODE_PRIVATE);
        boolean expert = sp.getBoolean("expert_mode", false);
        if (!expert) {
            Log.i(TAG, "boot: expert mode off - autorun skipped");
            return;
        }
        String suManager = sp.getString("su_manager", null);
        if (suManager == null) {
            Log.i(TAG, "boot: no SU manager selected - autorun skipped");
            return;
        }
        boolean autoSoftReboot = sp.getBoolean("auto_soft_reboot", false);
        boolean disableModules = sp.getBoolean("disable_modules", false);
        // auto_soft_reboot=true: on success, ksud triggers its OWN soft reboot
        // after late-load completes - so Zygisk/LSPosed modules (which need a
        // fresh Zygote with the module loaded) become active in the same power
        // session. With it off, the exploit still roots the device but nothing
        // reboots.

        PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
        PowerManager.WakeLock wl = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "dfroot:boot");
        wl.acquire();
        new Thread(() -> {
            boolean ok = false;
            try {
                ExploitResult result = ExploitRunner.run(deCtx,
                        new ExploitOptions(suManager, autoSoftReboot, disableModules), this);
                Log.i(TAG, "boot: exploit " + result);
                ok = result == ExploitResult.OK || result == ExploitResult.ALREADY_HOOKED;
            } catch (Exception e) {
                Log.e(TAG, "boot: exploit exception", e);
            } finally {
                wl.release();
            }
            if (!ok) {
                Log.i(TAG, "boot: failed - disabling autorun interlock");
                context.getPackageManager().setComponentEnabledSetting(
                        new ComponentName(context, BootReceiver.class),
                        PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                        PackageManager.DONT_KILL_APP);
            }
        }, "dfroot-boot").start();
    }
}