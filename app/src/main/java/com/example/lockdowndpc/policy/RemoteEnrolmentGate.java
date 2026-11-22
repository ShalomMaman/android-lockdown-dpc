package com.example.lockdowndpc.policy;

import android.app.admin.DevicePolicyManager;
import android.content.Intent;
import android.os.Build;
import android.os.PersistableBundle;

import androidx.core.content.IntentCompat;

import com.example.lockdowndpc.BuildConfig;

public final class RemoteEnrolmentGate {
    private RemoteEnrolmentGate() {}

    private static volatile boolean openedByTest;

    public static boolean permits() {
        return BuildConfig.REMOTE_ENROLMENT_ENABLED || openedByTest;
    }

    /**
     * Lets JVM tests run the gated code. It refuses to work on a device: only
     * the Robolectric runtime reports this build fingerprint, and a source test
     * keeps every caller in the test tree.
     */
    static void openForTests(boolean open) {
        if (!"robolectric".equals(Build.FINGERPRINT)) {
            throw new IllegalStateException("The enrolment gate is a build constant");
        }
        openedByTest = open;
    }

    /** Only local provisioning is implemented. Unreadable extras are refused. */
    public static boolean permitsLocalProvisioning(Intent request) {
        if (request == null) {
            return false;
        }
        try {
            PersistableBundle extras = IntentCompat.getParcelableExtra(request,
                    DevicePolicyManager.EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE, PersistableBundle.class);
            return extras == null
                    ? !request.hasExtra(DevicePolicyManager.EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE)
                    : extras.keySet().stream().noneMatch(key -> key.startsWith("dg.remote."));
        } catch (RuntimeException unreadable) {
            return false;
        }
    }
}
