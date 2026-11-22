package com.example.lockdowndpc.policy;

import android.app.admin.DevicePolicyManager;
import android.content.Intent;
import android.os.PersistableBundle;

import androidx.core.content.IntentCompat;

import com.example.lockdowndpc.BuildConfig;

public final class RemoteEnrolmentGate {
    private RemoteEnrolmentGate() {}

    /**
     * Nothing in this application writes this field, so in a shipped build the
     * gate is the build constant alone. The JVM tests set it by reflection, from
     * the test tree, to run the gated code. A source test keeps it that way.
     */
    private static boolean openedByTest;

    public static boolean permits() {
        return BuildConfig.REMOTE_ENROLMENT_ENABLED || openedByTest;
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
