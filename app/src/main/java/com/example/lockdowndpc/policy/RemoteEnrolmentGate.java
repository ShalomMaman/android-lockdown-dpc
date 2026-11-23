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

    /** Only a readable bundle without remote keys can enter local provisioning. */
    public static boolean permitsLocalProvisioning(Intent request) {
        try {
            return remoteExtras(request) == null;
        } catch (RuntimeException unreadable) {
            return false;
        }
    }

    static PersistableBundle remoteExtras(Intent request) {
        if (request == null) throw new IllegalArgumentException();
        PersistableBundle extras = IntentCompat.getParcelableExtra(request,
                DevicePolicyManager.EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE, PersistableBundle.class);
        if (extras == null && request.hasExtra(DevicePolicyManager.EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE)) {
            throw new IllegalArgumentException();
        }
        if (extras == null || extras.keySet().stream().noneMatch(key -> key.startsWith("dg.remote."))) {
            return null;
        }
        return extras;
    }
}
