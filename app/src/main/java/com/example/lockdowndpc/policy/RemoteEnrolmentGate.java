package com.example.lockdowndpc.policy;

import android.app.admin.DevicePolicyManager;
import android.content.Intent;
import android.os.PersistableBundle;

import androidx.core.content.IntentCompat;

import com.example.lockdowndpc.BuildConfig;

public final class RemoteEnrolmentGate {
    private RemoteEnrolmentGate() {}

    public static boolean permits() {
        return BuildConfig.REMOTE_ENROLMENT_ENABLED;
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
        if (extras == null && request.hasExtra(DevicePolicyManager.EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE)
                && rawAdminExtras(request) != null) {
            // Present with a non-null value the typed read rejected: unreadable, fail closed.
            throw new IllegalArgumentException();
        }
        if (extras == null || extras.keySet().stream().noneMatch(key -> key.startsWith("dg.remote."))) {
            return null;
        }
        return extras;
    }

    /**
     * Android always puts the admin-extras key into GET_PROVISIONING_MODE and
     * ADMIN_POLICY_COMPLIANCE, with a null value when the QR code carries no
     * admin extras (AOSP PreProvisioningActivityController). A null value means
     * "no extras", not "unreadable".
     */
    @SuppressWarnings("deprecation")
    private static Object rawAdminExtras(Intent request) {
        android.os.Bundle all = request.getExtras();
        return all == null ? null : all.get(DevicePolicyManager.EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE);
    }
}
