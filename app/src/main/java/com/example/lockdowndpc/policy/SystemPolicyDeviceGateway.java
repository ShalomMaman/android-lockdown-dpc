package com.example.lockdowndpc.policy;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;

/**
 * The production {@link SystemPolicyGateway}: official Device Owner calls only.
 *
 * <p>Reads go through {@code getUserRestrictions(admin)} every time rather than
 * through a cached bundle, because the point of the read is to find out what the
 * platform did with the write that just happened.
 */
public final class SystemPolicyDeviceGateway implements SystemPolicyGateway {

    private final DevicePolicyManager dpm;
    private final ComponentName admin;

    public SystemPolicyDeviceGateway(DevicePolicyManager dpm, ComponentName admin) {
        this.dpm = dpm;
        this.admin = admin;
    }

    @Override
    public void addRestriction(String key) {
        dpm.addUserRestriction(admin, key);
    }

    @Override
    public void clearRestriction(String key) {
        dpm.clearUserRestriction(admin, key);
    }

    @Override
    public boolean isRestrictionInForce(String key) {
        return dpm.getUserRestrictions(admin).getBoolean(key);
    }
}
