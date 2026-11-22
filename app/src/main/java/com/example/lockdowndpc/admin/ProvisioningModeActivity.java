package com.example.lockdowndpc.admin;

import static android.app.admin.DevicePolicyManager.ACTION_GET_PROVISIONING_MODE;
import static android.app.admin.DevicePolicyManager.EXTRA_PROVISIONING_ALLOWED_PROVISIONING_MODES;
import static android.app.admin.DevicePolicyManager.EXTRA_PROVISIONING_MODE;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;

import com.example.lockdowndpc.policy.RemoteEnrolmentGate;

import java.util.OptionalInt;

/** Selects fully managed mode for the setup wizard. */
public final class ProvisioningModeActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Intent request = getIntent();
        setResult(RESULT_CANCELED);
        if (RemoteEnrolmentGate.permitsLocalProvisioning(request)
                && ACTION_GET_PROVISIONING_MODE.equals(request.getAction())) {
            OptionalInt mode = ProvisioningFlow.selectMode(
                    request.hasExtra(EXTRA_PROVISIONING_ALLOWED_PROVISIONING_MODES),
                    request.getIntegerArrayListExtra(EXTRA_PROVISIONING_ALLOWED_PROVISIONING_MODES));
            if (mode.isPresent()) {
                setResult(RESULT_OK, new Intent().putExtra(EXTRA_PROVISIONING_MODE, mode.getAsInt()));
            }
        }
        finish();
    }
}
