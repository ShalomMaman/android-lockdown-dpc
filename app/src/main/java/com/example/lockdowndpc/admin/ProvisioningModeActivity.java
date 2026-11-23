package com.example.lockdowndpc.admin;

import static android.app.admin.DevicePolicyManager.ACTION_GET_PROVISIONING_MODE;
import static android.app.admin.DevicePolicyManager.EXTRA_PROVISIONING_ALLOWED_PROVISIONING_MODES;
import static android.app.admin.DevicePolicyManager.EXTRA_PROVISIONING_MODE;

import android.app.Activity;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;

import com.example.lockdowndpc.policy.RemoteEnrolmentGate;
import com.example.lockdowndpc.policy.RemoteTransport;

import java.util.OptionalInt;

/** Selects fully managed mode for the setup wizard. */
public final class ProvisioningModeActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Intent request = getIntent();
        setResult(RESULT_CANCELED);
        if (ACTION_GET_PROVISIONING_MODE.equals(request.getAction())) {
            boolean local = RemoteEnrolmentGate.permitsLocalProvisioning(request);
            boolean remote = !local && RemoteTransport.mark(this, request);
            if (!local && !remote) {
                finish();
                return;
            }
            boolean requireModes = remote ? Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
                    : request.hasExtra(EXTRA_PROVISIONING_ALLOWED_PROVISIONING_MODES);
            OptionalInt mode = ProvisioningFlow.selectMode(
                    requireModes,
                    request.getIntegerArrayListExtra(EXTRA_PROVISIONING_ALLOWED_PROVISIONING_MODES));
            if (mode.isPresent()) {
                setResult(RESULT_OK, new Intent().putExtra(EXTRA_PROVISIONING_MODE, mode.getAsInt()));
            }
        }
        finish();
    }
}
