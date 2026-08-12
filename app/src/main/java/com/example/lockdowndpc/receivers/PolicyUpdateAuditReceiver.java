package com.example.lockdowndpc.receivers;

import android.annotation.TargetApi;
import android.app.admin.PolicyUpdateReceiver;
import android.app.admin.PolicyUpdateResult;
import android.app.admin.TargetUser;
import android.content.Context;
import android.os.Bundle;

import com.example.lockdowndpc.R;
import com.example.lockdowndpc.policy.AllowedAppsStore;
import com.example.lockdowndpc.policy.AuditLog;

/** Receives authoritative asynchronous policy results on Android 14 and newer. */
@TargetApi(34)
public final class PolicyUpdateAuditReceiver extends PolicyUpdateReceiver {
    @Override
    public void onPolicySetResult(
            Context context,
            String policyIdentifier,
            Bundle additionalPolicyParams,
            TargetUser targetUser,
            PolicyUpdateResult policyUpdateResult
    ) {
        recordFailureIfNeeded(context, R.string.policy_event_set, policyIdentifier, additionalPolicyParams,
                policyUpdateResult);
    }

    @Override
    public void onPolicyChanged(
            Context context,
            String policyIdentifier,
            Bundle additionalPolicyParams,
            TargetUser targetUser,
            PolicyUpdateResult policyUpdateResult
    ) {
        recordFailureIfNeeded(context, R.string.policy_event_change, policyIdentifier, additionalPolicyParams,
                policyUpdateResult);
    }

    private static void recordFailureIfNeeded(
            Context context,
            int eventResource,
            String policyIdentifier,
            Bundle additionalPolicyParams,
            PolicyUpdateResult result
    ) {
        if (result.getResultCode() == PolicyUpdateResult.RESULT_POLICY_SET
                || !AllowedAppsStore.isProtectionEnabled(context)) {
            return;
        }
        String packageName = additionalPolicyParams.getString(EXTRA_PACKAGE_NAME, "");
        String target = packageName.isEmpty()
                ? policyIdentifier
                : policyIdentifier + " / " + packageName;
        String error = context.getString(
                R.string.policy_update_failure,
                context.getString(eventResource),
                target,
                result.getResultCode());
        AllowedAppsStore.markApplyFailed(context, error);
        AuditLog.append(context, error);
    }
}
