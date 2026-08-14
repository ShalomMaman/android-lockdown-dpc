package com.example.lockdowndpc.maintenance;

import android.app.job.JobParameters;
import android.app.job.JobService;
import android.util.Log;

import com.example.lockdowndpc.policy.PolicyReconciliationCoordinator;

/**
 * The scheduled pass that closes a lapsed maintenance window.
 *
 * <p>It carries no rules of its own: it hands straight to
 * {@link MaintenanceGuard#refresh}, which asks the same
 * {@link MaintenanceCoordinator} the console asks. A device with nothing open
 * reads one preference file and finishes.
 *
 * <p>The work runs on the shared policy executor rather than on the job's main
 * thread, because a restore makes many {@code DevicePolicyManager} calls.
 */
public final class MaintenanceGuardJobService extends JobService {

    private static final String TAG = "MaintenanceGuardJob";

    @Override
    public boolean onStartJob(JobParameters params) {
        PolicyReconciliationCoordinator.runOnPolicyThread(() -> {
            try {
                MaintenanceGuard.refresh(getApplicationContext());
            } catch (RuntimeException exception) {
                // A crash here would be invisible, so it is logged rather than
                // swallowed. The periodic sweep tries again either way.
                Log.e(TAG, "Maintenance refresh failed", exception);
            } finally {
                jobFinished(params, false);
            }
        });
        return true;
    }

    @Override
    public boolean onStopJob(JobParameters params) {
        // Reschedule: a window whose deadline was missed has to be closed, and
        // the next pass reaches the same conclusion from the stored record.
        return true;
    }
}
