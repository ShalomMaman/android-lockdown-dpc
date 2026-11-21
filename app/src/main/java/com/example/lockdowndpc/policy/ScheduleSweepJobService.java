package com.example.lockdowndpc.policy;

import android.app.job.JobParameters;
import android.app.job.JobService;

/**
 * The periodic night and work hours sweep, armed only while a schedule is
 * enforcing and cancelled with the boundary alarm.
 *
 * <p>It carries no rules of its own: on the shared policy thread it runs
 * {@link ScheduleAlarm#catchUp}, which reads the stored schedule and queues a
 * full policy pass only when a boundary passed without one. A sweep that finds
 * nothing missed reads two preference files and finishes.
 */
public final class ScheduleSweepJobService extends JobService {

    @Override
    public boolean onStartJob(JobParameters params) {
        PolicyReconciliationCoordinator.runOnPolicyThread(() -> {
            boolean queued = false;
            try {
                // The job stays running until a queued pass ends, so Doze does
                // not suspend the process between the check and the pass.
                queued = ScheduleAlarm.catchUp(getApplicationContext(), "sweep",
                        () -> jobFinished(params, false));
            } finally {
                if (!queued) {
                    jobFinished(params, false);
                }
            }
        });
        return true;
    }

    @Override
    public boolean onStopJob(JobParameters params) {
        // The next period checks again; a missed boundary is still missed then.
        return false;
    }
}
