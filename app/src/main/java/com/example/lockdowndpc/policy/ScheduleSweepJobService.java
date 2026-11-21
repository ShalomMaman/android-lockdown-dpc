package com.example.lockdowndpc.policy;

import android.app.job.JobParameters;
import android.app.job.JobService;

/**
 * The night and work hours sweep: the periodic job, armed only while a
 * schedule is enforcing and cancelled with the boundary alarm, and the one-off
 * retry after a pass that was not verified.
 *
 * <p>It carries no rules of its own: on the shared policy thread it runs
 * {@link ScheduleAlarm#catchUp}, which reads the stored schedule and queues a
 * full policy pass only when a boundary passed without a verified one and no
 * retry backoff is pending. A run that finds nothing due reads two preference
 * files and finishes. A queued pass that fails schedules the next retry itself.
 */
public final class ScheduleSweepJobService extends JobService {

    @Override
    public boolean onStartJob(JobParameters params) {
        PolicyReconciliationCoordinator.runOnPolicyThread(() -> {
            boolean queued = false;
            try {
                // The job stays running until a queued pass ends, so Doze does
                // not suspend the process between the check and the pass.
                String trigger = params.getJobId() == ScheduleAlarm.RETRY_JOB_ID ? "retry" : "sweep";
                queued = ScheduleAlarm.catchUp(getApplicationContext(), trigger,
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
