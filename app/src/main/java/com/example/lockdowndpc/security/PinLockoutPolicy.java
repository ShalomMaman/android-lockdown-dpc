package com.example.lockdowndpc.security;

/**
 * Pure lockout arithmetic for the administrator PIN.
 *
 * <p>The wall clock is not a trustworthy time source for throttling. Before
 * Android 9 the {@code DISALLOW_CONFIG_DATE_TIME} restriction is unavailable, so
 * a local user can open the date-and-time settings, move the clock forward and
 * clear a deadline expressed in {@link System#currentTimeMillis()}. This policy
 * therefore measures an active penalty with monotonic time (the caller supplies
 * {@code android.os.SystemClock#elapsedRealtime()}) and pins it to the boot it
 * was armed in.
 *
 * <p>Conservative semantics, in order of precedence:
 *
 * <ul>
 *   <li><b>Same boot</b>: only monotonic time can retire a penalty. Moving the
 *       wall clock in either direction has no effect.</li>
 *   <li><b>Boot boundary</b>: monotonic time restarts at reboot, so a penalty
 *       armed in an earlier boot cannot be measured any more. It is re-armed for
 *       its full configured duration instead of being cleared. A reboot can
 *       therefore lengthen a penalty, never shorten it. The penalty is dropped
 *       as soon as it is served and a verification attempt is made, so the
 *       re-arm only affects a reboot inside an unserved penalty.</li>
 *   <li><b>Legacy state</b>: an installation that only has the wall-clock
 *       deadline written by earlier versions is honoured once, clamped to
 *       {@link #MAX_PENALTY_MILLIS}, and immediately migrated to monotonic
 *       time.</li>
 *   <li><b>Inconsistent state</b>: an armed penalty with an unusable or absurd
 *       deadline is re-armed rather than ignored, but never for longer than
 *       {@link #MAX_PENALTY_MILLIS}, so corrupt state cannot lock an
 *       administrator out permanently.</li>
 * </ul>
 *
 * <p>The failure counter is independent of the penalty: it survives expiry,
 * reboots and migration so that penalties stay progressive, and is only reset by
 * a successful PIN or recovery-code verification.
 *
 * <p>This class is intentionally free of Android APIs so the boundary can be
 * covered by JVM regression tests.
 */
public final class PinLockoutPolicy {

    /** Longest penalty this policy will ever impose or honour. */
    public static final long MAX_PENALTY_MILLIS = 60 * 60_000L;

    /** Number of consecutive failures before the first penalty is imposed. */
    public static final int FIRST_PENALTY_FAILURE = 5;

    /**
     * Tolerance for the fallback boot identity. The fallback is derived from the
     * difference between two clocks sampled a few microseconds apart, which the
     * platform may also nudge by small NTP corrections.
     */
    private static final long BOOT_WALL_TOLERANCE_MILLIS = 5_000L;

    private PinLockoutPolicy() {}

    /** How the current boot is identified. */
    public enum BootKind {
        /** No usable identity; a penalty cannot be pinned to this boot. */
        NONE,
        /** {@code Settings.Global.BOOT_COUNT}, which only a privileged caller can change. */
        BOOT_COUNT,
        /** Fallback: the wall time the current boot started at. */
        BOOT_WALL_TIME
    }

    /** Identity of a boot, used to detect that monotonic time restarted. */
    public record BootId(BootKind kind, long value) {
        public static final BootId UNKNOWN = new BootId(BootKind.NONE, 0L);

        public BootId {
            if (kind == null) {
                kind = BootKind.NONE;
            }
            if (kind == BootKind.NONE) {
                value = 0L;
            }
        }

        public static BootId ofBootCount(long bootCount) {
            return new BootId(BootKind.BOOT_COUNT, bootCount);
        }

        public static BootId ofBootWallTime(long bootWallMillis) {
            return new BootId(BootKind.BOOT_WALL_TIME, bootWallMillis);
        }

        public boolean known() {
            return kind != BootKind.NONE;
        }

        /**
         * Returns {@code true} only when both identities describe the same boot.
         * Anything unknown, mismatched or unrepresentable is treated as a
         * different boot, which re-arms rather than clears a penalty.
         */
        public boolean sameBootAs(BootId other) {
            if (other == null || !known() || kind != other.kind) {
                return false;
            }
            if (kind == BootKind.BOOT_COUNT) {
                return value == other.value;
            }
            long difference;
            try {
                difference = Math.subtractExact(value, other.value);
            } catch (ArithmeticException unrepresentable) {
                return false;
            }
            return difference >= -BOOT_WALL_TOLERANCE_MILLIS
                    && difference <= BOOT_WALL_TOLERANCE_MILLIS;
        }
    }

    /**
     * Persisted lockout state.
     *
     * @param failures             consecutive failed verifications
     * @param armedBoot            boot the active penalty was armed in
     * @param armedElapsedDeadline monotonic deadline inside {@code armedBoot}
     * @param penaltyMillis        full duration of the active penalty
     * @param wallDeadline         wall-clock deadline, kept as supplemental
     *                             evidence for migration and for downgrades to
     *                             an earlier version; never the sole source of
     *                             truth while {@code armedBoot} is known
     */
    public record LockoutState(
            int failures,
            BootId armedBoot,
            long armedElapsedDeadline,
            long penaltyMillis,
            long wallDeadline
    ) {
        /** No failures recorded and no penalty owed. */
        public static final LockoutState CLEARED =
                new LockoutState(0, BootId.UNKNOWN, 0L, 0L, 0L);

        public LockoutState {
            if (armedBoot == null) {
                armedBoot = BootId.UNKNOWN;
            }
            if (failures < 0) {
                failures = 0;
            }
        }

        /** Whether a penalty is pinned to a specific boot. */
        public boolean penaltyArmed() {
            return armedBoot.known() && penaltyMillis > 0L;
        }

        /** Keeps the progressive failure count, drops the penalty. */
        public LockoutState withoutPenalty() {
            return new LockoutState(failures, BootId.UNKNOWN, 0L, 0L, 0L);
        }
    }

    /**
     * Outcome of evaluating stored state against the current clocks.
     *
     * @param remainingMillis  milliseconds left of the penalty, {@code 0} when unlocked
     * @param state            state that must now be treated as authoritative
     * @param persistRequired  whether {@code state} differs from what was stored
     */
    public record Evaluation(long remainingMillis, LockoutState state, boolean persistRequired) {
        public boolean locked() {
            return remainingMillis > 0L;
        }
    }

    /**
     * Decides whether a verification attempt is currently allowed.
     *
     * @param stored          state read from storage
     * @param currentBoot     identity of the running boot
     * @param elapsedRealtime monotonic milliseconds since boot
     * @param wallMillis      current wall clock, used only for legacy state
     */
    public static Evaluation evaluate(
            LockoutState stored,
            BootId currentBoot,
            long elapsedRealtime,
            long wallMillis
    ) {
        LockoutState state = stored == null ? LockoutState.CLEARED : stored;
        BootId boot = currentBoot == null ? BootId.UNKNOWN : currentBoot;

        if (state.penaltyArmed()) {
            if (boot.sameBootAs(state.armedBoot())) {
                return evaluateSameBoot(state, boot, elapsedRealtime, wallMillis);
            }
            // Monotonic time restarted, so the outstanding penalty can no longer
            // be measured. Re-arm it instead of letting a reboot cancel it.
            return arm(state, boot, elapsedRealtime, wallMillis, rearmDuration(state));
        }

        if (state.wallDeadline() > 0L) {
            // Legacy (or downgrade-written) state: wall-clock deadline only.
            long remaining = state.wallDeadline() - wallMillis;
            if (remaining > 0L) {
                return arm(state, boot, elapsedRealtime, wallMillis,
                        Math.min(remaining, MAX_PENALTY_MILLIS));
            }
            return new Evaluation(0L, state.withoutPenalty(), true);
        }

        return new Evaluation(0L, state, false);
    }

    /**
     * Records a failed verification and arms the next progressive penalty.
     *
     * @param current         state that was evaluated for this attempt
     * @param currentBoot     identity of the running boot
     * @param elapsedRealtime monotonic milliseconds since boot
     * @param wallMillis      current wall clock, stored as supplemental evidence
     */
    public static LockoutState afterFailure(
            LockoutState current,
            BootId currentBoot,
            long elapsedRealtime,
            long wallMillis
    ) {
        LockoutState state = current == null ? LockoutState.CLEARED : current;
        int failures = state.failures() == Integer.MAX_VALUE
                ? Integer.MAX_VALUE
                : state.failures() + 1;
        long penalty = penaltyMillis(failures);
        if (penalty <= 0L) {
            return new LockoutState(failures, BootId.UNKNOWN, 0L, 0L, 0L);
        }
        BootId boot = currentBoot == null ? BootId.UNKNOWN : currentBoot;
        return new LockoutState(
                failures,
                boot,
                saturatedAdd(elapsedRealtime, penalty),
                penalty,
                saturatedAdd(wallMillis, penalty)
        );
    }

    /** Progressive penalty ladder applied after {@code failures} consecutive errors. */
    public static long penaltyMillis(int failures) {
        if (failures < FIRST_PENALTY_FAILURE) {
            return 0L;
        }
        if (failures == 5) {
            return 60_000L;
        }
        if (failures == 6) {
            return 5 * 60_000L;
        }
        if (failures == 7) {
            return 30 * 60_000L;
        }
        return MAX_PENALTY_MILLIS;
    }

    private static Evaluation evaluateSameBoot(
            LockoutState state,
            BootId boot,
            long elapsedRealtime,
            long wallMillis
    ) {
        long deadline = state.armedElapsedDeadline();
        if (deadline <= 0L) {
            // Armed without a usable deadline: treat the penalty as unserved.
            return arm(state, boot, elapsedRealtime, wallMillis, rearmDuration(state));
        }

        long remaining;
        try {
            remaining = Math.subtractExact(deadline, elapsedRealtime);
        } catch (ArithmeticException unrepresentable) {
            remaining = Long.MAX_VALUE;
        }
        if (remaining > MAX_PENALTY_MILLIS) {
            // Further away than any penalty this policy issues. Stay locked, but
            // bounded, so inconsistent state cannot brick an administrator.
            return arm(state, boot, elapsedRealtime, wallMillis, MAX_PENALTY_MILLIS);
        }
        if (remaining > 0L) {
            return new Evaluation(remaining, state, false);
        }
        // Served. Drop the penalty, keep the progressive failure count.
        return new Evaluation(0L, state.withoutPenalty(), true);
    }

    private static Evaluation arm(
            LockoutState state,
            BootId boot,
            long elapsedRealtime,
            long wallMillis,
            long penalty
    ) {
        long duration = Math.min(Math.max(penalty, 0L), MAX_PENALTY_MILLIS);
        if (duration == 0L) {
            return new Evaluation(0L, state.withoutPenalty(), true);
        }
        LockoutState armed = new LockoutState(
                state.failures(),
                boot,
                saturatedAdd(elapsedRealtime, duration),
                duration,
                saturatedAdd(wallMillis, duration)
        );
        return new Evaluation(duration, armed, true);
    }

    /**
     * Duration to re-arm with. The configured penalty for the recorded failure
     * count and the stored duration are both considered so that neither a reset
     * counter nor a truncated duration can shorten the penalty, and the result
     * is capped at {@link #MAX_PENALTY_MILLIS}.
     */
    private static long rearmDuration(LockoutState state) {
        long configured = penaltyMillis(state.failures());
        long stored = Math.max(state.penaltyMillis(), 0L);
        return Math.min(Math.max(configured, stored), MAX_PENALTY_MILLIS);
    }

    private static long saturatedAdd(long base, long delta) {
        try {
            return Math.addExact(base, delta);
        } catch (ArithmeticException overflow) {
            return Long.MAX_VALUE;
        }
    }
}
