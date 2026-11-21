package com.example.lockdowndpc.policy;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * Night and work hours enforcement inside the policy pass, independent of Android.
 *
 * <p>Every pass recomputes from the clock: the active windows come from
 * {@link SchedulePolicy#activeWindows} at {@code now}, never from a stored
 * "in window" flag, so a clock jump, a reboot across a boundary or a timezone
 * change converges on the next pass. Package suspension is the only mechanism;
 * hiding stays with the base package policy.
 *
 * <p>Ownership: Android keeps one suspension flag per package for this admin,
 * and other steps of the pass use it too (the social containment fallback, the
 * Chrome exemption, a browser-backed WebView provider). The schedule therefore
 * records which packages <em>it</em> suspended and only ever releases those.
 * A package already suspended by someone else is never claimed, and an owned
 * package that another step now needs suspended is handed over (dropped from
 * the record) instead of released. Ownership is saved before a suspension, so
 * a pass that dies midway never leaves a schedule suspension nobody tracks.
 *
 * <p>Every change is read back. A refusal, a silently ignored call or an
 * exception adds an error token, so the pass is never reported as verified.
 */
public final class ScheduleSuspension {

    public static final String SUSPEND_REFUSED = "schedule-suspend-refused";
    public static final String SUSPEND_UNVERIFIED = "schedule-suspend-unverified";
    public static final String SUSPEND_FAILED = "schedule-suspend";
    public static final String RELEASE_UNVERIFIED = "schedule-release-unverified";
    public static final String RELEASE_FAILED = "schedule-release";
    public static final String OWNERSHIP_UNSAVED = "schedule-ownership-unsaved";
    public static final String OWNERSHIP_UNREADABLE = "schedule-ownership-unreadable";
    public static final String INVENTORY_FAILED = "schedule-inventory";
    public static final String ALARM_FAILED = "schedule-alarm";

    private ScheduleSuspension() {}

    /** The Android side, one call per question. Any call may throw. */
    public interface Gateway {
        /** Packages with a launcher entry for this user right now. */
        Set<String> launchablePackages();

        /**
         * Whether Android reports the package suspended by this admin, or
         * {@code null} when the package is not installed.
         */
        Boolean suspended(String packageName);

        /**
         * Asks Android to change suspension.
         *
         * @return the packages Android refused
         */
        String[] setSuspended(String[] packageNames, boolean suspended);

        /** Packages this schedule suspended, as recorded. */
        Set<String> owned();

        /** Records the owned packages durably; {@code false} when it was not persisted. */
        boolean saveOwned(Set<String> owned);

        /** Arms the next boundary alarm. */
        void armBoundary(Instant at);

        /** Cancels the boundary alarm. */
        void cancelBoundary();
    }

    /**
     * What the pass knows about this device beyond the schedule.
     *
     * @param alwaysAvailable packages never suspended by a window: this app, the
     *                        trusted management and VPN apps, essential system
     *                        packages, the default dialer, SMS, clock, launcher,
     *                        active input method and WebView provider, and the
     *                        kiosk target or maintenance stores while they apply
     * @param heldByOthers    packages another step of this pass needs suspended
     *                        or contained; the schedule never releases them
     */
    public record Device(Set<String> alwaysAvailable, Set<String> heldByOthers) {
        public Device {
            alwaysAvailable = alwaysAvailable == null ? Set.of() : Set.copyOf(alwaysAvailable);
            heldByOthers = heldByOthers == null ? Set.of() : Set.copyOf(heldByOthers);
        }
    }

    /**
     * @param activeWindows the windows in force at the pass's instant
     * @param suspended     packages the schedule holds suspended after the pass
     * @param nextBoundary  the alarm the pass armed, if any
     */
    public record Result(Set<String> activeWindows, Set<String> suspended, Optional<Instant> nextBoundary) {
        public Result {
            activeWindows = Set.copyOf(activeWindows);
            suspended = Collections.unmodifiableSet(new TreeSet<>(suspended));
        }
    }

    /** The windows in force at {@code now}; none when nothing is enforced. */
    public static Set<String> activeWindows(ScheduleSettings settings, Instant now) {
        if (settings == null || settings.schedule() == null) {
            return Set.of();
        }
        return SchedulePolicy.activeWindows(settings.schedule(), now);
    }

    /**
     * The packages the schedule holds right now: its recorded packages while a
     * window is active, otherwise none. Another step must not release these.
     */
    public static Set<String> holding(ScheduleSettings settings, Instant now, Set<String> owned) {
        return activeWindows(settings, now).isEmpty() || owned == null ? Set.of() : Set.copyOf(owned);
    }

    /** One policy pass: suspend inside a window, release outside it, re-arm the boundary. */
    public static Result reconcile(
            ScheduleSettings settings,
            Instant now,
            Device device,
            Gateway gateway,
            List<String> errors
    ) {
        if (settings.unreadable()) {
            errors.add(ScheduleSettings.UNREADABLE_ERROR);
        }
        Set<String> active = activeWindows(settings, now);
        TreeSet<String> owned = readOwned(gateway, errors);
        if (!active.isEmpty() || !owned.isEmpty()) {
            enforce(settings, active, device, owned, gateway, errors);
        }
        Optional<Instant> next = settings.schedule() == null
                ? Optional.empty()
                : SchedulePolicy.nextTransition(settings.schedule(), now);
        try {
            if (next.isPresent()) {
                gateway.armBoundary(next.get());
            } else if (settings.schedule() != null || !owned.isEmpty()) {
                // A schedule that was turned off may have left an alarm armed.
                gateway.cancelBoundary();
            }
        } catch (RuntimeException exception) {
            errors.add(ALARM_FAILED + ":" + exception.getClass().getSimpleName());
        }
        return new Result(active, owned, next);
    }

    /**
     * Releases every package the schedule suspended and cancels the boundary
     * alarm, for a protection pause. A release Android does not confirm stays
     * recorded and is reported.
     */
    public static void releaseAll(Gateway gateway, List<String> errors) {
        TreeSet<String> owned = readOwned(gateway, errors);
        try {
            gateway.cancelBoundary();
        } catch (RuntimeException exception) {
            errors.add(ALARM_FAILED + ":" + exception.getClass().getSimpleName());
        }
        if (owned.isEmpty()) {
            return;
        }
        TreeSet<String> remaining = new TreeSet<>(owned);
        for (String packageName : owned) {
            if (release(packageName, gateway, errors)) {
                remaining.remove(packageName);
            }
        }
        saveOwned(gateway, remaining, errors);
    }

    private static void enforce(
            ScheduleSettings settings,
            Set<String> active,
            Device device,
            TreeSet<String> owned,
            Gateway gateway,
            List<String> errors
    ) {
        LinkedHashSet<String> exempt = new LinkedHashSet<>(device.alwaysAvailable());
        exempt.addAll(settings.allowlist());

        TreeSet<String> target = new TreeSet<>();
        if (!active.isEmpty()) {
            try {
                target.addAll(gateway.launchablePackages());
            } catch (RuntimeException exception) {
                // Without an inventory nothing new is suspended, and nothing
                // already held is released either.
                errors.add(INVENTORY_FAILED + ":" + exception.getClass().getSimpleName());
            }
            target.addAll(owned);
            target.removeAll(exempt);
        }

        boolean ownershipChanged = false;
        // Release first: what is no longer in the target, unless another step holds it.
        for (String packageName : new ArrayList<>(owned)) {
            if (target.contains(packageName)) {
                continue;
            }
            if (device.heldByOthers().contains(packageName) || release(packageName, gateway, errors)) {
                owned.remove(packageName);
                ownershipChanged = true;
            }
        }

        // Then claim: only packages Android reports installed and not suspended.
        ArrayList<String> candidates = new ArrayList<>();
        for (String packageName : target) {
            Boolean suspended;
            try {
                suspended = gateway.suspended(packageName);
            } catch (RuntimeException exception) {
                errors.add(SUSPEND_FAILED + ":" + packageName + ":" + exception.getClass().getSimpleName());
                continue;
            }
            if (suspended == null) {
                if (owned.remove(packageName)) {
                    ownershipChanged = true;
                }
            } else if (!suspended) {
                candidates.add(packageName);
            }
            // Suspended and owned: already ours. Suspended and not owned:
            // another step's suspension, which the schedule never claims.
        }

        if (candidates.isEmpty()) {
            if (ownershipChanged) {
                saveOwned(gateway, owned, errors);
            }
            return;
        }
        TreeSet<String> claimed = new TreeSet<>(owned);
        claimed.addAll(candidates);
        if (!saveOwned(gateway, claimed, errors)) {
            // An untracked suspension would never be released; suspend nothing.
            return;
        }
        owned.clear();
        owned.addAll(claimed);

        Set<String> refused = new LinkedHashSet<>();
        try {
            String[] failed = gateway.setSuspended(candidates.toArray(new String[0]), true);
            if (failed != null) {
                Collections.addAll(refused, failed);
            }
        } catch (RuntimeException exception) {
            errors.add(SUSPEND_FAILED + ":" + exception.getClass().getSimpleName());
        }
        boolean dropped = false;
        for (String packageName : candidates) {
            Boolean suspended;
            try {
                suspended = gateway.suspended(packageName);
            } catch (RuntimeException exception) {
                // Unknown: keep the record so a later pass can release it.
                errors.add(SUSPEND_UNVERIFIED + ":" + packageName);
                continue;
            }
            if (Boolean.TRUE.equals(suspended)) {
                continue;
            }
            if (suspended != null) {
                errors.add((refused.contains(packageName) ? SUSPEND_REFUSED : SUSPEND_UNVERIFIED)
                        + ":" + packageName);
            }
            // Not suspended (or gone): not ours, so another step may use it.
            owned.remove(packageName);
            dropped = true;
        }
        if (dropped) {
            saveOwned(gateway, owned, errors);
        }
    }

    /** @return whether the package no longer carries a suspension to release */
    private static boolean release(String packageName, Gateway gateway, List<String> errors) {
        try {
            Boolean suspended = gateway.suspended(packageName);
            if (suspended == null || !suspended) {
                return true;
            }
            String[] failed = gateway.setSuspended(new String[]{packageName}, false);
            Boolean after = gateway.suspended(packageName);
            if (after == null || !after) {
                return true;
            }
            errors.add(RELEASE_UNVERIFIED + ":" + packageName
                    + (failed != null && failed.length > 0 ? ":refused" : ""));
            return false;
        } catch (RuntimeException exception) {
            errors.add(RELEASE_FAILED + ":" + packageName + ":" + exception.getClass().getSimpleName());
            return false;
        }
    }

    private static TreeSet<String> readOwned(Gateway gateway, List<String> errors) {
        try {
            Set<String> owned = gateway.owned();
            return owned == null ? new TreeSet<>() : new TreeSet<>(owned);
        } catch (RuntimeException exception) {
            errors.add(OWNERSHIP_UNREADABLE + ":" + exception.getClass().getSimpleName());
            return new TreeSet<>();
        }
    }

    private static boolean saveOwned(Gateway gateway, Set<String> owned, List<String> errors) {
        boolean saved;
        try {
            saved = gateway.saveOwned(Collections.unmodifiableSet(new TreeSet<>(owned)));
        } catch (RuntimeException exception) {
            saved = false;
        }
        if (!saved) {
            errors.add(OWNERSHIP_UNSAVED);
        }
        return saved;
    }
}
