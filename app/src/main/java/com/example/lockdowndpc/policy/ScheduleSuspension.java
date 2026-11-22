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
 * <p>Targets: while a window is active, every package outside the
 * always-available core and the allowlist is a window target ({@link Hold}).
 * The rule other steps of the pass follow is a single one: no step lifts a
 * suspension on a window target. That needs no ownership record, so it holds
 * even when the record cannot be read.
 *
 * <p>Ownership: inside a window the schedule suspends every target itself on
 * every pass, whatever Android reports first, because Android reports the
 * combined suspension state and another app's or step's suspension may be
 * lifted at any time. It records every target, and releases only what it
 * recorded. An owned package that another step needs suspended once the
 * window ends (the social containment fallback, Chrome while its exemption is
 * not shown) is handed over (dropped from the record) instead of released.
 * The record is saved before a suspension; a save that fails does not stop
 * the suspension, it marks the record unknown and is reported.
 *
 * <p>An unknown ownership record (a failed save, a wrong type, a damaged file
 * Android loaded as empty) is never read as "none", and the pass reports it.
 * No window target is ever released on account of it. Inside a window the
 * record is rewritten from a full inventory: every target. Outside a window no
 * package is a target, so every launchable package Android reports suspended
 * that no other step holds is released, which is what a readable record would
 * have led to, and the record is rewritten with whatever Android did not
 * confirm released.
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

        /** Packages this schedule suspended, as recorded; throws when the record is unreadable. */
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
     *                        or contained; the schedule never releases them. It
     *                        must name every package another step keeps
     *                        suspended outside a window: an unreadable record
     *                        is recovered against it.
     */
    public record Device(Set<String> alwaysAvailable, Set<String> heldByOthers) {
        public Device {
            alwaysAvailable = alwaysAvailable == null ? Set.of() : Set.copyOf(alwaysAvailable);
            heldByOthers = heldByOthers == null ? Set.of() : Set.copyOf(heldByOthers);
        }
    }

    /**
     * Which packages an active window targets, settled once per pass before any
     * package step runs. Other steps consult {@link #targets} and never lift a
     * suspension on a target.
     *
     * @param activeWindows the windows in force at the pass's instant
     * @param exempt        the always-available core and the allowlist
     */
    public record Hold(Set<String> activeWindows, Set<String> exempt) {
        public static final Hold NONE = new Hold(Set.of(), Set.of());

        public Hold {
            activeWindows = activeWindows == null ? Set.of() : Set.copyOf(activeWindows);
            exempt = exempt == null ? Set.of() : Set.copyOf(exempt);
        }

        /** The hold at {@code now}; {@code alwaysAvailable} matters only inside a window. */
        public static Hold of(ScheduleSettings settings, Instant now, Set<String> alwaysAvailable) {
            Set<String> active = ScheduleSuspension.activeWindows(settings, now);
            if (active.isEmpty()) {
                return NONE;
            }
            LinkedHashSet<String> exempt = new LinkedHashSet<>();
            if (alwaysAvailable != null) {
                exempt.addAll(alwaysAvailable);
            }
            exempt.addAll(settings.allowlist());
            return new Hold(active, exempt);
        }

        public boolean windowActive() {
            return !activeWindows.isEmpty();
        }

        /** Whether an active window wants the package suspended. */
        public boolean targets(String packageName) {
            return windowActive() && !exempt.contains(packageName);
        }
    }

    /**
     * @param activeWindows the windows in force at the pass's instant
     * @param suspended     packages the schedule holds suspended after the pass;
     *                      empty when ownership could not be read
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

    /** One policy pass: suspend inside a window, release outside it, re-arm the boundary. */
    public static Result reconcile(
            ScheduleSettings settings,
            Instant now,
            Device device,
            Gateway gateway,
            List<String> errors
    ) {
        return reconcile(settings, now, device, gateway, true, errors);
    }

    static Result reconcile(
            ScheduleSettings settings,
            Instant now,
            Device device,
            Gateway gateway,
            boolean allowRelease,
            List<String> errors
    ) {
        if (settings.unreadable()) {
            errors.add(ScheduleSettings.UNREADABLE_ERROR);
        }
        Set<String> active = activeWindows(settings, now);
        // null: the record is unreadable, so ownership is unknown.
        TreeSet<String> owned = readOwned(gateway, errors);
        if (owned == null && active.isEmpty()) {
            if (allowRelease) {
                owned = recover(device, gateway, errors);
            }
        } else if (owned == null || !active.isEmpty() || !owned.isEmpty()) {
            owned = enforce(settings, active, device, owned, gateway, allowRelease, errors);
        }
        Optional<Instant> next = settings.schedule() == null
                ? Optional.empty()
                : SchedulePolicy.nextTransition(settings.schedule(), now);
        try {
            if (next.isPresent()) {
                gateway.armBoundary(next.get());
            } else if (settings.schedule() != null || owned == null || !owned.isEmpty()) {
                // A schedule that was turned off may have left an alarm armed.
                gateway.cancelBoundary();
            }
        } catch (RuntimeException exception) {
            errors.add(ALARM_FAILED + ":" + exception.getClass().getSimpleName());
        }
        return new Result(active, owned == null ? Set.of() : owned, next);
    }

    /**
     * Releases every package the schedule suspended and cancels the boundary
     * alarm, for a protection pause. A release Android does not confirm stays
     * recorded and is reported. With an unreadable record, every launchable
     * package Android reports suspended is released, as a pause releases every
     * other suspension too, and the record is rewritten from the read-back.
     */
    public static void releaseAll(Gateway gateway, List<String> errors) {
        TreeSet<String> owned = readOwned(gateway, errors);
        try {
            gateway.cancelBoundary();
        } catch (RuntimeException exception) {
            errors.add(ALARM_FAILED + ":" + exception.getClass().getSimpleName());
        }
        if (owned == null) {
            recover(new Device(Set.of(), Set.of()), gateway, errors);
            return;
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

    /**
     * Inside a window, or outside one with packages still recorded: releases
     * what the schedule recorded and no longer targets, then records and
     * suspends every window target.
     *
     * <p>Every target is suspended by this admin on every pass, whatever
     * Android reports first: Android reports a package's combined suspension
     * state, and a suspension another app or step placed may be lifted at any
     * time. The call is idempotent. A record that cannot be saved does not
     * stop the suspension: the failed save marks the record unknown, which no
     * later pass reads as "nothing owned", and the pass reports it.
     *
     * @param owned the recorded packages, or {@code null} when unknown: then
     *              nothing is released, and the record is rewritten only from
     *              a full inventory
     * @return the record after the pass, or {@code null} when it stays unknown
     */
    private static TreeSet<String> enforce(
            ScheduleSettings settings,
            Set<String> active,
            Device device,
            TreeSet<String> owned,
            Gateway gateway,
            boolean allowRelease,
            List<String> errors
    ) {
        TreeSet<String> record = owned == null ? new TreeSet<>() : new TreeSet<>(owned);
        TreeSet<String> target = new TreeSet<>();
        boolean inventoried = false;
        if (!active.isEmpty()) {
            try {
                target.addAll(gateway.launchablePackages());
                inventoried = true;
            } catch (RuntimeException exception) {
                // Without an inventory only what is recorded is suspended, and
                // nothing recorded is released.
                errors.add(INVENTORY_FAILED + ":" + exception.getClass().getSimpleName());
            }
            target.addAll(record);
            target.removeAll(exempt(settings, device));
        }
        if (owned != null && allowRelease) {
            // Release what is no longer a target, unless another step holds it.
            // Without network verification the ownership record stays for retry.
            for (String packageName : owned) {
                if (!target.contains(packageName)
                        && (device.heldByOthers().contains(packageName) || release(packageName, gateway, errors))) {
                    record.remove(packageName);
                }
            }
        } else if (owned == null && !inventoried) {
            return null;
        }
        record.addAll(target);
        if (!record.equals(owned)) {
            // Recorded before the suspension, so a pass that dies midway leaves
            // nothing untracked. A failed save is reported and marks it unknown.
            saveOwned(gateway, record, errors);
        }
        suspendAndVerify(target, record, gateway, errors);
        return record;
    }

    /**
     * Suspends {@code targets}, already recorded in {@code record}, and reads
     * each back. A package Android refused, or does not report suspended, is
     * reported and dropped from the record again; a package that is gone is
     * dropped silently.
     */
    private static void suspendAndVerify(
            Set<String> targets, TreeSet<String> record, Gateway gateway, List<String> errors) {
        if (targets.isEmpty()) {
            return;
        }
        Set<String> refused = new LinkedHashSet<>();
        try {
            String[] failed = gateway.setSuspended(targets.toArray(new String[0]), true);
            if (failed != null) {
                Collections.addAll(refused, failed);
            }
        } catch (RuntimeException exception) {
            errors.add(SUSPEND_FAILED + ":" + exception.getClass().getSimpleName());
        }
        boolean dropped = false;
        for (String packageName : targets) {
            Boolean suspended;
            try {
                suspended = gateway.suspended(packageName);
            } catch (RuntimeException exception) {
                // Unknown: keep the record so a later pass can release it.
                errors.add(SUSPEND_UNVERIFIED + ":" + packageName);
                continue;
            }
            if (suspended == null) {
                // Uninstalled since the inventory.
                record.remove(packageName);
                dropped = true;
            } else if (refused.contains(packageName)) {
                // Another suspension may still show; this admin's is not there.
                errors.add(SUSPEND_REFUSED + ":" + packageName);
                record.remove(packageName);
                dropped = true;
            } else if (!suspended) {
                errors.add(SUSPEND_UNVERIFIED + ":" + packageName);
                record.remove(packageName);
                dropped = true;
            }
        }
        if (dropped) {
            saveOwned(gateway, record, errors);
        }
    }

    /**
     * Outside a window with an unreadable record: releases every launchable
     * package Android reports suspended that no other step holds, then
     * rewrites the record with what Android did not confirm released. Without
     * an inventory nothing is released and the record is left as it is.
     *
     * @return the rewritten record, or {@code null} when it was not rewritten
     */
    private static TreeSet<String> recover(Device device, Gateway gateway, List<String> errors) {
        TreeSet<String> launchable = new TreeSet<>();
        try {
            launchable.addAll(gateway.launchablePackages());
        } catch (RuntimeException exception) {
            errors.add(INVENTORY_FAILED + ":" + exception.getClass().getSimpleName());
            return null;
        }
        TreeSet<String> remaining = new TreeSet<>();
        for (String packageName : launchable) {
            if (!device.heldByOthers().contains(packageName) && !release(packageName, gateway, errors)) {
                remaining.add(packageName);
            }
        }
        return saveOwned(gateway, remaining, errors) ? remaining : null;
    }

    private static Set<String> exempt(ScheduleSettings settings, Device device) {
        LinkedHashSet<String> exempt = new LinkedHashSet<>(device.alwaysAvailable());
        exempt.addAll(settings.allowlist());
        return exempt;
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

    /** @return the recorded packages, or {@code null} when the record is unreadable */
    private static TreeSet<String> readOwned(Gateway gateway, List<String> errors) {
        try {
            Set<String> owned = gateway.owned();
            if (owned != null) {
                return new TreeSet<>(owned);
            }
            errors.add(OWNERSHIP_UNREADABLE);
        } catch (RuntimeException exception) {
            errors.add(OWNERSHIP_UNREADABLE + ":" + exception.getClass().getSimpleName());
        }
        return null;
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
