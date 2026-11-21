package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * Night and work hours enforcement against a fake Android layer: what is
 * suspended, what is never touched, what is released, and that every pass
 * converges from the clock alone.
 */
public final class ScheduleSuspensionTest {

    private static final ZoneId JERUSALEM = ZoneId.of("Asia/Jerusalem");

    private static final String GAME = "com.example.game";
    private static final String VIDEO = "com.example.video";
    private static final String WORK_APP = "com.example.workapp";
    private static final String SELF = "com.example.lockdowndpc";
    private static final String VPN = "com.example.vpn";
    private static final String DIALER = "com.android.dialer";
    private static final String SMS = "com.google.android.apps.messaging";
    private static final String CLOCK = "com.google.android.deskclock";
    private static final String LAUNCHER = "com.google.android.apps.nexuslauncher";
    private static final String KEYBOARD = "com.example.keyboard";
    private static final String WEBVIEW = "com.google.android.webview";
    private static final String SETTINGS = "com.android.settings";
    private static final String SOCIAL = "org.telegram.messenger";

    private static final Set<String> CORE = Set.of(
            SELF, VPN, DIALER, SMS, CLOCK, LAUNCHER, KEYBOARD, WEBVIEW, SETTINGS);
    private static final ScheduleSuspension.Device DEVICE = new ScheduleSuspension.Device(CORE, Set.of());

    /** Thursday 2026-11-19, local Jerusalem time. */
    private static Instant at(int day, int hour, int minute) {
        return LocalDateTime.of(2026, 11, day, hour, minute).atZone(JERUSALEM).toInstant();
    }

    private static ScheduleSettings enabled() {
        return new ScheduleSettings(ScheduleSettings.defaultSchedule(JERUSALEM, true), Set.of(), false);
    }

    private static ScheduleSettings enabled(Set<String> allowlist) {
        return new ScheduleSettings(ScheduleSettings.defaultSchedule(JERUSALEM, true), allowlist, false);
    }

    private static ScheduleSettings disabled() {
        return new ScheduleSettings(ScheduleSettings.defaultSchedule(JERUSALEM, false), Set.of(), false);
    }

    /** Persisted Android state; survives a "reboot" (a new gateway over the same state). */
    static final class AndroidState {
        final Set<String> installed = new LinkedHashSet<>();
        final Set<String> launchable = new LinkedHashSet<>();
        final Set<String> suspended = new TreeSet<>();
        final Set<String> owned = new TreeSet<>();
        Instant alarm;

        AndroidState() {
            for (String pkg : List.of(GAME, VIDEO, WORK_APP, SELF, VPN, DIALER, SMS, CLOCK,
                    LAUNCHER, KEYBOARD, WEBVIEW, SETTINGS, SOCIAL)) {
                installed.add(pkg);
            }
            launchable.addAll(List.of(GAME, VIDEO, WORK_APP, DIALER, SMS, CLOCK, SETTINGS, SELF, SOCIAL));
        }
    }

    static class FakeGateway implements ScheduleSuspension.Gateway {
        final AndroidState state;
        final List<String> calls = new ArrayList<>();
        final Set<String> refuse = new LinkedHashSet<>();
        final Set<String> ignore = new LinkedHashSet<>();
        boolean setThrows;
        boolean inventoryThrows;
        boolean saveFails;
        boolean readThrows;
        /** The ownership record is damaged until the next successful save. */
        boolean ownedUnreadable;

        FakeGateway(AndroidState state) {
            this.state = state;
        }

        @Override
        public Set<String> launchablePackages() {
            calls.add("inventory");
            if (inventoryThrows) {
                throw new IllegalStateException("inventory");
            }
            return new LinkedHashSet<>(state.launchable);
        }

        @Override
        public Boolean suspended(String packageName) {
            if (readThrows) {
                throw new SecurityException("read");
            }
            return state.installed.contains(packageName) ? state.suspended.contains(packageName) : null;
        }

        @Override
        public String[] setSuspended(String[] packageNames, boolean suspend) {
            calls.add((suspend ? "suspend:" : "release:") + String.join(",", packageNames));
            if (setThrows) {
                throw new SecurityException("set");
            }
            List<String> failed = new ArrayList<>();
            for (String pkg : packageNames) {
                if (refuse.contains(pkg)) {
                    failed.add(pkg);
                } else if (!ignore.contains(pkg)) {
                    if (suspend) {
                        state.suspended.add(pkg);
                    } else {
                        state.suspended.remove(pkg);
                    }
                }
            }
            return failed.toArray(new String[0]);
        }

        @Override
        public Set<String> owned() {
            if (ownedUnreadable) {
                throw new IllegalStateException("ownership-unmarked");
            }
            return new TreeSet<>(state.owned);
        }

        @Override
        public boolean saveOwned(Set<String> owned) {
            calls.add("save:" + String.join(",", owned));
            if (saveFails) {
                return false;
            }
            state.owned.clear();
            state.owned.addAll(owned);
            ownedUnreadable = false;
            return true;
        }

        @Override
        public void armBoundary(Instant at) {
            calls.add("arm:" + at);
            state.alarm = at;
        }

        @Override
        public void cancelBoundary() {
            calls.add("cancel");
            state.alarm = null;
        }

        List<String> suspensionCalls() {
            List<String> result = new ArrayList<>();
            for (String call : calls) {
                if (call.startsWith("suspend:") || call.startsWith("release:")) {
                    result.add(call);
                }
            }
            return result;
        }
    }

    private static ScheduleSuspension.Result pass(
            ScheduleSettings settings, Instant now, FakeGateway gateway, List<String> errors) {
        return ScheduleSuspension.reconcile(settings, now, DEVICE, gateway, errors);
    }

    // ------------------------------------------------------------------ default off

    @Test
    public void nothingStoredMakesNoAndroidCallAtAll() {
        AndroidState state = new AndroidState();
        FakeGateway gateway = new FakeGateway(state);
        List<String> errors = new ArrayList<>();
        ScheduleSuspension.Result result = pass(ScheduleSettings.OFF, at(19, 23, 30), gateway, errors);
        assertEquals(List.of(), gateway.calls);
        assertEquals(List.of(), errors);
        assertEquals(Set.of(), result.activeWindows());
        assertEquals(Optional.empty(), result.nextBoundary());
        assertEquals(Set.of(), state.suspended);
    }

    @Test
    public void bothWindowsDisabledSuspendsNothingAndClearsTheAlarm() {
        AndroidState state = new AndroidState();
        state.alarm = at(19, 23, 0);
        FakeGateway gateway = new FakeGateway(state);
        List<String> errors = new ArrayList<>();
        pass(disabled(), at(19, 23, 30), gateway, errors);
        assertEquals(List.of("cancel"), gateway.calls);
        assertEquals(List.of(), errors);
        assertEquals(null, state.alarm);
    }

    // -------------------------------------------------------- always-available core

    @Test
    public void insideAWindowEveryLaunchableAppOutsideTheCoreIsSuspended() {
        AndroidState state = new AndroidState();
        FakeGateway gateway = new FakeGateway(state);
        List<String> errors = new ArrayList<>();
        ScheduleSuspension.Result result = pass(enabled(), at(19, 23, 30), gateway, errors);
        assertEquals(List.of(), errors);
        assertEquals(Set.of(SchedulePolicy.WINDOW_NIGHT), result.activeWindows());
        assertEquals(new TreeSet<>(Set.of(GAME, VIDEO, WORK_APP, SOCIAL)), state.suspended);
        assertEquals(state.suspended, state.owned);
        for (String core : CORE) {
            assertFalse(core + " must stay available", state.suspended.contains(core));
            for (String call : gateway.suspensionCalls()) {
                assertFalse(core + " was passed to a suspend call", call.contains(core));
            }
        }
    }

    @Test
    public void theAllowlistKeepsAnAppAvailableInsideTheWindow() {
        AndroidState state = new AndroidState();
        FakeGateway gateway = new FakeGateway(state);
        List<String> errors = new ArrayList<>();
        pass(enabled(Set.of(WORK_APP)), at(19, 10, 0), gateway, errors);
        assertEquals(List.of(), errors);
        assertFalse(state.suspended.contains(WORK_APP));
        assertTrue(state.suspended.contains(GAME));
    }

    @Test
    public void ownershipIsRecordedBeforeTheSuspensionCall() {
        AndroidState state = new AndroidState();
        FakeGateway gateway = new FakeGateway(state);
        pass(enabled(), at(19, 23, 30), gateway, new ArrayList<>());
        int save = gateway.calls.indexOf("save:" + String.join(",", new TreeSet<>(Set.of(GAME, VIDEO, WORK_APP, SOCIAL))));
        int suspend = -1;
        for (int i = 0; i < gateway.calls.size(); i++) {
            if (gateway.calls.get(i).startsWith("suspend:")) {
                suspend = i;
                break;
            }
        }
        assertTrue("ownership saved", save >= 0);
        assertTrue("saved before suspending", save < suspend);
    }

    // ----------------------------------------------------------- other owners

    @Test
    public void aPackageAnotherStepSuspendedIsNeverClaimedOrReleased() {
        AndroidState state = new AndroidState();
        state.suspended.add(SOCIAL); // the social containment fallback
        FakeGateway gateway = new FakeGateway(state);
        List<String> errors = new ArrayList<>();
        pass(enabled(), at(19, 23, 30), gateway, errors);
        assertFalse("not claimed", state.owned.contains(SOCIAL));
        pass(enabled(), at(20, 7, 0), gateway, errors);
        assertTrue("still suspended by its owner", state.suspended.contains(SOCIAL));
        for (String call : gateway.suspensionCalls()) {
            assertFalse(call, call.startsWith("release:") && call.contains(SOCIAL));
        }
        assertEquals(List.of(), errors);
        assertEquals(Set.of(SOCIAL), state.suspended);
    }

    @Test
    public void anOwnedPackageAnotherStepNowHoldsIsHandedOverNotReleased() {
        AndroidState state = new AndroidState();
        FakeGateway gateway = new FakeGateway(state);
        pass(enabled(), at(19, 23, 30), gateway, new ArrayList<>());
        assertTrue(state.owned.contains(SOCIAL));
        // Overnight its exemption was revoked: containment now owns it.
        ScheduleSuspension.Device revoked = new ScheduleSuspension.Device(CORE, Set.of(SOCIAL));
        List<String> errors = new ArrayList<>();
        ScheduleSuspension.reconcile(enabled(), at(20, 7, 0), revoked, gateway, errors);
        assertEquals(List.of(), errors);
        assertTrue("left suspended for containment", state.suspended.contains(SOCIAL));
        assertFalse("no longer the schedule's", state.owned.contains(SOCIAL));
        assertFalse(state.suspended.contains(GAME));
    }

    @Test
    public void theHoldTargetsEveryPackageOutsideTheCoreAndAllowlistOnlyInsideAWindow() {
        ScheduleSuspension.Hold night = ScheduleSuspension.Hold.of(enabled(Set.of(WORK_APP)), at(19, 23, 30), CORE);
        assertTrue(night.windowActive());
        assertTrue(night.targets(GAME));
        assertTrue("a hidden or never-recorded app is a target too", night.targets(BuiltInBlockExemptions.CHROME));
        assertFalse(night.targets(DIALER));
        assertFalse(night.targets(WORK_APP));
        assertFalse(ScheduleSuspension.Hold.of(enabled(), at(20, 7, 0), CORE).targets(GAME));
        assertFalse(ScheduleSuspension.Hold.of(ScheduleSettings.OFF, at(19, 23, 30), CORE).targets(GAME));
        assertFalse(ScheduleSuspension.Hold.NONE.targets(GAME));
        // An unreadable record holds too: both default windows.
        ScheduleSettings corrupt = ScheduleSettings.fromStored("{not json", null, JERUSALEM);
        assertTrue(ScheduleSuspension.Hold.of(corrupt, at(19, 10, 0), CORE).targets(GAME));
    }

    // --------------------------------------------------------- read-back failures

    @Test
    public void aRefusedSuspensionIsAnErrorAndNotRecordedAsOwned() {
        AndroidState state = new AndroidState();
        FakeGateway gateway = new FakeGateway(state);
        gateway.refuse.add(GAME);
        List<String> errors = new ArrayList<>();
        pass(enabled(), at(19, 23, 30), gateway, errors);
        assertEquals(List.of(ScheduleSuspension.SUSPEND_REFUSED + ":" + GAME), errors);
        assertFalse(state.owned.contains(GAME));
        assertTrue(state.owned.contains(VIDEO));
    }

    @Test
    public void aSilentlyIgnoredSuspensionIsCaughtByTheReadBack() {
        AndroidState state = new AndroidState();
        FakeGateway gateway = new FakeGateway(state);
        gateway.ignore.add(VIDEO);
        List<String> errors = new ArrayList<>();
        pass(enabled(), at(19, 23, 30), gateway, errors);
        assertEquals(List.of(ScheduleSuspension.SUSPEND_UNVERIFIED + ":" + VIDEO), errors);
        assertFalse(state.owned.contains(VIDEO));
    }

    @Test
    public void aThrowingSuspensionCallFailsThePass() {
        AndroidState state = new AndroidState();
        FakeGateway gateway = new FakeGateway(state);
        gateway.setThrows = true;
        List<String> errors = new ArrayList<>();
        pass(enabled(), at(19, 23, 30), gateway, errors);
        assertTrue(errors.contains(ScheduleSuspension.SUSPEND_FAILED + ":SecurityException"));
        assertTrue(errors.contains(ScheduleSuspension.SUSPEND_UNVERIFIED + ":" + GAME));
        assertEquals(Set.of(), state.owned);
    }

    @Test
    public void aReleaseAndroidIgnoresStaysOwnedAndIsReported() {
        AndroidState state = new AndroidState();
        FakeGateway gateway = new FakeGateway(state);
        pass(enabled(), at(19, 23, 30), gateway, new ArrayList<>());
        gateway.ignore.add(GAME);
        List<String> errors = new ArrayList<>();
        pass(enabled(), at(20, 7, 0), gateway, errors);
        assertEquals(List.of(ScheduleSuspension.RELEASE_UNVERIFIED + ":" + GAME), errors);
        assertEquals(Set.of(GAME), state.owned);
        assertEquals(Set.of(GAME), state.suspended);
        // The next pass retries it.
        gateway.ignore.clear();
        errors.clear();
        pass(enabled(), at(20, 7, 5), gateway, errors);
        assertEquals(List.of(), errors);
        assertEquals(Set.of(), state.suspended);
        assertEquals(Set.of(), state.owned);
    }

    @Test
    public void ownershipThatCannotBeSavedSuspendsNothing() {
        AndroidState state = new AndroidState();
        FakeGateway gateway = new FakeGateway(state);
        gateway.saveFails = true;
        List<String> errors = new ArrayList<>();
        pass(enabled(), at(19, 23, 30), gateway, errors);
        assertEquals(List.of(ScheduleSuspension.OWNERSHIP_UNSAVED), errors);
        assertEquals(List.of(), gateway.suspensionCalls());
    }

    @Test
    public void aFailedInventoryKeepsEverythingHeldAndFailsThePass() {
        AndroidState state = new AndroidState();
        FakeGateway gateway = new FakeGateway(state);
        pass(enabled(), at(19, 23, 30), gateway, new ArrayList<>());
        Set<String> before = new TreeSet<>(state.suspended);
        gateway.inventoryThrows = true;
        List<String> errors = new ArrayList<>();
        pass(enabled(), at(20, 1, 0), gateway, errors);
        assertEquals(List.of(ScheduleSuspension.INVENTORY_FAILED + ":IllegalStateException"), errors);
        assertEquals(before, state.suspended);
        assertEquals(before, state.owned);
    }

    @Test
    public void anUnreadableRecordEnforcesBothDefaultWindowsAndFailsThePass() {
        AndroidState state = new AndroidState();
        FakeGateway gateway = new FakeGateway(state);
        List<String> errors = new ArrayList<>();
        ScheduleSettings corrupt = ScheduleSettings.fromStored("{not json", null, JERUSALEM);
        ScheduleSuspension.Result result = pass(corrupt, at(19, 23, 30), gateway, errors);
        assertEquals(List.of(ScheduleSettings.UNREADABLE_ERROR), errors);
        assertEquals(Set.of(SchedulePolicy.WINDOW_NIGHT), result.activeWindows());
        assertTrue(state.suspended.contains(GAME));
        // Work hours too: a damaged record never restricts less than the default.
        errors.clear();
        result = pass(corrupt, at(19, 10, 0), gateway, errors);
        assertEquals(Set.of(SchedulePolicy.WINDOW_WORK), result.activeWindows());
        assertTrue(state.suspended.contains(GAME));
        // Between the windows it releases.
        errors.clear();
        pass(corrupt, at(19, 18, 0), gateway, errors);
        assertFalse(state.suspended.contains(GAME));
    }

    // ---------------------------------------------------- unreadable ownership

    @Test
    public void unknownOwnershipOutsideAWindowIsRecoveredFromTheReadBack() {
        AndroidState state = new AndroidState();
        state.suspended.add(SOCIAL); // the containment fallback
        FakeGateway gateway = new FakeGateway(state);
        ScheduleSuspension.Device contained = new ScheduleSuspension.Device(CORE, Set.of(SOCIAL));
        ScheduleSuspension.reconcile(enabled(), at(19, 23, 30), contained, gateway, new ArrayList<>());
        assertTrue(state.suspended.contains(GAME));
        gateway.ownedUnreadable = true;
        List<String> errors = new ArrayList<>();
        ScheduleSuspension.reconcile(enabled(), at(20, 7, 0), contained, gateway, errors);
        // Reported once, so the pass is retried and verified next time.
        assertEquals(List.of(ScheduleSuspension.OWNERSHIP_UNREADABLE + ":IllegalStateException"), errors);
        assertEquals("only what another step holds stays suspended", Set.of(SOCIAL), state.suspended);
        assertFalse("the record is rewritten", gateway.ownedUnreadable);
        assertEquals(Set.of(), state.owned);
        assertTrue("the next boundary is still armed", state.alarm != null);
        errors.clear();
        ScheduleSuspension.reconcile(enabled(), at(20, 7, 5), contained, gateway, errors);
        assertEquals(List.of(), errors);
    }

    @Test
    public void aRecoveryReleaseAndroidIgnoresStaysRecorded() {
        AndroidState state = new AndroidState();
        FakeGateway gateway = new FakeGateway(state);
        pass(enabled(), at(19, 23, 30), gateway, new ArrayList<>());
        gateway.ownedUnreadable = true;
        gateway.ignore.add(GAME);
        List<String> errors = new ArrayList<>();
        pass(enabled(), at(20, 7, 0), gateway, errors);
        assertTrue(errors.contains(ScheduleSuspension.RELEASE_UNVERIFIED + ":" + GAME));
        assertEquals(Set.of(GAME), state.owned);
        assertEquals(Set.of(GAME), state.suspended);
    }

    @Test
    public void unknownOwnershipOnADeviceWithTheScheduleOffIsRecoveredToo() {
        AndroidState state = new AndroidState();
        FakeGateway gateway = new FakeGateway(state);
        pass(enabled(), at(19, 23, 30), gateway, new ArrayList<>());
        gateway.ownedUnreadable = true;
        List<String> errors = new ArrayList<>();
        pass(disabled(), at(19, 23, 40), gateway, errors);
        assertEquals(List.of(ScheduleSuspension.OWNERSHIP_UNREADABLE + ":IllegalStateException"), errors);
        assertEquals(Set.of(), state.suspended);
        assertFalse(gateway.ownedUnreadable);
    }

    @Test
    public void unknownOwnershipOutsideAWindowWithoutAnInventoryReleasesNothing() {
        AndroidState state = new AndroidState();
        FakeGateway gateway = new FakeGateway(state);
        pass(enabled(), at(19, 23, 30), gateway, new ArrayList<>());
        Set<String> held = new TreeSet<>(state.suspended);
        gateway.ownedUnreadable = true;
        gateway.inventoryThrows = true;
        List<String> errors = new ArrayList<>();
        pass(enabled(), at(20, 7, 0), gateway, errors);
        assertEquals(held, state.suspended);
        assertTrue("the record is kept", gateway.ownedUnreadable);
        assertTrue(errors.contains(ScheduleSuspension.INVENTORY_FAILED + ":IllegalStateException"));
    }

    @Test
    public void unknownOwnershipInsideAWindowIsRewrittenFromTheReadBack() {
        AndroidState state = new AndroidState();
        FakeGateway gateway = new FakeGateway(state);
        pass(enabled(), at(19, 23, 30), gateway, new ArrayList<>());
        // A new app arrives and the record is damaged.
        state.installed.add("com.example.newgame");
        state.launchable.add("com.example.newgame");
        gateway.ownedUnreadable = true;
        List<String> errors = new ArrayList<>();
        pass(enabled(), at(20, 1, 0), gateway, errors);
        assertEquals(List.of(ScheduleSuspension.OWNERSHIP_UNREADABLE + ":IllegalStateException"), errors);
        assertFalse(gateway.ownedUnreadable);
        assertEquals(new TreeSet<>(Set.of(GAME, VIDEO, WORK_APP, SOCIAL, "com.example.newgame")), state.owned);
        assertEquals(state.owned, state.suspended);
        for (String call : gateway.suspensionCalls()) {
            assertFalse(call, call.startsWith("release:"));
        }
        // Once readable again, the window's end releases everything.
        errors.clear();
        pass(enabled(), at(20, 7, 0), gateway, errors);
        assertEquals(List.of(), errors);
        assertEquals(Set.of(), state.suspended);
    }

    @Test
    public void aRewriteNeverAdoptsWhatAnotherStepHolds() {
        AndroidState state = new AndroidState();
        state.suspended.add(SOCIAL); // the containment fallback
        FakeGateway gateway = new FakeGateway(state);
        gateway.ownedUnreadable = true;
        ScheduleSuspension.Device contained = new ScheduleSuspension.Device(CORE, Set.of(SOCIAL));
        List<String> errors = new ArrayList<>();
        ScheduleSuspension.reconcile(enabled(), at(19, 23, 30), contained, gateway, errors);
        assertFalse(state.owned.contains(SOCIAL));
        assertTrue(state.owned.contains(GAME));
        ScheduleSuspension.reconcile(enabled(), at(20, 7, 0), contained, gateway, errors);
        assertEquals(Set.of(SOCIAL), state.suspended);
    }

    @Test
    public void unknownOwnershipWithoutAnInventoryKeepsTheRecordAndSuspendsNothing() {
        AndroidState state = new AndroidState();
        FakeGateway gateway = new FakeGateway(state);
        gateway.ownedUnreadable = true;
        gateway.inventoryThrows = true;
        List<String> errors = new ArrayList<>();
        pass(enabled(), at(19, 23, 30), gateway, errors);
        assertEquals(List.of(ScheduleSuspension.OWNERSHIP_UNREADABLE + ":IllegalStateException",
                ScheduleSuspension.INVENTORY_FAILED + ":IllegalStateException"), errors);
        assertTrue(gateway.ownedUnreadable);
        assertEquals(List.of(), gateway.suspensionCalls());
    }

    @Test
    public void unknownOwnershipThatCannotBeRewrittenSuspendsNothing() {
        AndroidState state = new AndroidState();
        FakeGateway gateway = new FakeGateway(state);
        gateway.ownedUnreadable = true;
        gateway.saveFails = true;
        List<String> errors = new ArrayList<>();
        pass(enabled(), at(19, 23, 30), gateway, errors);
        assertTrue(errors.contains(ScheduleSuspension.OWNERSHIP_UNSAVED));
        assertTrue(gateway.ownedUnreadable);
        assertEquals(List.of(), gateway.suspensionCalls());
    }

    @Test
    public void pauseWithUnknownOwnershipReleasesFromTheReadBackAndReportsIt() {
        AndroidState state = new AndroidState();
        FakeGateway gateway = new FakeGateway(state);
        pass(enabled(), at(19, 23, 30), gateway, new ArrayList<>());
        gateway.ownedUnreadable = true;
        List<String> errors = new ArrayList<>();
        ScheduleSuspension.releaseAll(gateway, errors);
        assertEquals(List.of(ScheduleSuspension.OWNERSHIP_UNREADABLE + ":IllegalStateException"), errors);
        assertEquals(Set.of(), state.suspended);
        assertFalse(gateway.ownedUnreadable);
        assertEquals(null, state.alarm);
    }

    // -------------------------------------------------- clock jumps and reboots

    @Test
    public void clockJumpsConvergeFromTheClockAlone() {
        AndroidState state = new AndroidState();
        FakeGateway gateway = new FakeGateway(state);
        List<String> errors = new ArrayList<>();

        ScheduleSuspension.Result evening = pass(enabled(), at(19, 22, 50), gateway, errors);
        assertEquals(Set.of(), state.suspended);
        assertEquals(Optional.of(at(19, 23, 0)), evening.nextBoundary());
        assertEquals(at(19, 23, 0), state.alarm);

        ScheduleSuspension.Result night = pass(enabled(), at(20, 1, 0), gateway, errors);
        assertEquals(new TreeSet<>(Set.of(GAME, VIDEO, WORK_APP, SOCIAL)), state.suspended);
        assertEquals(at(20, 6, 0), state.alarm);
        assertEquals(Set.of(SchedulePolicy.WINDOW_NIGHT), night.activeWindows());

        // Friday 07:00: no work window on Friday.
        ScheduleSuspension.Result morning = pass(enabled(), at(20, 7, 0), gateway, errors);
        assertEquals(Set.of(), state.suspended);
        assertEquals(Set.of(), state.owned);
        assertEquals(at(20, 23, 0), state.alarm);
        assertEquals(Set.of(), morning.activeWindows());
        assertEquals(List.of(), errors);
    }

    @Test
    public void aBackwardClockJumpOutOfTheWindowReleases() {
        AndroidState state = new AndroidState();
        FakeGateway gateway = new FakeGateway(state);
        List<String> errors = new ArrayList<>();
        pass(enabled(), at(19, 23, 30), gateway, errors);
        assertFalse(state.suspended.isEmpty());
        pass(enabled(), at(19, 22, 0), gateway, errors);
        assertEquals(Set.of(), state.suspended);
        assertEquals(at(19, 23, 0), state.alarm);
        assertEquals(List.of(), errors);
    }

    @Test
    public void aRebootRecomputesWithoutAnyStoredWindowFlag() {
        AndroidState state = new AndroidState();
        pass(enabled(), at(19, 22, 50), new FakeGateway(state), new ArrayList<>());
        // Powered off across 23:00; the alarm did not survive.
        state.alarm = null;
        List<String> errors = new ArrayList<>();
        pass(enabled(), at(20, 1, 0), new FakeGateway(state), errors);
        assertTrue(state.suspended.contains(GAME));
        assertEquals(at(20, 6, 0), state.alarm);
        // Off again across 06:00; Android kept the suspensions.
        state.alarm = null;
        pass(enabled(), at(20, 7, 0), new FakeGateway(state), errors);
        assertEquals(Set.of(), state.suspended);
        assertEquals(at(20, 23, 0), state.alarm);
        assertEquals(List.of(), errors);
    }

    @Test
    public void aDeviceTimezoneChangeDoesNotMoveTheWindows() {
        // The stored schedule names its zone; the instant is all a pass reads.
        AndroidState state = new AndroidState();
        FakeGateway gateway = new FakeGateway(state);
        List<String> errors = new ArrayList<>();
        Instant elevenPmJerusalem = at(19, 23, 30);
        ZoneId previous = java.util.TimeZone.getDefault().toZoneId();
        try {
            java.util.TimeZone.setDefault(java.util.TimeZone.getTimeZone("America/New_York"));
            pass(enabled(), elevenPmJerusalem, gateway, errors);
        } finally {
            java.util.TimeZone.setDefault(java.util.TimeZone.getTimeZone(previous));
        }
        assertTrue(state.suspended.contains(GAME));
        assertEquals(at(20, 6, 0), state.alarm);
        assertEquals(List.of(), errors);
    }

    @Test
    public void workHoursFollowTheirDays() {
        AndroidState state = new AndroidState();
        FakeGateway gateway = new FakeGateway(state);
        List<String> errors = new ArrayList<>();
        ScheduleSuspension.Result thursday = pass(enabled(), at(19, 9, 0), gateway, errors);
        assertEquals(Set.of(SchedulePolicy.WINDOW_WORK), thursday.activeWindows());
        assertTrue(state.suspended.contains(GAME));
        assertEquals(at(19, 17, 0), state.alarm);
        ScheduleSuspension.Result friday = pass(enabled(), at(20, 12, 0), gateway, errors);
        assertEquals(Set.of(), friday.activeWindows());
        assertEquals(Set.of(), state.suspended);
        assertEquals(List.of(), errors);
    }

    // ------------------------------------------------- tightening and loosening

    @Test
    public void allowlistingAnOwnedAppReleasesItInsideTheWindow() {
        AndroidState state = new AndroidState();
        FakeGateway gateway = new FakeGateway(state);
        List<String> errors = new ArrayList<>();
        pass(enabled(), at(19, 23, 30), gateway, errors);
        assertTrue(state.suspended.contains(WORK_APP));
        pass(enabled(Set.of(WORK_APP)), at(19, 23, 40), gateway, errors);
        assertFalse(state.suspended.contains(WORK_APP));
        assertFalse(state.owned.contains(WORK_APP));
        assertTrue(state.suspended.contains(GAME));
        assertEquals(List.of(), errors);
    }

    @Test
    public void disablingTheScheduleReleasesEverythingItHeld() {
        AndroidState state = new AndroidState();
        FakeGateway gateway = new FakeGateway(state);
        List<String> errors = new ArrayList<>();
        pass(enabled(), at(19, 23, 30), gateway, errors);
        pass(disabled(), at(19, 23, 40), gateway, errors);
        assertEquals(Set.of(), state.suspended);
        assertEquals(Set.of(), state.owned);
        assertEquals(null, state.alarm);
        assertEquals(List.of(), errors);
    }

    @Test
    public void anOwnedAppThatLeftTheLauncherStaysHeldInsideTheWindow() {
        AndroidState state = new AndroidState();
        FakeGateway gateway = new FakeGateway(state);
        List<String> errors = new ArrayList<>();
        pass(enabled(), at(19, 23, 30), gateway, errors);
        state.launchable.remove(GAME);
        pass(enabled(), at(20, 0, 30), gateway, errors);
        assertTrue(state.suspended.contains(GAME));
        assertEquals(List.of(), errors);
    }

    @Test
    public void anUninstalledOwnedAppIsDroppedFromTheRecord() {
        AndroidState state = new AndroidState();
        FakeGateway gateway = new FakeGateway(state);
        List<String> errors = new ArrayList<>();
        pass(enabled(), at(19, 23, 30), gateway, errors);
        state.installed.remove(GAME);
        state.launchable.remove(GAME);
        state.suspended.remove(GAME);
        pass(enabled(), at(20, 7, 0), gateway, errors);
        assertFalse(state.owned.contains(GAME));
        assertEquals(List.of(), errors);
    }

    // ------------------------------------------------------------------ pause

    @Test
    public void pauseReleasesOnlyWhatTheScheduleSuspendedAndCancelsTheAlarm() {
        AndroidState state = new AndroidState();
        state.suspended.add(SOCIAL); // another owner's
        FakeGateway gateway = new FakeGateway(state);
        pass(enabled(), at(19, 23, 30), gateway, new ArrayList<>());
        assertTrue(state.alarm != null);
        List<String> errors = new ArrayList<>();
        ScheduleSuspension.releaseAll(gateway, errors);
        assertEquals(List.of(), errors);
        assertEquals(Set.of(SOCIAL), state.suspended);
        assertEquals(Set.of(), state.owned);
        assertEquals(null, state.alarm);
    }

    @Test
    public void pauseReportsAReleaseAndroidRefuses() {
        AndroidState state = new AndroidState();
        FakeGateway gateway = new FakeGateway(state);
        pass(enabled(), at(19, 23, 30), gateway, new ArrayList<>());
        gateway.refuse.add(GAME);
        List<String> errors = new ArrayList<>();
        ScheduleSuspension.releaseAll(gateway, errors);
        assertEquals(List.of(ScheduleSuspension.RELEASE_UNVERIFIED + ":" + GAME + ":refused"), errors);
        assertEquals(Set.of(GAME), state.owned);
    }

    @Test
    public void anAlarmThatCannotBeArmedFailsThePass() {
        AndroidState state = new AndroidState();
        FakeGateway gateway = new FakeGateway(state) {
            @Override
            public void armBoundary(Instant at) {
                throw new IllegalStateException("no alarm service");
            }
        };
        List<String> errors = new ArrayList<>();
        pass(enabled(), at(19, 22, 0), gateway, errors);
        assertEquals(List.of(ScheduleSuspension.ALARM_FAILED + ":IllegalStateException"), errors);
    }
}
