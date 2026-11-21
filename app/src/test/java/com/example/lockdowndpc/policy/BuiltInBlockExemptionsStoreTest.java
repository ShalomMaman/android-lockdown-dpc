package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.content.SharedPreferences;

import com.example.lockdowndpc.kiosk.KioskAppCatalog;
import com.example.lockdowndpc.policy.BuiltInBlockExemptions.Settings;

import org.junit.Test;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * The store through its real preference backing, against an Android-like
 * {@code SharedPreferences}: every commit updates memory, the commit result
 * reports the disk write, and the file's existence is a separate fact.
 */
public final class BuiltInBlockExemptionsStoreTest {

    private static final String TELEGRAM = "org.telegram.messenger";
    private static final String SIGNER = "aa".repeat(32);

    // --- One reader, failing closed -----------------------------------------------------

    @Test
    public void aZeroByteFileThatExistsIsUnreadableAndEnforcesNothing() {
        Map<String, Object> memory = new HashMap<>();
        BuiltInExemptionsPersistence store = BuiltInBlockExemptionsStore.persistenceFor(
                androidLikePreferences(memory, new boolean[]{false}), () -> true);
        assertTrue(store.record().unreadable());
        assertEquals(BuiltInBlockExemptions.ChromeFlag.UNREADABLE, store.record().flag());
        assertEquals(Settings.NONE, store.read());
    }

    @Test
    public void noFileAtAllIsAnEmptyReadableRecord() {
        BuiltInExemptionsPersistence store = BuiltInBlockExemptionsStore.persistenceFor(
                androidLikePreferences(new HashMap<>(), new boolean[]{false}), () -> false);
        assertFalse(store.record().unreadable());
        assertEquals(BuiltInBlockExemptions.ChromeFlag.ABSENT, store.record().flag());
    }

    @Test
    public void anOldFormatChromeApprovalEnforcesNothingAndIsNotKioskEligible() {
        Map<String, Object> memory = new HashMap<>();
        memory.put("chrome", true);
        memory.put("social_pins", new LinkedHashSet<>(Set.of(TELEGRAM + "=" + SIGNER)));
        BuiltInExemptionsPersistence store = BuiltInBlockExemptionsStore.persistenceFor(
                androidLikePreferences(memory, new boolean[]{false}), () -> true);
        assertTrue(store.record().unreadable());
        Settings enforced = store.read();
        assertFalse("no Chrome", enforced.chrome());
        assertTrue("no social app", enforced.socialPins().isEmpty());
        assertFalse(BuiltInBlockExemptions.socialVisible(TELEGRAM, enforced, SIGNER));
        assertTrue("not kiosk-eligible", KioskAppCatalog.isProtectedFromKiosk(TELEGRAM, Set.of()));
        assertEquals("teardown refused", BuiltInBlockExemptions.ChromeFlag.UNREADABLE, store.record().flag());
    }

    @Test
    public void aFailedClearRestoresTheExactPriorMapAndStaysUnreadable() {
        Map<String, Object> memory = new HashMap<>();
        memory.put("chrome", true);
        Map<String, Object> prior = new HashMap<>(memory);
        boolean[] diskFails = {true};
        BuiltInExemptionsPersistence store = BuiltInBlockExemptionsStore.persistenceFor(
                androidLikePreferences(memory, diskFails), () -> true);
        assertTrue(store.record().unreadable());
        assertFalse(store.write(Settings.NONE));
        assertEquals("exactly the prior map, no marker added", prior, memory);
        assertTrue(store.record().unreadable());
        assertEquals(BuiltInBlockExemptions.ChromeFlag.UNREADABLE, store.record().flag());
    }

    @Test
    public void aSuccessfulSaveWritesTheFormatMarker() {
        Map<String, Object> memory = new HashMap<>();
        BuiltInExemptionsPersistence store = BuiltInBlockExemptionsStore.persistenceFor(
                androidLikePreferences(memory, new boolean[]{false}), () -> true);
        assertTrue(store.write(Settings.NONE.withChrome(true)));
        assertEquals(BuiltInBlockExemptions.FORMAT_VERSION, memory.get("format"));
        assertEquals(BuiltInBlockExemptions.ChromeFlag.PRESENT, store.record().flag());
    }

    // --- Pause durability ----------------------------------------------------------------

    @Test
    public void invalidatingContinuationReportsAFailedCommit() {
        Map<String, Object> memory = new HashMap<>();
        memory.put("verified_filter", "abc");
        assertTrue(BuiltInBlockExemptionsStore.invalidateContinuation(
                androidLikePreferences(memory, new boolean[]{false})));
        assertFalse(memory.containsKey("verified_filter"));
        memory.put("verified_filter", "abc");
        assertFalse(BuiltInBlockExemptionsStore.invalidateContinuation(
                androidLikePreferences(memory, new boolean[]{true})));
    }

    @Test
    public void aPauseWhoseInvalidationFailedIsRefusedAndChangesNothing() {
        java.util.List<String> calls = new java.util.ArrayList<>();
        boolean started = PauseStart.begin(new PauseStart.Steps() {
            @Override
            public boolean invalidateContinuation() {
                calls.add("invalidate");
                return false;
            }

            @Override
            public void markPauseStarted() {
                calls.add("mark-paused");
            }
        });
        assertFalse(started);
        assertEquals(java.util.List.of("invalidate"), calls);
    }

    @Test
    public void aPauseInvalidatesContinuationBeforeItMarksItselfStarted() {
        java.util.List<String> calls = new java.util.ArrayList<>();
        assertTrue(PauseStart.begin(new PauseStart.Steps() {
            @Override
            public boolean invalidateContinuation() {
                calls.add("invalidate");
                return true;
            }

            @Override
            public void markPauseStarted() {
                calls.add("mark-paused");
            }
        }));
        assertEquals(java.util.List.of("invalidate", "mark-paused"), calls);
    }

    // --- Read-back ---------------------------------------------------------------------

    private static BuiltInBlockExemptionsStore.Readback readback() {
        return new BuiltInBlockExemptionsStore.Readback(
                Settings.NONE.auditText(),
                ChromeFilterExemption.Decision.NOT_EXEMPTED,
                BuiltInBlockExemptions.Observed.HIDDEN);
    }

    @Test
    public void aSavedReadBackReadsBack() {
        SharedPreferences prefs = androidLikePreferences(new HashMap<>(), new boolean[]{false});
        assertTrue(BuiltInBlockExemptionsStore.saveReadback(prefs, readback()));
        assertEquals(readback(), BuiltInBlockExemptionsStore.readback(prefs));
    }

    @Test
    public void aFailedReadBackCommitIsReportedToThePass() {
        SharedPreferences prefs = androidLikePreferences(new HashMap<>(), new boolean[]{true});
        assertFalse(BuiltInBlockExemptionsStore.saveReadback(prefs, readback()));
    }

    // --- Android-like SharedPreferences --------------------------------------------------

    private static SharedPreferences androidLikePreferences(Map<String, Object> memory, boolean[] diskFails) {
        return (SharedPreferences) Proxy.newProxyInstance(SharedPreferences.class.getClassLoader(),
                new Class<?>[]{SharedPreferences.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "getAll" -> new HashMap<>(memory);
                    case "contains" -> memory.containsKey(args[0]);
                    case "getString", "getBoolean", "getStringSet", "getLong", "getInt" ->
                            memory.containsKey(args[0]) ? memory.get(args[0]) : args[1];
                    case "edit" -> editor(memory, diskFails);
                    default -> throw new AssertionError(method.getName());
                });
    }

    private static SharedPreferences.Editor editor(Map<String, Object> memory, boolean[] diskFails) {
        Map<String, Object> puts = new HashMap<>();
        Set<String> removes = new HashSet<>();
        Object[] self = new Object[1];
        self[0] = Proxy.newProxyInstance(SharedPreferences.Editor.class.getClassLoader(),
                new Class<?>[]{SharedPreferences.Editor.class}, (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "putString", "putBoolean", "putInt", "putLong", "putFloat" -> {
                            puts.put((String) args[0], args[1]);
                            removes.remove(args[0]);
                            return self[0];
                        }
                        case "putStringSet" -> {
                            @SuppressWarnings("unchecked")
                            Set<String> values = (Set<String>) args[1];
                            puts.put((String) args[0], new LinkedHashSet<>(values));
                            removes.remove(args[0]);
                            return self[0];
                        }
                        case "remove" -> {
                            removes.add((String) args[0]);
                            puts.remove(args[0]);
                            return self[0];
                        }
                        case "commit" -> {
                            removes.forEach(memory::remove);
                            memory.putAll(puts);
                            return !diskFails[0];
                        }
                        default -> throw new AssertionError(method.getName());
                    }
                });
        return (SharedPreferences.Editor) self[0];
    }
}
