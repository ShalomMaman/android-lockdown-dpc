package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.content.SharedPreferences;

import com.example.lockdowndpc.kiosk.KioskAppCatalog;
import com.example.lockdowndpc.policy.BuiltInBlockExemptions.Settings;

import org.junit.Test;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

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
                androidLikePreferences(memory, new boolean[]{false}), () -> true, () -> {});
        assertTrue(store.record().unreadable());
        assertEquals(BuiltInBlockExemptions.ChromeFlag.UNREADABLE, store.record().flag());
        assertEquals(Settings.NONE, store.read());
    }

    @Test
    public void noFileAtAllIsAnEmptyReadableRecord() {
        BuiltInExemptionsPersistence store = BuiltInBlockExemptionsStore.persistenceFor(
                androidLikePreferences(new HashMap<>(), new boolean[]{false}), () -> false, () -> {});
        assertFalse(store.record().unreadable());
        assertEquals(BuiltInBlockExemptions.ChromeFlag.ABSENT, store.record().flag());
    }

    @Test
    public void anOldFormatChromeApprovalEnforcesNothingAndIsNotKioskEligible() {
        Map<String, Object> memory = new HashMap<>();
        memory.put("chrome", true);
        memory.put("social_pins", new LinkedHashSet<>(Set.of(TELEGRAM + "=" + SIGNER)));
        BuiltInExemptionsPersistence store = BuiltInBlockExemptionsStore.persistenceFor(
                androidLikePreferences(memory, new boolean[]{false}), () -> true, () -> {});
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
                androidLikePreferences(memory, diskFails), () -> true, () -> {});
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
                androidLikePreferences(memory, new boolean[]{false}), () -> true, () -> {});
        assertTrue(store.write(Settings.NONE.withChrome(true)));
        assertEquals(BuiltInBlockExemptions.FORMAT_VERSION, memory.get("format"));
        assertEquals(BuiltInBlockExemptions.ChromeFlag.PRESENT, store.record().flag());
    }

    @Test
    public void aFailedFirstSaveOnAFreshDeviceRestoresTheAbsentFile() {
        Map<String, Object> memory = new HashMap<>();
        boolean[] fileExists = {false};
        boolean[] diskFails = {true};
        SharedPreferences backing = androidLikePreferences(memory, diskFails);
        // A failed commit can still leave a partial file behind; the store must remove it.
        SharedPreferences prefs = creatingFileOnCommit(backing, fileExists);
        BuiltInExemptionsPersistence store = BuiltInBlockExemptionsStore.persistenceFor(
                prefs, () -> fileExists[0], () -> fileExists[0] = false);
        assertFalse(store.record().unreadable());

        assertFalse(store.write(Settings.NONE.withChrome(true)));

        assertFalse("no file, as before", fileExists[0]);
        assertTrue("no keys, as before", memory.isEmpty());
        assertFalse("readable, not damaged", store.record().unreadable());
        assertEquals(BuiltInBlockExemptions.ChromeFlag.ABSENT, store.record().flag());

        diskFails[0] = false;
        assertTrue("the next save works", store.write(Settings.NONE.withChrome(true)));
        assertTrue(store.read().chrome());
    }

    @Test
    public void aFailedSaveOverAnExistingFileKeepsTheFile() {
        Map<String, Object> memory = new HashMap<>();
        memory.put("chrome", false);
        memory.put("social_pins", new LinkedHashSet<String>());
        memory.put("format", BuiltInBlockExemptions.FORMAT_VERSION);
        boolean[] fileExists = {true};
        boolean[] deleted = {false};
        BuiltInExemptionsPersistence store = BuiltInBlockExemptionsStore.persistenceFor(
                androidLikePreferences(memory, new boolean[]{true}), () -> fileExists[0], () -> deleted[0] = true);
        assertFalse(store.write(Settings.NONE.withChrome(true)));
        assertFalse("an existing file is never deleted", deleted[0]);
        assertEquals(Boolean.FALSE, memory.get("chrome"));
        assertFalse(store.record().unreadable());
    }

    @Test
    public void onlyTheBackupLeftByAFailedWriteStillCountsAsAFile() throws java.io.IOException {
        java.io.File dir = java.nio.file.Files.createTempDirectory("prefs").toFile();
        try {
            java.io.File file = new java.io.File(dir, "builtin_block_exemptions.xml");
            java.io.File backup = new java.io.File(dir, "builtin_block_exemptions.xml.bak");
            java.util.function.BooleanSupplier exists = BuiltInBlockExemptionsStore.fileOrBackupExists(file);
            assertFalse("neither", exists.getAsBoolean());
            assertTrue(backup.createNewFile());
            assertTrue("backup only", exists.getAsBoolean());

            // A damaged file Android loaded as an empty map, of which a failed
            // write left only the backup: still unreadable, never a fresh device.
            BuiltInExemptionsPersistence store = BuiltInBlockExemptionsStore.persistenceFor(
                    androidLikePreferences(new HashMap<>(), new boolean[]{false}), exists, () -> {});
            assertTrue(store.record().unreadable());
            assertEquals(BuiltInBlockExemptions.ChromeFlag.UNREADABLE, store.record().flag());

            assertTrue(backup.delete());
            assertTrue(file.createNewFile());
            assertTrue("file only", exists.getAsBoolean());
        } finally {
            for (java.io.File child : dir.listFiles()) {
                child.delete();
            }
            dir.delete();
        }
    }

    @Test
    public void refusedContainmentIsAuditedThroughTheStoreOnlyOnAChange() {
        SharedPreferences prefs = androidLikePreferences(new HashMap<>(), new boolean[]{false});
        List<String> lines = new ArrayList<>();
        Set<String> none = Set.of();
        Set<String> refused = Set.of(TELEGRAM);
        BuiltInBlockExemptionsStore.containmentOutcome(prefs, none, none, none, lines::addAll);
        BuiltInBlockExemptionsStore.containmentOutcome(prefs, refused, none, none, lines::addAll);
        BuiltInBlockExemptionsStore.containmentOutcome(prefs, refused, none, none, lines::addAll);
        // Approved again: the refused set clears without a "restored" claim.
        BuiltInBlockExemptionsStore.containmentOutcome(prefs, none, none, refused, lines::addAll);
        BuiltInBlockExemptionsStore.containmentOutcome(prefs, none, none, none, lines::addAll);
        // Refused again, then Android confirms a suspension: restored.
        BuiltInBlockExemptionsStore.containmentOutcome(prefs, refused, none, none, lines::addAll);
        BuiltInBlockExemptionsStore.containmentOutcome(prefs, none, refused, none, lines::addAll);
        assertEquals(List.of(
                "builtin-exemption: CONTAINMENT_REFUSED: " + TELEGRAM,
                "builtin-exemption: approved again; containment no longer needed: " + TELEGRAM,
                "builtin-exemption: CONTAINMENT_REFUSED: " + TELEGRAM,
                "builtin-exemption: social containment restored: " + TELEGRAM), lines);
    }

    @Test
    public void containmentDedupStateIsSavedOnlyAfterTheAuditPersists() {
        Map<String, Object> memory = new HashMap<>();
        SharedPreferences prefs = androidLikePreferences(memory, new boolean[]{false});
        Set<String> refused = Set.of(TELEGRAM);
        Set<String> none = Set.of();
        List<String> attempts = new ArrayList<>();
        Predicate<List<String>> append = lines -> {
            assertTrue("dedup state has not been saved yet", memory.isEmpty());
            attempts.addAll(lines);
            return attempts.size() == 2;
        };

        BuiltInBlockExemptionsStore.containmentOutcome(prefs, refused, none, none, append);
        assertTrue("failed audit leaves the transition available to retry", memory.isEmpty());
        BuiltInBlockExemptionsStore.containmentOutcome(prefs, refused, none, none, append);
        assertEquals(Set.of(refused), new HashSet<>(memory.values()));
        BuiltInBlockExemptionsStore.containmentOutcome(prefs, refused, none, none, append);

        String line = "builtin-exemption: CONTAINMENT_REFUSED: " + TELEGRAM;
        assertEquals(List.of(line, line), attempts);
    }

    @Test
    public void failedContainmentAuditRetriesAllRowsOnceAndPreservesPriorEntries() {
        SharedPreferences readback = androidLikePreferences(new HashMap<>(), new boolean[]{false});
        String priorRefusal = "com.whatsapp";
        Set<String> previous = Set.of(priorRefusal);
        Set<String> refused = Set.of(TELEGRAM);
        Set<String> none = Set.of();
        Map<String, Object> priorAudit = Map.of("entries", "1|previous audit entry");
        Map<String, Object> auditMemory = new HashMap<>(priorAudit);
        boolean[] diskFails = {true};
        SharedPreferences audit = androidLikePreferences(auditMemory, diskFails);
        AuditEvent event = AuditEvent.EXEMPTION_CONTAINMENT_CHANGED;
        Predicate<List<String>> append = lines -> AuditLog.appendBatchCommitted(audit, event, lines);

        BuiltInBlockExemptionsStore.containmentOutcome(readback, previous, none, none, lines -> true);
        BuiltInBlockExemptionsStore.containmentOutcome(readback, refused, previous, none, append);
        assertEquals(priorAudit, auditMemory);

        diskFails[0] = false;
        BuiltInBlockExemptionsStore.containmentOutcome(readback, refused, previous, none, append);
        BuiltInBlockExemptionsStore.containmentOutcome(readback, refused, previous, none, append);

        List<String> rows = List.of(audit.getString("entries", "").split("\\n"));
        assertEquals(3, rows.size());
        assertEquals(new AuditLog.Entry(1, AuditEvent.LEGACY_CODE, "previous audit entry"),
                AuditLog.parse(rows.get(0), true));
        assertEquals("builtin-exemption: CONTAINMENT_REFUSED: " + TELEGRAM,
                AuditLog.parse(rows.get(1), true).text());
        assertEquals("builtin-exemption: social containment restored: " + priorRefusal,
                AuditLog.parse(rows.get(2), true).text());
    }

    // --- Routing warning audit -----------------------------------------------------------

    @Test
    public void theRoutingWarningIsAuditedOnlyWhenItChanges() {
        SharedPreferences prefs = androidLikePreferences(new HashMap<>(), new boolean[]{false});
        assertEquals("healthy, nothing to audit", null,
                BuiltInBlockExemptionsStore.routingOutcome(prefs, false, ""));
        assertEquals("first failure", "builtin-exemption: chrome link routing unverified: x",
                BuiltInBlockExemptionsStore.routingOutcome(prefs, true, "x"));
        assertEquals("still failing: log only", null,
                BuiltInBlockExemptionsStore.routingOutcome(prefs, true, "x"));
        assertEquals("still failing: log only", null,
                BuiltInBlockExemptionsStore.routingOutcome(prefs, true, "y"));
        assertEquals("recovery", "builtin-exemption: chrome link routing recovered",
                BuiltInBlockExemptionsStore.routingOutcome(prefs, false, ""));
        assertEquals("still healthy", null,
                BuiltInBlockExemptionsStore.routingOutcome(prefs, false, ""));
    }

    @Test
    public void routingAuditTransitionsArePure() {
        assertEquals(null, BuiltInBlockExemptions.routingAuditTransition(false, false, ""));
        assertEquals(null, BuiltInBlockExemptions.routingAuditTransition(true, true, "x"));
        assertEquals("builtin-exemption: chrome link routing unverified: x",
                BuiltInBlockExemptions.routingAuditTransition(false, true, "x"));
        assertEquals("builtin-exemption: chrome link routing recovered",
                BuiltInBlockExemptions.routingAuditTransition(true, false, ""));
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

    /** Wraps preferences so that any commit, even a failed one, creates the file. */
    private static SharedPreferences creatingFileOnCommit(SharedPreferences prefs, boolean[] fileExists) {
        return (SharedPreferences) Proxy.newProxyInstance(SharedPreferences.class.getClassLoader(),
                new Class<?>[]{SharedPreferences.class}, (proxy, method, args) -> {
                    Object result = method.invoke(prefs, args);
                    if (!"edit".equals(method.getName())) {
                        return result;
                    }
                    SharedPreferences.Editor inner = (SharedPreferences.Editor) result;
                    Object[] self = new Object[1];
                    self[0] = Proxy.newProxyInstance(SharedPreferences.Editor.class.getClassLoader(),
                            new Class<?>[]{SharedPreferences.Editor.class}, (p, m, a) -> {
                                Object r = m.invoke(inner, a);
                                if ("commit".equals(m.getName())) {
                                    fileExists[0] = true;
                                    return r;
                                }
                                return r == inner ? self[0] : r;
                            });
                    return self[0];
                });
    }

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
