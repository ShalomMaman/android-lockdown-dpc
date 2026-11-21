package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.content.SharedPreferences;

import org.junit.Test;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * The read-back store against an Android-like {@code SharedPreferences}:
 * every commit updates memory, and the commit result reports the disk write.
 * The console no longer shows a stored verification; only the decision reason
 * is read back from here.
 */
public final class BuiltInBlockExemptionsStoreTest {

    private static BuiltInBlockExemptionsStore.Readback readback() {
        return new BuiltInBlockExemptionsStore.Readback(
                BuiltInBlockExemptions.Settings.NONE.auditText(),
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

    private static SharedPreferences androidLikePreferences(Map<String, Object> memory, boolean[] diskFails) {
        return (SharedPreferences) Proxy.newProxyInstance(SharedPreferences.class.getClassLoader(),
                new Class<?>[]{SharedPreferences.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "getString" -> memory.containsKey(args[0]) ? memory.get(args[0]) : args[1];
                    case "getBoolean" -> memory.containsKey(args[0]) ? memory.get(args[0]) : args[1];
                    case "getStringSet" -> memory.containsKey(args[0]) ? memory.get(args[0]) : args[1];
                    case "edit" -> editor(memory, diskFails);
                    default -> throw new AssertionError(method.getName());
                });
    }

    private static SharedPreferences.Editor editor(Map<String, Object> memory, boolean[] diskFails) {
        Map<String, Object> puts = new HashMap<>();
        Object[] self = new Object[1];
        self[0] = Proxy.newProxyInstance(SharedPreferences.Editor.class.getClassLoader(),
                new Class<?>[]{SharedPreferences.Editor.class}, (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "putString", "putBoolean" -> {
                            puts.put((String) args[0], args[1]);
                            return self[0];
                        }
                        case "putStringSet" -> {
                            @SuppressWarnings("unchecked")
                            Set<String> values = (Set<String>) args[1];
                            puts.put((String) args[0], new HashSet<>(values));
                            return self[0];
                        }
                        case "commit" -> {
                            memory.putAll(puts);
                            return !diskFails[0];
                        }
                        default -> throw new AssertionError(method.getName());
                    }
                });
        return (SharedPreferences.Editor) self[0];
    }
}
