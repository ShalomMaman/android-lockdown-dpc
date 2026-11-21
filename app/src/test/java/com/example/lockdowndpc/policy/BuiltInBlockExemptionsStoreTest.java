package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
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
 */
public final class BuiltInBlockExemptionsStoreTest {

    private static BuiltInBlockExemptionsStore.Readback verifiedReadback() {
        return new BuiltInBlockExemptionsStore.Readback(
                BuiltInBlockExemptions.Settings.NONE.auditText(),
                true,
                ChromeFilterExemption.Decision.NOT_EXEMPTED,
                BuiltInBlockExemptions.Observed.HIDDEN,
                Map.of("com.whatsapp", BuiltInBlockExemptions.Observed.HIDDEN),
                Set.of());
    }

    @Test
    public void aSavedReadBackReadsBackAsVerified() {
        SharedPreferences prefs = androidLikePreferences(new HashMap<>(), new boolean[]{false});
        assertTrue(BuiltInBlockExemptionsStore.saveReadback(prefs, verifiedReadback()));
        assertTrue(BuiltInBlockExemptionsStore.readback(prefs).passVerified());
    }

    @Test
    public void aReadBackWhoseCommitFailedIsNeverShownAsVerified() {
        SharedPreferences prefs = androidLikePreferences(new HashMap<>(), new boolean[]{true});
        assertFalse(BuiltInBlockExemptionsStore.saveReadback(prefs, verifiedReadback()));
        BuiltInBlockExemptionsStore.Readback inMemory = BuiltInBlockExemptionsStore.readback(prefs);
        assertNotNull(inMemory);
        assertFalse(inMemory.passVerified());
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
