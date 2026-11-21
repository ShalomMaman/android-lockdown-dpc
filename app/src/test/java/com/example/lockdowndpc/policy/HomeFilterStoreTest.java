package com.example.lockdowndpc.policy;

import android.content.SharedPreferences;

import org.junit.Test;

import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class HomeFilterStoreTest {
    private static final String PAC = "https://filter.example/home.pac";

    @Test
    public void corruptStoredConfigurationMarksApplyFailedAndNeverReadsAsOff() {
        var corruptRecords = List.<Map<String, Object>>of(
                Map.of("pac_url", "broken URL", "enabled", true),
                Map.of("enabled", true),
                Map.of("pac_url", PAC, "enabled", "true"),
                Map.of("pac_url", PAC, "ca", "not base64"),
                Map.of("pac_url", PAC, "last_readback", true),
                Map.of("pac_url", PAC, "tailnet_id", "T123"),
                Map.of("pac_url", PAC, "canary_body", "missing URL"));
        AtomicInteger failures = new AtomicInteger();
        for (Map<String, Object> record : corruptRecords) {
            assertNull(HomeFilterStore.readOrReport(
                    () -> HomeFilterStore.read(preferences(record)), failures::incrementAndGet));
        }
        assertEquals(corruptRecords.size(), failures.get());
    }

    @Test
    public void legacySettingsRemainReadableWithoutInventingRoutingOrProbe() {
        AtomicInteger failures = new AtomicInteger();
        HomeFilterPolicy.Settings legacy = HomeFilterStore.readOrReport(
                () -> HomeFilterStore.read(preferences(Map.of("pac_url", PAC, "enabled", true))),
                failures::incrementAndGet);
        assertTrue(legacy.enabled());
        assertNull(legacy.config().routing());
        assertNull(legacy.config().canary());
        assertEquals(0, failures.get());
    }

    @Test
    public void aFailedCommitRestoresThePreviousSettingsInMemory() {
        // Android's commit() updates the in-memory map before the disk write;
        // here the disk write fails.
        Map<String, Object> memory = new java.util.HashMap<>();
        boolean[] diskFails = {false};
        SharedPreferences prefs = androidLikePreferences(memory, diskFails);
        HomeFilterPolicy.Settings enabled = new HomeFilterPolicy.Settings(
                new HomeFilterPolicy.Config(HomeFilterPolicy.DEFAULT_VPN_PACKAGE, PAC), true, null, false);
        HomeFilterStore.write(prefs, enabled);
        diskFails[0] = true;
        SharedPreferences failing = prefs;
        assertThrows(IllegalStateException.class,
                () -> HomeFilterStore.write(failing, enabled.requestDisable()));
        assertTrue("readers keep seeing the previous, enabled settings",
                HomeFilterStore.read(prefs).enabled());
        assertEquals(enabled, HomeFilterStore.read(prefs));
    }

    /** Memory is updated by every commit; the commit result reports the disk write. */
    private static SharedPreferences androidLikePreferences(Map<String, Object> memory, boolean[] diskFails) {
        return (SharedPreferences) Proxy.newProxyInstance(SharedPreferences.class.getClassLoader(),
                new Class<?>[]{SharedPreferences.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "contains" -> memory.containsKey(args[0]);
                    case "getString" -> memory.containsKey(args[0]) ? (String) memory.get(args[0]) : (String) args[1];
                    case "getBoolean" -> memory.containsKey(args[0]) ? (Boolean) memory.get(args[0]) : (Boolean) args[1];
                    case "edit" -> editor(memory, diskFails);
                    default -> throw new AssertionError(method.getName());
                });
    }

    private static SharedPreferences.Editor editor(Map<String, Object> memory, boolean[] diskFails) {
        Map<String, Object> puts = new java.util.HashMap<>();
        java.util.Set<String> removes = new java.util.HashSet<>();
        boolean[] clear = {false};
        Object[] self = new Object[1];
        self[0] = Proxy.newProxyInstance(SharedPreferences.Editor.class.getClassLoader(),
                new Class<?>[]{SharedPreferences.Editor.class}, (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "putString", "putBoolean" -> {
                            if (args[1] == null) {
                                removes.add((String) args[0]);
                                puts.remove(args[0]);
                            } else {
                                puts.put((String) args[0], args[1]);
                            }
                            return self[0];
                        }
                        case "remove" -> {
                            removes.add((String) args[0]);
                            return self[0];
                        }
                        case "clear" -> {
                            clear[0] = true;
                            return self[0];
                        }
                        case "commit" -> {
                            if (clear[0]) {
                                memory.clear();
                            }
                            removes.forEach(memory::remove);
                            memory.putAll(puts);
                            return !diskFails[0];
                        }
                        default -> throw new AssertionError(method.getName());
                    }
                });
        return (SharedPreferences.Editor) self[0];
    }

    private static SharedPreferences preferences(Map<String, Object> values) {
        return (SharedPreferences) Proxy.newProxyInstance(SharedPreferences.class.getClassLoader(),
                new Class<?>[]{SharedPreferences.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "contains" -> values.containsKey(args[0]);
                    case "getString" -> (String) values.getOrDefault(args[0], args[1]);
                    case "getBoolean" -> (Boolean) values.getOrDefault(args[0], args[1]);
                    default -> throw new AssertionError(method.getName());
                });
    }
}
