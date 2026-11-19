package com.example.lockdowndpc.policy;

import android.content.SharedPreferences;

import org.junit.Test;

import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
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
