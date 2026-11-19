package com.example.lockdowndpc.policy;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class HomeFilterProbeTest {
    @Test
    public void optionalProbeRequiresHttpsAndBoundedExpectedText() {
        assertEquals(HomeFilterPolicy.ProbeState.NOT_RUN, HomeFilterProbe.check(null));
        assertThrows(IllegalArgumentException.class,
                () -> new HomeFilterPolicy.Canary("http://canary.example/check", "ok"));
        assertThrows(IllegalArgumentException.class,
                () -> new HomeFilterPolicy.Canary("https://name@canary.example/check", "ok"));
        assertThrows(IllegalArgumentException.class,
                () -> new HomeFilterPolicy.Canary("https://canary.example/check", " "));
        assertThrows(IllegalArgumentException.class,
                () -> new HomeFilterPolicy.Canary("https://canary.example/check", "x".repeat(1025)));
    }

    @Test
    public void requiresExactUtf8ResponseIncludingEndOfBody() throws Exception {
        assertTrue(HomeFilterProbe.matches(body("סינון"), "סינון"));
        assertFalse(HomeFilterProbe.matches(body("ok\n"), "ok"));
        assertFalse(HomeFilterProbe.matches(body("other"), "ok"));
        assertFalse(HomeFilterProbe.matches(body("o"), "ok"));
    }

    private static ByteArrayInputStream body(String value) {
        return new ByteArrayInputStream(value.getBytes(StandardCharsets.UTF_8));
    }
}
