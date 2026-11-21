package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import android.content.SharedPreferences;

import org.junit.Test;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public final class AuditLogTest {
    @Test
    public void parsesLegacyTextEvenWhenItLooksLikeACode() {
        assertEquals(new AuditLog.Entry(1000, "legacy", "pin.set|historical text"),
                AuditLog.parse("1000|pin.set|historical text", false));
        assertEquals(new AuditLog.Entry(1000, "legacy", "historical text"),
                AuditLog.parse("1000|historical text", false));
    }

    @Test
    public void roundTripsCodedEntriesWithPipesAndFlattensNewlines() {
        AuditLog.Entry entry = new AuditLog.Entry(2000, AuditEvent.PIN_SET.code(), "first|second");
        assertEquals("2000|pin.set|first|second", entry.encode());
        assertEquals(entry, AuditLog.parse(entry.encode(), true));
        assertEquals("2000|pin.set|first second",
                new AuditLog.Entry(2000, "pin.set", "first\nsecond").encode());
        assertEquals(new AuditLog.Entry(2000, "pin.set", ""), AuditLog.parse("2000|pin.set|", true));
    }

    @Test
    public void formatsBothVersionsNewestFirstAndOmitsCodes() {
        SimpleDateFormat date = new SimpleDateFormat("HH:mm:ss", Locale.ROOT);
        date.setTimeZone(TimeZone.getTimeZone("UTC"));

        assertEquals("00:00:01 — first|second",
                AuditLog.format(List.of("1000|first|second"), false, date));
        assertEquals("00:00:02 — recent\n00:00:01 — first|second", AuditLog.format(
                List.of("1000|legacy|first|second", "broken|pin.set|ignore", "2000|pin.set|recent"),
                true, date));
    }

    @Test
    public void skipsMalformedRowsAndUnrecognizedCodes() {
        assertNull(AuditLog.parse("bad|text", false));
        assertNull(AuditLog.parse("1000|pin.set", true));
        assertNull(AuditLog.parse("1000|unknown.code|text", true));
    }

    @Test
    public void migratesOnFirstWriteAndKeepsOnlyTheLastFiftyRecords() {
        Map<String, Object> stored = new HashMap<>();
        stored.put("entries", IntStream.rangeClosed(1, 50)
                .mapToObj(time -> time + "|pin.set|older text")
                .collect(Collectors.joining("\n")));
        SharedPreferences prefs = preferences(stored);

        assertEquals(new AuditLog.CodeEntry(1, "legacy"), AuditLog.readCodes(prefs).get(0));
        SharedPreferences.Editor edit = AuditLog.edit(prefs, AuditEvent.PIN_SET, "new text");
        assertFalse(stored.containsKey("entries_have_codes"));
        assertTrue(edit.commit());

        List<AuditLog.CodeEntry> codes = AuditLog.readCodes(prefs);
        assertEquals(50, codes.size());
        assertEquals(new AuditLog.CodeEntry(2, "legacy"), codes.get(0));
        assertEquals(new AuditLog.CodeEntry(50, "legacy"), codes.get(48));
        assertEquals("pin.set", codes.get(49).code());
        assertTrue(((String) stored.get("entries")).startsWith("2|legacy|pin.set|older text\n"));
        assertTrue(((String) stored.get("entries")).endsWith("|pin.set|new text"));

        AuditLog.edit(prefs, AuditEvent.PIN_REPLACED, "replacement").apply();
        codes = AuditLog.readCodes(prefs);
        assertEquals(50, codes.size());
        assertEquals(new AuditLog.CodeEntry(3, "legacy"), codes.get(0));
        assertEquals("pin.set", codes.get(48).code());
        assertEquals("pin.replaced", codes.get(49).code());
    }

    private static SharedPreferences preferences(Map<String, Object> stored) {
        return proxy(SharedPreferences.class, (instance, method, args) -> switch (method.getName()) {
            case "getString", "getBoolean" -> stored.getOrDefault(args[0], args[1]);
            case "edit" -> {
                Map<String, Object> pending = new HashMap<>();
                yield proxy(SharedPreferences.Editor.class, (editor, action, values) -> {
                    switch (action.getName()) {
                        case "putString", "putBoolean" -> {
                            pending.put((String) values[0], values[1]);
                            return editor;
                        }
                        case "apply", "commit" -> {
                            stored.putAll(pending);
                            return "commit".equals(action.getName()) ? true : null;
                        }
                        default -> throw new AssertionError(action.getName());
                    }
                });
            }
            default -> throw new AssertionError(method.getName());
        });
    }

    private static <T> T proxy(Class<T> type, InvocationHandler handler) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, handler));
    }
}
