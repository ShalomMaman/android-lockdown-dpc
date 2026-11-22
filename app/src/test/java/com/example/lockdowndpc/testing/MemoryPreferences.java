package com.example.lockdowndpc.testing;

import android.content.SharedPreferences;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

/** Like Android, a commit changes memory even when it reports a disk failure. */
public final class MemoryPreferences {
    private final Map<String, Object> memory;
    public boolean failCommit = true;

    public MemoryPreferences(Map<String, ?> initial) {
        memory = new HashMap<>(initial);
    }

    public SharedPreferences preferences() {
        return (SharedPreferences) Proxy.newProxyInstance(SharedPreferences.class.getClassLoader(),
                new Class<?>[]{SharedPreferences.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "getAll" -> new HashMap<>(memory);
                    case "contains" -> memory.containsKey(args[0]);
                    case "getString", "getStringSet", "getInt", "getLong", "getBoolean" ->
                            memory.getOrDefault(args[0], args[1]);
                    case "edit" -> editor();
                    default -> throw new AssertionError(method.getName());
                });
    }

    private SharedPreferences.Editor editor() {
        Map<String, Object> changes = new HashMap<>();
        return (SharedPreferences.Editor) Proxy.newProxyInstance(
                SharedPreferences.Editor.class.getClassLoader(),
                new Class<?>[]{SharedPreferences.Editor.class}, (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "putString", "putStringSet", "putInt", "putLong", "putBoolean" ->
                                changes.put((String) args[0], args[1]);
                        case "remove" -> changes.put((String) args[0], null);
                        case "commit" -> {
                            changes.forEach((key, value) -> {
                                if (value == null) {
                                    memory.remove(key);
                                } else {
                                    memory.put(key, value);
                                }
                            });
                            return !failCommit;
                        }
                        default -> throw new AssertionError(method.getName());
                    }
                    return proxy;
                });
    }
}
