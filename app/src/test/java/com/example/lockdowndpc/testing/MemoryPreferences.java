package com.example.lockdowndpc.testing;

import android.content.SharedPreferences;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

/** Like Android, a commit changes memory even when it reports a disk failure. */
public final class MemoryPreferences {
    private final Map<String, Object> memory;
    private final Map<String, Object> durable;
    public Consumer<Set<String>> beforeCommit = keys -> {};
    public Consumer<Set<String>> afterCommit = keys -> {};
    public boolean failCommit = true;
    public boolean throwBeforeCommit;
    public int successfulCommits;

    public MemoryPreferences(Map<String, ?> initial) {
        memory = new HashMap<>(initial);
        durable = new HashMap<>(initial);
    }

    public void restart() {
        memory.clear();
        memory.putAll(durable);
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
        boolean[] clear = {false};
        return (SharedPreferences.Editor) Proxy.newProxyInstance(
                SharedPreferences.Editor.class.getClassLoader(),
                new Class<?>[]{SharedPreferences.Editor.class}, (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "putString", "putStringSet", "putInt", "putLong", "putBoolean" ->
                                changes.put((String) args[0], args[1]);
                        case "remove" -> changes.put((String) args[0], null);
                        case "clear" -> clear[0] = true;
                        case "commit" -> {
                            // Like Android, a clear applies before the other edits of the same commit.
                            Set<String> touched = new HashSet<>(changes.keySet());
                            if (clear[0]) {
                                touched.addAll(memory.keySet());
                            }
                            beforeCommit.accept(Set.copyOf(touched));
                            if (throwBeforeCommit) {
                                throw new IllegalStateException("Cannot update preferences");
                            }
                            if (clear[0]) {
                                memory.clear();
                            }
                            changes.forEach((key, value) -> {
                                if (value == null) {
                                    memory.remove(key);
                                } else {
                                    memory.put(key, value);
                                }
                            });
                            if (failCommit) return false;
                            successfulCommits++;
                            durable.clear();
                            durable.putAll(memory);
                            afterCommit.accept(Set.copyOf(touched));
                            return true;
                        }
                        default -> throw new AssertionError(method.getName());
                    }
                    return proxy;
                });
    }
}
