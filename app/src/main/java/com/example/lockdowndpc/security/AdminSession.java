package com.example.lockdowndpc.security;

import android.os.SystemClock;

import java.util.concurrent.TimeUnit;

public final class AdminSession {
    private static final long SESSION_MILLIS = TimeUnit.MINUTES.toMillis(3);
    private static volatile long unlockedUntilElapsed;

    private AdminSession() {}

    public static void unlock() {
        unlockedUntilElapsed = SystemClock.elapsedRealtime() + SESSION_MILLIS;
    }

    public static void extend() {
        if (isUnlocked()) {
            unlock();
        }
    }

    public static boolean isUnlocked() {
        return unlockedUntilElapsed > SystemClock.elapsedRealtime();
    }

    public static void lock() {
        unlockedUntilElapsed = 0L;
    }
}
