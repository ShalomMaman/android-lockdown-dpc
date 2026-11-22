package com.example.lockdowndpc.security;

import android.os.SystemClock;

import java.util.concurrent.TimeUnit;

public final class AdminSession {
    private static final long SESSION_MILLIS = TimeUnit.MINUTES.toMillis(3);
    private static long unlockedUntilElapsed;
    private static long generation;

    private AdminSession() {}

    public static synchronized void unlock() {
        generation++;
        unlockedUntilElapsed = SystemClock.elapsedRealtime() + SESSION_MILLIS;
    }

    public static synchronized void extend() {
        if (isUnlocked()) {
            unlockedUntilElapsed = SystemClock.elapsedRealtime() + SESSION_MILLIS;
        }
    }

    public static synchronized boolean isUnlocked() {
        long deadline = unlockedUntilElapsed;
        return deadline != 0L && deadline > SystemClock.elapsedRealtime();
    }

    public static synchronized long activeGeneration() {
        return isUnlocked() ? generation : 0L;
    }

    public static synchronized void lock() {
        unlockedUntilElapsed = 0L;
    }
}
