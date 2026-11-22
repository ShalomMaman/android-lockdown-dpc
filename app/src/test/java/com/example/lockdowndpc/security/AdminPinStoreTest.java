package com.example.lockdowndpc.security;

import android.content.SharedPreferences;

import org.junit.Test;

import java.lang.reflect.Proxy;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class AdminPinStoreTest {
    @Test
    public void initialSetupRefusesToOverwriteAnExistingPin() {
        AtomicReference<String> storedPin = new AtomicReference<>("first");

        assertFalse(AdminPinStore.setInitialPin(preferences(storedPin), () -> storedPin.set("second")));
        assertEquals("first", storedPin.get());
    }

    @Test
    public void replacementWithoutAnAdminSessionIsRefusedBeforeAccessingPreferences() {
        AdminSession.lock();

        assertFalse(AdminPinStore.replacePin(null, "123456"));
    }

    @Test
    public void concurrentInitialSetupsOnlySaveTheFirstPin() throws Exception {
        AtomicReference<String> storedPin = new AtomicReference<>();
        SharedPreferences prefs = preferences(storedPin);
        CountDownLatch firstWriting = new CountDownLatch(1);
        CountDownLatch finishFirstWrite = new CountDownLatch(1);
        CountDownLatch secondStarting = new CountDownLatch(1);
        ExecutorService callers = Executors.newFixedThreadPool(2);
        try {
            Future<Boolean> first = callers.submit(() -> AdminPinStore.setInitialPin(prefs, () -> {
                firstWriting.countDown();
                await(finishFirstWrite);
                storedPin.set("first");
            }));
            await(firstWriting);
            Future<Boolean> second = callers.submit(() -> {
                secondStarting.countDown();
                return AdminPinStore.setInitialPin(prefs, () -> storedPin.set("second"));
            });
            await(secondStarting);
            assertThrows(TimeoutException.class, () -> second.get(100, MILLISECONDS));
            finishFirstWrite.countDown();

            assertTrue(first.get(5, SECONDS));
            assertFalse(second.get(5, SECONDS));
            assertEquals("first", storedPin.get());
        } finally {
            finishFirstWrite.countDown();
            callers.shutdownNow();
        }
    }

    private static SharedPreferences preferences(AtomicReference<String> storedPin) {
        return (SharedPreferences) Proxy.newProxyInstance(SharedPreferences.class.getClassLoader(),
                new Class<?>[]{SharedPreferences.class}, (proxy, method, args) -> {
                    if (method.getName().equals("contains")) {
                        return switch ((String) args[0]) {
                            case "pin_salt", "pin_verifier" -> storedPin.get() != null;
                            default -> false;
                        };
                    }
                    throw new AssertionError(method.getName());
                });
    }

    private static void await(CountDownLatch latch) {
        try {
            assertTrue(latch.await(5, SECONDS));
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new AssertionError(exception);
        }
    }
}
