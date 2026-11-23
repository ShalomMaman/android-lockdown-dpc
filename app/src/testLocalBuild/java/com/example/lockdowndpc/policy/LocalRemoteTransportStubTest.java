package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.Test;

/**
 * Pins the debug/release RemoteTransport stub: it never marks, stores or schedules remote work,
 * and the remoteTest-only lab classes are absent from these builds.
 */
public class LocalRemoteTransportStubTest {

    private static final List<String> LAB_CLASSES = Arrays.asList(
            "com.example.lockdowndpc.policy.AndroidRemoteIdentity",
            "com.example.lockdowndpc.policy.RemoteTestJobService",
            "com.example.lockdowndpc.remote.RemoteHttps",
            "com.example.lockdowndpc.remote.RemotePinnedTrustManager");

    @Test
    public void stubRefusesEveryRemoteRequest() {
        assertFalse(RemoteTransport.mark(null, null));
        assertFalse(RemoteTransport.store(null, null));
        RemoteTransport.schedule(null);
    }

    @Test
    public void stubExposesOnlyTheThreeNoOpEntryPoints() {
        List<String> publicMethods = Arrays.stream(RemoteTransport.class.getDeclaredMethods())
                .filter(m -> Modifier.isPublic(m.getModifiers()))
                .map(Method::getName)
                .sorted()
                .collect(Collectors.toList());
        assertEquals(Arrays.asList("mark", "schedule", "store"), publicMethods);
    }

    @Test
    public void labClassesAreNotOnTheClasspath() {
        for (String name : LAB_CLASSES) {
            try {
                Class.forName(name, false, getClass().getClassLoader());
                fail(name + " must exist only in the remoteTest variant");
            } catch (ClassNotFoundException expected) {
                // The lab class is compiled out of this build.
            }
        }
    }
}
