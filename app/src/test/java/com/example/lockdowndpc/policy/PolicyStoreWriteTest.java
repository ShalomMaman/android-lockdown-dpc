package com.example.lockdowndpc.policy;

import android.content.SharedPreferences;

import com.example.lockdowndpc.testing.MemoryPreferences;

import org.junit.Test;

import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class PolicyStoreWriteTest {

    @Test
    public void failedProtectionModeWriteKeepsOldModeAndLegacySelection() {
        Map<String, ?> before = Map.of(
                "protection_mode", "BLOCK_SELECTED",
                "allowed_packages", Set.of("com.example.old"),
                "allowlist_configured", true);
        MemoryPreferences fake = new MemoryPreferences(before);
        SharedPreferences prefs = fake.preferences();

        assertFalse(AllowedAppsStore.setProtectionMode(prefs, AllowedAppsStore.ProtectionMode.ALLOW_SELECTED));
        assertEquals(before, prefs.getAll());

        fake.failCommit = false;
        assertTrue(AllowedAppsStore.setProtectionMode(prefs, AllowedAppsStore.ProtectionMode.ALLOW_SELECTED));
        assertEquals("ALLOW_SELECTED", prefs.getString("protection_mode", null));
        assertEquals(Set.of("com.example.old"), prefs.getStringSet("allowed_packages:BLOCK_SELECTED", null));
        assertTrue(prefs.getBoolean("allowlist_configured:BLOCK_SELECTED", false));
        assertFalse(prefs.contains("allowed_packages"));
    }

    @Test
    public void failedAllowlistWriteRestoresSelectionInventoryAndConfiguredFlag() {
        Map<String, ?> before = Map.of(
                "allowed_packages:BLOCK_SELECTED", Set.of("com.example.old"),
                "managed_packages", Set.of("com.example.old", "com.example.other"));
        SharedPreferences prefs = new MemoryPreferences(before).preferences();

        assertFalse(AllowedAppsStore.setAllowedPackages(
                prefs, Set.of("com.example.new"), Set.of("com.example.new")));
        assertEquals(before, prefs.getAll());
    }

    @Test
    public void failedSystemPolicyWriteRestoresChoiceAndSchemaVersion() {
        SystemPolicyControl control = SystemPolicyControl.USB_FILE_TRANSFER;
        Map<String, ?> before = Map.of("choice:" + control.storageKey(), true);
        SharedPreferences prefs = new MemoryPreferences(before).preferences();

        assertFalse(SystemPolicyStore.setRequested(prefs, control, false));
        assertEquals(before, prefs.getAll());
    }
}
