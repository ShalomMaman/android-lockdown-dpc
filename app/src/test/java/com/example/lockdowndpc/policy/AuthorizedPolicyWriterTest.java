package com.example.lockdowndpc.policy;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.SharedPreferences;

import com.example.lockdowndpc.security.AdminSession;
import com.example.lockdowndpc.testing.MemoryPreferences;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 32)
public class AuthorizedPolicyWriterTest {
    private Context context;
    private static final String PACKAGE = "com.example.fixture";
    private static final Set<String> PACKAGES = Set.of(PACKAGE);
    private static final String MANAGEMENT_PACKAGE = LockdownPackages.managementPackageNames().iterator().next();

    @Before
    public void setUp() {
        context = RuntimeEnvironment.getApplication();
    }

    @After
    public void lockSession() {
        AdminSession.lock();
    }

    @Test
    public void rawPolicyMutatorsHavePackageVisibility() throws Exception {
        // Discover every store, including Kotlin stores and new stores added outside policy/.
        Path main = Path.of("src/main");
        if (!Files.isDirectory(main)) {
            main = Path.of("app/src/main");
        }
        try (var sources = Files.walk(main)) {
            var stores = sources.filter(path -> path.getFileName().toString().matches(".*Store\\.(java|kt)"))
                    .sorted().toList();
            assertFalse("No application stores discovered", stores.isEmpty());
            for (Path source : stores) {
                String packageName = Files.readAllLines(source).stream()
                        .filter(line -> line.startsWith("package ")).findFirst().orElseThrow()
                        .substring("package ".length()).replace(";", "").trim();
                String file = source.getFileName().toString();
                Class<?> store = Class.forName(packageName + "." + file.substring(0, file.lastIndexOf('.')),
                        false, getClass().getClassLoader());
                for (var method : store.getDeclaredMethods()) {
                    int access = Modifier.PUBLIC | Modifier.PROTECTED;
                    if ((method.getModifiers() & access) != 0) {
                        assertTrue("Public policy write bypasses the authority gate: " + method,
                                visibleStoreApi(store.getSimpleName(), method.getName()));
                    }
                }
            }
        }
    }

    @Test
    public void noLocalAuthorityWithoutLocalModeAndLiveSession() {
        AdminSession.unlock();
        assertNull(AdminAuthority.localSession(context));
        assertTrue(ManagementModeStore.selectLocal(context));
        AdminSession.lock();
        assertNull(AdminAuthority.localSession(context));

        assertDenied(null);
        AdminSession.unlock();
        AdminAuthority old = AdminAuthority.localSession(context);
        assertNotNull(old);
        AdminSession.extend();
        assertTrue(AdminAuthority.permitsLocal(context, old));
        AdminSession.lock();
        assertDenied(old);
        AdminSession.unlock();
        assertDenied(old);
    }

    @Test
    public void aMarkerRevokesAStillLiveLocalAuthority() {
        AdminAuthority authority = localAuthority();
        assertTrue(context.createDeviceProtectedStorageContext()
                .getSharedPreferences(ManagementModeStore.MARKER_PREFS, Context.MODE_PRIVATE)
                .edit().putBoolean(ManagementModeStore.MARKER_KEY, true).commit());

        assertDenied(authority);
        assertFalse(AuthorizedPolicyWriter.setSchedule(context, authority, ScheduleSettings.OFF));
        assertFalse(AuthorizedPolicyWriter.setBuiltInExemptions(
                context, authority, BuiltInBlockExemptions.Settings.NONE));
    }

    @Test
    public void localWritesSucceedAndFailedCommitLeavesTheOldPolicyVisible() {
        AdminAuthority authority = localAuthority();
        assertTrue(AuthorizedPolicyWriter.setProtectionMode(
                context, authority, AllowedAppsStore.ProtectionMode.ALLOW_SELECTED));
        assertTrue(AuthorizedPolicyWriter.setAllowedPackages(context, authority, PACKAGES, PACKAGES, Set.of()));
        SystemPolicyControl control = SystemPolicyControl.USB_FILE_TRANSFER;
        assertTrue(AuthorizedPolicyWriter.setSystemControl(context, authority, control, false));

        Map<String, ?> old = Map.of("compatibility_enabled", false, "changed_at", 123L);
        MemoryPreferences failing = new MemoryPreferences(old);
        SharedPreferences failedStore = failing.preferences();
        Context faulted = new ContextWrapper(context) {
            @Override
            public SharedPreferences getSharedPreferences(String name, int mode) {
                return name.equals("play_store_compatibility")
                        ? failedStore : super.getSharedPreferences(name, mode);
            }
        };

        assertFalse(AuthorizedPolicyWriter.setPlayCompatibility(faulted, authority, true));
        assertEquals(old, failedStore.getAll());
        assertFalse(PlayStoreCompatibilityStore.isEnabled(faulted));
        failing.failCommit = false;
        assertTrue(AuthorizedPolicyWriter.setPlayCompatibility(faulted, authority, true));
        assertTrue(PlayStoreCompatibilityStore.isEnabled(faulted));
    }

    private AdminAuthority localAuthority() {
        assertTrue(ManagementModeStore.selectLocal(context));
        AdminSession.unlock();
        AdminAuthority authority = AdminAuthority.localSession(context);
        assertNotNull(authority);
        return authority;
    }

    private void assertDenied(AdminAuthority authority) {
        assertFalse(AuthorizedPolicyWriter.setProtectionMode(
                context, authority, AllowedAppsStore.ProtectionMode.ALLOW_SELECTED));
        assertFalse(AuthorizedPolicyWriter.setAllowedPackages(context, authority, PACKAGES, PACKAGES, Set.of()));
        assertFalse(AuthorizedPolicyWriter.recordSystemRiskAcceptance(context, authority,
                new SystemAppRiskAcceptance(PACKAGE, "", "", "", "", 1L)));
        assertFalse(AuthorizedPolicyWriter.setManagementCertificatePins(
                context, authority, MANAGEMENT_PACKAGE, Set.of("01".repeat(32))));
        assertFalse(AuthorizedPolicyWriter.setSystemControl(
                context, authority, SystemPolicyControl.USB_FILE_TRANSFER, false));
        assertFalse(AuthorizedPolicyWriter.setPlayCompatibility(context, authority, true));
        assertFalse(AuthorizedPolicyWriter.setHomeFilter(context, authority, HomeFilterPolicy.Settings.OFF));
        assertFalse(AuthorizedPolicyWriter.recordScheduleOwnership(context, authority, PACKAGES));
        assertFalse(AuthorizedPolicyWriter.rememberManagedPackage(context, authority, PACKAGE, "Fixture"));
        assertFalse(AuthorizedPolicyWriter.commitKioskChange(context, authority, () -> {
            throw new AssertionError("A denied write must never execute");
        }));
        assertThrows(SecurityException.class, () -> HomeFilterController.retry(context, authority));
        assertEquals(AllowedAppsStore.ProtectionMode.BLOCK_SELECTED, AllowedAppsStore.getProtectionMode(context));
        assertFalse(AllowedAppsStore.isAllowlistConfigured(context));
        assertFalse(PlayStoreCompatibilityStore.isEnabled(context));
    }

    private static boolean visibleStoreApi(String store, String method) {
        if (method.matches("(get|is|has|read|watch|was|requires)[A-Z].*") || method.equals("read")) {
            return true;
        }
        // Named readers and state owned by authentication, provisioning,
        // maintenance, or updates. Evidence writes do not change policy choices.
        return switch (store) {
            case "AdminPinStore" -> Set.of("setInitialPin", "replacePin", "rotateRecoveryCode", "verify")
                    .contains(method);
            case "ManagementModeStore" -> method.equals("selectLocal");
            case "AllowedAppsStore" -> method.equals("rememberPackageLabel");
            case "BuiltInBlockExemptionsStore" -> Set.of("record", "chromeFlag", "readback").contains(method);
            case "PlayStoreCompatibilityStore" -> method.equals("changedAt");
            case "SystemPolicyStore" -> Set.of("effectiveProfile", "explicitChoices", "baseChoices",
                    "saveReport", "lastOutcome", "lastDetail", "lastVerifiedAt").contains(method);
            case "MaintenanceStore" -> Set.of("deviceClock", "liveWindow", "restorePending",
                    "clearRestorePending", "clearWindow", "clearForRemoteIntent").contains(method);
            case "UpdateStateStore" -> Set.of("recordChecking", "recordRetryPending", "recordDownloading",
                    "recordInstalling", "recordUpToDate", "recordInstalled", "recordFailure",
                    "highestAuthorizedVersion", "recordAuthorizedVersion").contains(method);
            default -> false;
        };
    }
}
