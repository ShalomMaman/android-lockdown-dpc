package com.example.lockdowndpc.health;

import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;

import com.example.lockdowndpc.BuildConfig;
import com.example.lockdowndpc.kiosk.KioskConfigStore;
import com.example.lockdowndpc.kiosk.KioskMode;
import com.example.lockdowndpc.kiosk.KioskStateMachine.KioskState;
import com.example.lockdowndpc.maintenance.MaintenanceCapability;
import com.example.lockdowndpc.maintenance.MaintenanceStateMachine;
import com.example.lockdowndpc.maintenance.MaintenanceStore;
import com.example.lockdowndpc.maintenance.MaintenanceWindow;
import com.example.lockdowndpc.policy.AllowedAppsStore;
import com.example.lockdowndpc.policy.LockdownPackages;
import com.example.lockdowndpc.policy.ManagementIdentityInspector;
import com.example.lockdowndpc.policy.ManagementIdentityStatus;
import com.example.lockdowndpc.policy.ReconciliationRecord;
import com.example.lockdowndpc.policy.SystemPolicyControl;
import com.example.lockdowndpc.policy.SystemPolicyOutcome;
import com.example.lockdowndpc.policy.SystemPolicyStore;
import com.example.lockdowndpc.updates.UpdateConfig;
import com.example.lockdowndpc.updates.UpdatePhase;
import com.example.lockdowndpc.updates.UpdateSnapshot;
import com.example.lockdowndpc.updates.UpdateStateStore;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Reads the device state the health report describes.
 *
 * <p>This is the only class in the feature that touches Android, which is the
 * point: {@link DeviceHealthAssessor}, {@link DeviceHealthRedaction} and
 * {@link DeviceHealthReport} stay ordinary JVM code, and everything that can
 * throw is confined here.
 *
 * <h2>A collector that throws is a collector that lies</h2>
 *
 * <p>Every section is read inside its own {@code try}. A section that cannot be
 * read falls back to the {@code unknown()} value for that section rather than
 * propagating, because the alternative — a report that fails to render — leaves
 * an administrator with no information at all, and the alternative to
 * <em>that</em> — treating an unreadable section as fine — is the one outcome
 * the whole feature exists to prevent. Unknown is never healthy; it is
 * {@code UNVERIFIED}.
 *
 * <p>Nothing here writes, and nothing here reaches the network.
 */
public final class DeviceHealthCollector {

    private DeviceHealthCollector() {}

    /** Everything the report needs, read from this device, right now. */
    public static DeviceHealthSnapshot read(Context context) {
        if (context == null) {
            return DeviceHealthSnapshot.unreadable();
        }
        Context appContext = context.getApplicationContext();
        return new DeviceHealthSnapshot(
                readPolicy(appContext),
                readKiosk(appContext),
                readUpdates(appContext),
                readManagementIdentities(appContext),
                readReconciliation(appContext),
                readPlatform(),
                // AuditLog stores localized prose with no machine code, and the
                // redaction allowlist works on codes, so an unconverted tail
                // would export as nothing anyway. The local report shows the
                // audit log on its own screen.
                List.of(),
                readMaintenance(appContext));
    }

    private static DeviceHealthSnapshot.Policy readPolicy(Context context) {
        try {
            AllowedAppsStore.PolicyState state = AllowedAppsStore.getPolicyState(context);
            DeviceHealthSnapshot.PolicyVerification verification = switch (state) {
                case INACTIVE -> DeviceHealthSnapshot.PolicyVerification.NOT_REQUESTED;
                case APPLYING -> DeviceHealthSnapshot.PolicyVerification.REQUESTED_NOT_VERIFIED;
                case ACTIVE -> DeviceHealthSnapshot.PolicyVerification.VERIFIED;
                case FAILED -> DeviceHealthSnapshot.PolicyVerification.FAILED;
            };
            String error = AllowedAppsStore.getPolicyError(context);
            List<String> errors = error == null || error.isBlank() ? List.of() : List.of(error);
            return new DeviceHealthSnapshot.Policy(
                    verification,
                    readOwnership(context),
                    AllowedAppsStore.getPolicyVerifiedAt(context),
                    errors,
                    readPackageCensus(context),
                    readSystemControls(context));
        } catch (RuntimeException exception) {
            return DeviceHealthSnapshot.Policy.unknown();
        }
    }

    /**
     * Three states rather than a boolean.
     *
     * <p>"The platform could not be asked" is not "Device Guard is not the
     * owner": the first sends an operator to look, the second sends them to
     * re-provision a device that may be perfectly healthy.
     */
    private static DeviceHealthSnapshot.Ownership readOwnership(Context context) {
        try {
            DevicePolicyManager dpm = context.getSystemService(DevicePolicyManager.class);
            if (dpm == null) {
                return DeviceHealthSnapshot.Ownership.UNKNOWN;
            }
            return dpm.isDeviceOwnerApp(context.getPackageName())
                    ? DeviceHealthSnapshot.Ownership.DEVICE_OWNER
                    : DeviceHealthSnapshot.Ownership.NOT_DEVICE_OWNER;
        } catch (RuntimeException exception) {
            return DeviceHealthSnapshot.Ownership.UNKNOWN;
        }
    }

    /**
     * Counts only.
     *
     * <p>The names are available on the inventory screen to an administrator who
     * is holding the device. A census that travels is a list of everything a
     * person uses, so this one carries numbers.
     */
    private static DeviceHealthSnapshot.PackageCensus readPackageCensus(Context context) {
        try {
            int allowed = AllowedAppsStore.getAllowedPackages(context).size();
            int managed = AllowedAppsStore.getManagedPackages(context).size();
            return DeviceHealthSnapshot.PackageCensus.counted(Math.max(0, managed - allowed), allowed);
        } catch (RuntimeException exception) {
            return DeviceHealthSnapshot.PackageCensus.none();
        }
    }

    private static DeviceHealthSnapshot.SystemControls readSystemControls(Context context) {
        try {
            int requested = 0;
            int applied = 0;
            int faulted = 0;
            int advisory = 0;
            int unsupportedRequested = 0;
            for (SystemPolicyControl control : SystemPolicyControl.values()) {
                boolean on = SystemPolicyStore.isRequested(context, control);
                SystemPolicyOutcome outcome = SystemPolicyStore.lastOutcome(context, control);
                if (on) {
                    requested++;
                }
                if (outcome == SystemPolicyOutcome.APPLIED) {
                    applied++;
                } else if (outcome == SystemPolicyOutcome.UNSUPPORTED) {
                    if (on) {
                        unsupportedRequested++;
                    }
                } else if (outcome == SystemPolicyOutcome.FAILED) {
                    // The same split the report uses: a requested critical
                    // control that failed leaves the device weaker than asked;
                    // anything else is recorded without faulting protection.
                    if (on && control.critical()) {
                        faulted++;
                    } else {
                        advisory++;
                    }
                }
            }
            return new DeviceHealthSnapshot.SystemControls(
                    requested, applied, faulted, advisory, unsupportedRequested);
        } catch (RuntimeException exception) {
            return DeviceHealthSnapshot.SystemControls.none();
        }
    }

    private static DeviceHealthSnapshot.Kiosk readKiosk(Context context) {
        try {
            KioskConfigStore.Settings settings = KioskConfigStore.read(context);
            KioskState state = settings.state();
            DeviceHealthSnapshot.KioskPresence presence = switch (state) {
                case OFF -> DeviceHealthSnapshot.KioskPresence.OFF;
                case ARMED -> DeviceHealthSnapshot.KioskPresence.ARMED;
                case ACTIVE -> DeviceHealthSnapshot.KioskPresence.ACTIVE;
                case FAULT -> DeviceHealthSnapshot.KioskPresence.FAULT;
            };
            KioskMode mode = settings.config().mode();
            DeviceHealthSnapshot.KioskProfile profile = switch (mode) {
                case OFF -> DeviceHealthSnapshot.KioskProfile.NONE;
                case SINGLE_APP -> DeviceHealthSnapshot.KioskProfile.SINGLE_APP;
                case SINGLE_SITE -> DeviceHealthSnapshot.KioskProfile.SINGLE_SITE;
            };
            String target = settings.config().targetPackage();
            // The URL is passed whole: DeviceHealthRedaction reduces it to its
            // origin before anything can leave the device, and the local report
            // an administrator reads on the device may show what was configured.
            return new DeviceHealthSnapshot.Kiosk(
                    presence,
                    profile,
                    target,
                    settings.config().siteUrl(),
                    profile != DeviceHealthSnapshot.KioskProfile.SINGLE_APP
                            || isInstalled(context, target));
        } catch (RuntimeException exception) {
            return DeviceHealthSnapshot.Kiosk.unknown();
        }
    }

    private static DeviceHealthSnapshot.Updates readUpdates(Context context) {
        try {
            UpdateSnapshot snapshot = UpdateStateStore.INSTANCE.read(context);
            UpdatePhase phase = snapshot.getPhase();
            long lastChecked = snapshot.getLastCheckedAt();
            DeviceHealthSnapshot.UpdateState state = switch (phase) {
                case DISABLED -> DeviceHealthSnapshot.UpdateState.NOT_CONFIGURED;
                case CHECKING, DOWNLOADING, INSTALLING -> DeviceHealthSnapshot.UpdateState.IN_PROGRESS;
                case UP_TO_DATE, INSTALLED -> DeviceHealthSnapshot.UpdateState.UP_TO_DATE;
                case FAILED -> DeviceHealthSnapshot.UpdateState.FAILED;
                case IDLE -> lastChecked == 0L
                        ? DeviceHealthSnapshot.UpdateState.NEVER_CHECKED
                        : DeviceHealthSnapshot.UpdateState.UP_TO_DATE;
            };
            if (phase == UpdatePhase.IDLE && snapshot.getCandidateVersionCode() > 0) {
                state = DeviceHealthSnapshot.UpdateState.UPDATE_PENDING;
            }
            return new DeviceHealthSnapshot.Updates(
                    UpdateConfig.INSTANCE.isConfigured(),
                    state,
                    lastChecked,
                    snapshot.getMessage(),
                    BuildConfig.VERSION_NAME,
                    BuildConfig.VERSION_CODE);
        } catch (RuntimeException exception) {
            return DeviceHealthSnapshot.Updates.unknown();
        }
    }

    private static List<DeviceHealthSnapshot.ManagementIdentity> readManagementIdentities(
            Context context
    ) {
        try {
            List<DeviceHealthSnapshot.ManagementIdentity> identities = new ArrayList<>();
            for (ManagementIdentityStatus status : ManagementIdentityInspector.inspect(
                    AllowedAppsStore.getManagementCertificatePins(context),
                    new PackageManagerSignerSource(context))) {
                identities.add(new DeviceHealthSnapshot.ManagementIdentity(
                        status.packageName(), verdictOf(status)));
            }
            return identities;
        } catch (RuntimeException exception) {
            return List.of();
        }
    }

    private static DeviceHealthSnapshot.IdentityVerdict verdictOf(ManagementIdentityStatus status) {
        if (!status.installed()) {
            return DeviceHealthSnapshot.IdentityVerdict.NOT_INSTALLED;
        }
        return switch (status.verdict()) {
            case MATCH -> DeviceHealthSnapshot.IdentityVerdict.PINNED_MATCH;
            case MISMATCH -> DeviceHealthSnapshot.IdentityVerdict.PINNED_MISMATCH;
            case UNPINNED -> DeviceHealthSnapshot.IdentityVerdict.UNPINNED;
            case UNKNOWN_SIGNER -> DeviceHealthSnapshot.IdentityVerdict.UNKNOWN_SIGNER;
        };
    }

    /**
     * The maintenance dimension.
     *
     * <p>Read through the same state machine the console and the guard use, so a
     * window that has already lapsed is reported as closed here rather than as an
     * open one the report would have to explain. Closing it is not this method's
     * job — a read must never change device state — but an owed restore is
     * surfaced, because that is the case where relaxations may still be in force.
     */
    private static DeviceHealthSnapshot.Maintenance readMaintenance(Context context) {
        try {
            MaintenanceWindow window = MaintenanceStore.readWindow(context);
            boolean owed = MaintenanceStore.restorePending(context);
            if (window == null) {
                return owed
                        ? new DeviceHealthSnapshot.Maintenance(
                                DeviceHealthSnapshot.MaintenancePresence.RESTORE_OWED,
                                List.of(), false, 0L)
                        : DeviceHealthSnapshot.Maintenance.closed();
            }
            MaintenanceStateMachine.Evaluation evaluation =
                    MaintenanceStateMachine.evaluate(window, MaintenanceStore.deviceClock());
            if (!evaluation.open()) {
                return new DeviceHealthSnapshot.Maintenance(
                        DeviceHealthSnapshot.MaintenancePresence.RESTORE_OWED,
                        List.of(), false, 0L);
            }
            List<String> keys = new ArrayList<>();
            for (MaintenanceCapability capability : window.capabilities()) {
                keys.add(capability.storageKey());
            }
            return new DeviceHealthSnapshot.Maintenance(
                    DeviceHealthSnapshot.MaintenancePresence.OPEN,
                    keys,
                    window.breakGlass(),
                    window.expectedCloseWallClock());
        } catch (RuntimeException exception) {
            return DeviceHealthSnapshot.Maintenance.unknown();
        }
    }

    private static DeviceHealthSnapshot.Reconciliation readReconciliation(Context context) {
        try {
            ReconciliationRecord.Snapshot record = ReconciliationRecord.read(context);
            DeviceHealthSnapshot.ReconciliationOutcome outcome = switch (record.outcome()) {
                case NEVER_RUN -> DeviceHealthSnapshot.ReconciliationOutcome.NEVER_RUN;
                case VERIFIED -> DeviceHealthSnapshot.ReconciliationOutcome.VERIFIED;
                case FAILED -> DeviceHealthSnapshot.ReconciliationOutcome.FAILED;
                case CRASHED -> DeviceHealthSnapshot.ReconciliationOutcome.CRASHED;
            };
            return new DeviceHealthSnapshot.Reconciliation(
                    outcome, record.atMillis(), record.trigger(), record.detail());
        } catch (RuntimeException exception) {
            return DeviceHealthSnapshot.Reconciliation.unknown();
        }
    }

    private static DeviceHealthSnapshot.Platform readPlatform() {
        try {
            return new DeviceHealthSnapshot.Platform(
                    Build.VERSION.RELEASE,
                    Build.VERSION.SDK_INT,
                    Build.FINGERPRINT,
                    BuildConfig.VERSION_NAME,
                    BuildConfig.VERSION_CODE);
        } catch (RuntimeException exception) {
            return DeviceHealthSnapshot.Platform.unreadable();
        }
    }

    private static boolean isInstalled(Context context, String packageName) {
        if (packageName == null || packageName.isEmpty()) {
            return false;
        }
        try {
            context.getPackageManager().getApplicationInfo(packageName, 0);
            return true;
        } catch (PackageManager.NameNotFoundException | RuntimeException exception) {
            return false;
        }
    }

    /**
     * The signer reader, mirroring
     * {@code LockdownPolicyController.signingCertificateDigests} so the report
     * describes the identity the policy engine actually acts on.
     */
    private static final class PackageManagerSignerSource
            implements ManagementIdentityInspector.SignerSource {

        private final Context context;

        PackageManagerSignerSource(Context context) {
            this.context = context;
        }

        @Override
        public boolean isInstalled(String packageName) {
            try {
                context.getPackageManager().getApplicationInfo(packageName, 0);
                return true;
            } catch (PackageManager.NameNotFoundException exception) {
                return false;
            }
        }

        @Override
        public Set<String> signingCertificateSha256(String packageName) {
            LinkedHashSet<String> digests = new LinkedHashSet<>();
            PackageManager packageManager = context.getPackageManager();
            try {
                Signature[] signatures;
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    PackageInfo info = packageManager.getPackageInfo(
                            packageName, PackageManager.GET_SIGNING_CERTIFICATES);
                    SigningInfo signingInfo = info.signingInfo;
                    if (signingInfo == null) {
                        return digests;
                    }
                    signatures = signingInfo.hasMultipleSigners()
                            ? signingInfo.getApkContentsSigners()
                            : signingInfo.getSigningCertificateHistory();
                } else {
                    //noinspection deprecation
                    PackageInfo info = packageManager.getPackageInfo(
                            packageName, PackageManager.GET_SIGNATURES);
                    //noinspection deprecation
                    signatures = info.signatures;
                }
                if (signatures == null) {
                    return digests;
                }
                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                for (Signature signature : signatures) {
                    if (signature == null) {
                        continue;
                    }
                    digests.add(hex(sha256.digest(signature.toByteArray())));
                }
            } catch (Exception exception) {
                // No digest observed. A pinned record reads that as a refusal,
                // which is the fail-closed answer; an unpinned one was never
                // proving identity in the first place.
                return digests;
            }
            return digests;
        }

        private static String hex(byte[] bytes) {
            StringBuilder builder = new StringBuilder(bytes.length * 2);
            for (byte value : bytes) {
                builder.append(String.format(Locale.ROOT, "%02x", value));
            }
            return builder.toString();
        }
    }
}
