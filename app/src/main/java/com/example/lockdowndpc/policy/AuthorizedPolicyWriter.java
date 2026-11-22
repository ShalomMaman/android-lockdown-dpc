package com.example.lockdowndpc.policy;

import android.content.Context;

import java.util.Set;
import java.util.function.BooleanSupplier;

/** Entry points for administrator-controlled policy preference writes. */
public final class AuthorizedPolicyWriter {
    private AuthorizedPolicyWriter() {}

    public static boolean setProtectionMode(Context context, AdminAuthority authority,
                                            AllowedAppsStore.ProtectionMode mode) {
        return AdminAuthority.permitsLocal(context, authority)
                && AllowedAppsStore.setProtectionMode(context, mode);
    }

    public static boolean setAllowedPackages(Context context, AdminAuthority authority,
                                             Set<String> packages, Set<String> managed,
                                             Set<String> systemSelection) {
        return AdminAuthority.permitsLocal(context, authority)
                && AllowedAppsStore.setAllowedPackages(context, packages, managed, systemSelection);
    }

    public static boolean recordSystemRiskAcceptance(Context context, AdminAuthority authority,
                                                      SystemAppRiskAcceptance acceptance) {
        return AdminAuthority.permitsLocal(context, authority)
                && AllowedAppsStore.recordSystemRiskAcceptance(context, acceptance);
    }

    public static boolean setManagementCertificatePins(Context context, AdminAuthority authority,
                                                       String packageName, Set<String> digests) {
        return AdminAuthority.permitsLocal(context, authority)
                && AllowedAppsStore.setManagementCertificatePins(context, packageName, digests);
    }

    public static boolean setSystemControl(Context context, AdminAuthority authority,
                                           SystemPolicyControl control, boolean requested) {
        return AdminAuthority.permitsLocal(context, authority)
                && SystemPolicyStore.setRequested(context, control, requested);
    }

    public static boolean setPlayCompatibility(Context context, AdminAuthority authority,
                                                boolean enabled) {
        return AdminAuthority.permitsLocal(context, authority)
                && PlayStoreCompatibilityStore.setEnabled(context, enabled);
    }

    static boolean setSchedule(Context context, AdminAuthority authority, ScheduleSettings settings) {
        if (ManagementModeStore.read(context) != ManagementMode.LOCAL_PIN) {
            return false;
        }
        // Tightening remains available from the locked local console.
        return (AdminAuthority.permitsLocal(context, authority)
                || ScheduleSettings.classify(ScheduleStore.read(context), settings)
                    != SchedulePolicy.Change.LOOSEN)
                && ScheduleStore.write(context, settings);
    }

    static boolean setBuiltInExemptions(Context context, AdminAuthority authority,
                                        BuiltInBlockExemptions.Settings settings) {
        if (ManagementModeStore.read(context) != ManagementMode.LOCAL_PIN) {
            return false;
        }
        BuiltInBlockExemptions.Record current = BuiltInBlockExemptionsStore.record(context);
        return (AdminAuthority.permitsLocal(context, authority)
                || (!current.unreadable() && !BuiltInBlockExemptionsStore.untrusted(context)
                    && !current.enforced().loosensTo(settings)))
                && BuiltInBlockExemptionsStore.write(context, settings);
    }

    static boolean recordScheduleOwnership(Context context, AdminAuthority authority, Set<String> owned) {
        return AdminAuthority.PolicyPass.permits(context, authority) && ScheduleStore.saveOwned(context, owned);
    }

    static boolean rememberManagedPackage(
            Context context, AdminAuthority authority, String packageName, String label
    ) {
        return AdminAuthority.PolicyPass.permits(context, authority)
                && AllowedAppsStore.rememberManagedPackage(context, packageName, label);
    }

    /** Commits a validated local change through the kiosk package's private store. */
    public static boolean commitKioskChange(Context context, AdminAuthority authority,
                                            BooleanSupplier commit) {
        return AdminAuthority.permitsLocal(context, authority) && commit.getAsBoolean();
    }

    static boolean setHomeFilter(Context context, AdminAuthority authority,
                                 HomeFilterPolicy.Settings settings) {
        if (!AdminAuthority.permitsLocal(context, authority)) {
            return false;
        }
        HomeFilterStore.write(context, settings);
        return true;
    }

    /** A policy pass can only settle an existing filter request against its read-back. */
    static HomeFilterPolicy.Settings finishHomeFilterReadback(
            Context context, HomeFilterPolicy.Settings stored, HomeFilterPolicy.Report report) {
        HomeFilterPolicy.Settings remaining = stored.afterReadback(report);
        if (!remaining.equals(stored) && ManagementModeStore.read(context).usesLocalPolicy()) {
            HomeFilterStore.write(context, remaining);
        }
        return remaining;
    }
}
