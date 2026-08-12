package com.example.lockdowndpc.kiosk;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.Log;

import com.example.lockdowndpc.admin.LockdownAdminReceiver;
import com.example.lockdowndpc.kiosk.KioskStateMachine.KioskAction;
import com.example.lockdowndpc.kiosk.KioskStateMachine.KioskState;
import com.example.lockdowndpc.policy.AuditLog;
import com.example.lockdowndpc.policy.LockdownPackages;
import com.example.lockdowndpc.policy.PolicyReconciliationCoordinator;
import com.example.lockdowndpc.security.AdminSession;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Device-side owner of kiosk mode: authorization, lock task, and the controlled
 * HOME component.
 *
 * <p>Authorization is never delegated. Every entry point derives the
 * administrator session from {@link AdminSession} itself, so no caller — UI,
 * receiver or future integration — can assert authentication on its own behalf.
 * The transition rules live in the pure {@link KioskStateMachine}.
 */
public final class KioskController {

    private static final String TAG = "KioskController";

    /** Kiosk host, referenced by name to keep this package free of UI coupling. */
    static final String HOST_ACTIVITY = "com.example.lockdowndpc.kiosk.KioskHostActivity";

    /** Boot restoration runs once per process, not once per activity recreation. */
    private static boolean bootRestoreAttempted;

    private KioskController() {}

    public record Result(boolean allowed, KioskState state, String reason, List<String> errors) {
        public Result {
            errors = List.copyOf(errors);
        }

        static Result denied(KioskState state, String reason) {
            return new Result(false, state, reason, List.of());
        }
    }

    // ---------------------------------------------------------------- requests

    /** Stores a configuration and arms kiosk. Requires an unlocked admin session. */
    public static synchronized Result requestConfigure(Context context, KioskConfig config) {
        Context app = context.getApplicationContext();
        KioskConfigValidator.Validation validation =
                KioskConfigValidator.validate(config, resolveTarget(app, config.targetPackage()));
        KioskState from = KioskConfigStore.readState(app);
        KioskStateMachine.Outcome outcome = KioskStateMachine.transition(new KioskStateMachine.Request(
                from,
                KioskAction.CONFIGURE,
                AdminSession.isUnlocked(),
                validation.valid()
        ));
        if (!outcome.allowed()) {
            return new Result(false, from, outcome.reason(), validation.errors());
        }
        KioskConfigStore.writeConfig(app, config, validation.normalizedSiteUrl());
        KioskConfigStore.writeState(app, outcome.state(), "");
        AuditLog.append(app, "תצורת קיוסק נשמרה: " + config.mode().name());
        return applyNow(app, outcome.state(), outcome.reason());
    }

    /** Enters lock task. Requires an unlocked admin session and a valid config. */
    public static synchronized Result requestEnter(Context context) {
        return requestTransition(context, KioskAction.ENTER, "כניסה למצב קיוסק");
    }

    /** Leaves lock task. Requires an unlocked admin session. */
    public static synchronized Result requestExit(Context context) {
        return requestTransition(context, KioskAction.EXIT, "יציאה ממצב קיוסק");
    }

    /** Drops the kiosk configuration and returns to managed filtering only. */
    public static synchronized Result requestClear(Context context) {
        Context app = context.getApplicationContext();
        KioskState from = KioskConfigStore.readState(app);
        KioskStateMachine.Outcome outcome = KioskStateMachine.transition(new KioskStateMachine.Request(
                from, KioskAction.CLEAR, AdminSession.isUnlocked(), true
        ));
        if (!outcome.allowed()) {
            return Result.denied(from, outcome.reason());
        }
        KioskConfigStore.clear(app);
        AuditLog.append(app, "תצורת קיוסק נמחקה");
        return applyNow(app, KioskState.OFF, outcome.reason());
    }

    /**
     * Re-asserts kiosk after a reboot or a process restart.
     *
     * <p>Deliberately unauthenticated, and deliberately one-directional: it can
     * only restore a state that was already {@code ACTIVE}, so a reboot is never
     * a way out of kiosk. A configuration that no longer validates lands in
     * {@link KioskState#FAULT}, where the host shows a safe error instead of
     * falling back to a launcher.
     */
    public static synchronized Result restoreAfterBootOnce(Context context) {
        if (bootRestoreAttempted) {
            return Result.denied(KioskConfigStore.readState(context), "already-restored");
        }
        bootRestoreAttempted = true;
        return restoreAfterBoot(context);
    }

    public static synchronized Result restoreAfterBoot(Context context) {
        Context app = context.getApplicationContext();
        KioskConfigStore.Settings settings = KioskConfigStore.read(app);
        if (settings.state() == KioskState.OFF) {
            return Result.denied(KioskState.OFF, "kiosk-off");
        }
        KioskConfigValidator.Validation validation = validate(app);
        KioskStateMachine.Outcome outcome = KioskStateMachine.transition(new KioskStateMachine.Request(
                settings.state(), KioskAction.BOOT_RESTORE, false, validation.valid()
        ));
        if (!outcome.allowed()) {
            return Result.denied(settings.state(), outcome.reason());
        }
        if (outcome.state() == KioskState.FAULT) {
            AuditLog.append(app, "שחזור קיוסק נכשל: " + String.join(", ", validation.errors()));
        }
        KioskConfigStore.writeState(app, outcome.state(), faultReason(validation));
        return applyNow(app, outcome.state(), outcome.reason());
    }

    /**
     * Records that kiosk cannot be honoured. Unauthenticated on purpose — it only
     * ever moves towards the safe error state, never out of kiosk.
     */
    public static synchronized Result reportFault(Context context, String reason) {
        Context app = context.getApplicationContext();
        KioskState from = KioskConfigStore.readState(app);
        KioskStateMachine.Outcome outcome = KioskStateMachine.transition(new KioskStateMachine.Request(
                from, KioskAction.FAULT, false, false
        ));
        if (!outcome.allowed() || from == KioskState.FAULT) {
            return Result.denied(from, outcome.reason());
        }
        KioskConfigStore.writeState(app, KioskState.FAULT, reason);
        AuditLog.append(app, "מצב קיוסק לא תקין: " + reason);
        return new Result(true, KioskState.FAULT, outcome.reason(), List.of());
    }

    private static Result requestTransition(Context context, KioskAction action, String auditEvent) {
        Context app = context.getApplicationContext();
        KioskConfigValidator.Validation validation = validate(app);
        KioskState from = KioskConfigStore.readState(app);
        KioskStateMachine.Outcome outcome = KioskStateMachine.transition(new KioskStateMachine.Request(
                from, action, AdminSession.isUnlocked(), validation.valid()
        ));
        if (!outcome.allowed()) {
            return new Result(false, from, outcome.reason(), validation.errors());
        }
        KioskConfigStore.writeState(app, outcome.state(), "");
        AuditLog.append(app, auditEvent);
        return applyNow(app, outcome.state(), outcome.reason());
    }

    // ------------------------------------------------------------- validation

    public static KioskConfigValidator.Validation validate(Context context) {
        KioskConfig config = KioskConfigStore.readConfig(context);
        return KioskConfigValidator.validate(config, resolveTarget(context, config.targetPackage()));
    }

    /** Resolves what the device reports about a candidate single-app target. */
    public static KioskAppTarget resolveTarget(Context context, String packageName) {
        if (packageName == null || packageName.isEmpty()) {
            return null;
        }
        PackageManager pm = context.getPackageManager();
        boolean deviceGuardItself = packageName.equals(context.getPackageName());
        boolean essential = LockdownPackages.classify(packageName, Set.of())
                == LockdownPackages.PackageClass.ESSENTIAL_SYSTEM_PACKAGE
                || LockdownPackages.isManagementPackage(packageName);
        ApplicationInfo info;
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                info = pm.getApplicationInfo(packageName, PackageManager.ApplicationInfoFlags.of(0));
            } else {
                //noinspection deprecation
                info = pm.getApplicationInfo(packageName, 0);
            }
        } catch (PackageManager.NameNotFoundException ignored) {
            return new KioskAppTarget(packageName, false, false, false, essential, deviceGuardItself);
        }
        boolean installed = (info.flags & ApplicationInfo.FLAG_INSTALLED) != 0;
        boolean launchable = pm.getLaunchIntentForPackage(packageName) != null;
        return new KioskAppTarget(
                packageName,
                installed,
                info.enabled,
                launchable,
                essential,
                deviceGuardItself
        );
    }

    public static boolean isActive(Context context) {
        return KioskConfigStore.isActive(context);
    }

    // ------------------------------------------------------------ enforcement

    private static Result applyNow(Context context, KioskState state, String reason) {
        DevicePolicyManager dpm = context.getSystemService(DevicePolicyManager.class);
        ComponentName admin = LockdownAdminReceiver.componentName(context);
        ArrayList<String> errors = new ArrayList<>();
        if (dpm == null || !dpm.isDeviceOwnerApp(context.getPackageName())) {
            errors.add("קיוסק דורש Device Owner");
            return new Result(false, state, "not-device-owner", errors);
        }
        reconcile(context, dpm, admin, errors);
        // Package hiding stays owned by the policy engine. Entering kiosk has to
        // hide the escape surfaces and leaving it has to restore them, so hand the
        // full pass to the existing serialized reconciler instead of duplicating
        // setApplicationHidden here. It no-ops while protection is paused, which is
        // also the only state in which those packages were never hidden.
        PolicyReconciliationCoordinator.reconcileAsync(context, "kiosk-state-change", null);
        return new Result(errors.isEmpty(), KioskConfigStore.readState(context), reason, errors);
    }

    /**
     * Brings lock task, lock task features and the HOME component in line with the
     * stored kiosk state.
     *
     * <p>Intentionally not {@code synchronized}: it is called from inside
     * {@code LockdownPolicyController.apply()/pause()} (which hold their own
     * monitor) and from {@link #applyNow}. Taking a second lock here would create
     * a lock-ordering cycle between the policy engine and the kiosk controller.
     *
     * @return {@code true} when persistent preferred activities were cleared, so
     *         the caller can re-register the managed-filtering link handlers
     */
    public static boolean reconcile(
            Context context,
            DevicePolicyManager dpm,
            ComponentName admin,
            List<String> errors
    ) {
        KioskConfigStore.Settings settings = KioskConfigStore.read(context);
        boolean active = settings.state() == KioskState.ACTIVE
                || settings.state() == KioskState.FAULT;
        if (!active) {
            return disableKiosk(context, dpm, admin, errors);
        }
        applyLockTaskPackages(context, dpm, admin, settings, errors);
        applyLockTaskFeatures(dpm, admin, errors);
        setHostComponentEnabled(context, true, errors);
        registerHome(context, dpm, admin, errors);
        return false;
    }

    private static boolean disableKiosk(
            Context context,
            DevicePolicyManager dpm,
            ComponentName admin,
            List<String> errors
    ) {
        boolean cleared = false;
        if (KioskConfigStore.isHomeRegistered(context)) {
            try {
                // Persistent preferred activities can only be cleared per package,
                // so the caller re-registers the managed-filtering link handlers.
                dpm.clearPackagePersistentPreferredActivities(admin, context.getPackageName());
                KioskConfigStore.setHomeRegistered(context, false);
                cleared = true;
            } catch (RuntimeException exception) {
                errors.add("ניקוי מסך הבית של הקיוסק: " + exception.getClass().getSimpleName());
            }
        }
        try {
            dpm.setLockTaskPackages(admin, new String[0]);
            if (dpm.isLockTaskPermitted(context.getPackageName())) {
                errors.add("ביטול נעילת המשימה לא אומת");
            }
        } catch (RuntimeException exception) {
            errors.add("ביטול נעילת המשימה: " + exception.getClass().getSimpleName());
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                dpm.setLockTaskFeatures(admin, DevicePolicyManager.LOCK_TASK_FEATURE_NONE);
            } catch (RuntimeException ignored) {
                // Features are only meaningful while packages are allowlisted.
            }
        }
        setHostComponentEnabled(context, false, errors);
        return cleared;
    }

    private static void applyLockTaskPackages(
            Context context,
            DevicePolicyManager dpm,
            ComponentName admin,
            KioskConfigStore.Settings settings,
            List<String> errors
    ) {
        LinkedHashSet<String> packages = new LinkedHashSet<>();
        // The DPC host stays allowlisted so the kiosk host, its safe error state
        // and the administrator PIN screen remain reachable for recovery.
        packages.add(context.getPackageName());
        if (settings.state() == KioskState.ACTIVE
                && settings.config().mode() == KioskMode.SINGLE_APP
                && !settings.config().targetPackage().isEmpty()) {
            packages.add(settings.config().targetPackage());
        }
        String[] allowlist = packages.toArray(new String[0]);
        try {
            dpm.setLockTaskPackages(admin, allowlist);
        } catch (RuntimeException exception) {
            errors.add("רשימת נעילת המשימה: " + exception.getClass().getSimpleName());
            return;
        }
        for (String packageName : allowlist) {
            if (!dpm.isLockTaskPermitted(packageName)) {
                errors.add("נעילת המשימה עבור " + packageName + " לא אומתה");
            }
        }
    }

    private static void applyLockTaskFeatures(
            DevicePolicyManager dpm,
            ComponentName admin,
            List<String> errors
    ) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            // Android 8.0/8.1 have no feature selector; lock task uses the legacy
            // behaviour (no Home, no Overview, no notification shade expansion).
            return;
        }
        int features = DevicePolicyManager.LOCK_TASK_FEATURE_NONE;
        try {
            dpm.setLockTaskFeatures(admin, features);
            if (dpm.getLockTaskFeatures(admin) != features) {
                errors.add("מאפייני נעילת המשימה לא אומתו");
            }
        } catch (RuntimeException exception) {
            errors.add("מאפייני נעילת המשימה: " + exception.getClass().getSimpleName());
        }
    }

    private static void registerHome(
            Context context,
            DevicePolicyManager dpm,
            ComponentName admin,
            List<String> errors
    ) {
        ComponentName host = new ComponentName(context.getPackageName(), HOST_ACTIVITY);
        try {
            IntentFilter filter = new IntentFilter(Intent.ACTION_MAIN);
            filter.addCategory(Intent.CATEGORY_HOME);
            filter.addCategory(Intent.CATEGORY_DEFAULT);
            dpm.addPersistentPreferredActivity(admin, filter, host);
            KioskConfigStore.setHomeRegistered(context, true);
        } catch (RuntimeException exception) {
            errors.add("מסך הבית של הקיוסק: " + exception.getClass().getSimpleName());
        }
    }

    private static void setHostComponentEnabled(
            Context context,
            boolean enabled,
            List<String> errors
    ) {
        ComponentName component = new ComponentName(context.getPackageName(), HOST_ACTIVITY);
        int state = enabled
                ? PackageManager.COMPONENT_ENABLED_STATE_ENABLED
                : PackageManager.COMPONENT_ENABLED_STATE_DISABLED;
        try {
            context.getPackageManager().setComponentEnabledSetting(
                    component, state, PackageManager.DONT_KILL_APP
            );
            if (context.getPackageManager().getComponentEnabledSetting(component) != state) {
                errors.add("רכיב מסך הקיוסק לא אומת");
            }
        } catch (RuntimeException exception) {
            Log.e(TAG, "Kiosk host component update failed", exception);
            errors.add("רכיב מסך הקיוסק: " + exception.getClass().getSimpleName());
        }
    }

    private static String faultReason(KioskConfigValidator.Validation validation) {
        return validation.valid() ? "" : String.join(", ", validation.errors());
    }
}
