package com.example.lockdowndpc.maintenance;

import com.example.lockdowndpc.policy.SystemPolicyControl;

import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * The capabilities a maintenance window may open, and the exact system policy
 * controls each one is allowed to relax.
 *
 * <p>Maintenance is not a pause of protection. It is a named, timed exception,
 * and this enum is what keeps it narrow: a window can only ever relax controls
 * that some selected capability declares here, so a new capability is a visible,
 * reviewable change rather than a wider {@code if} somewhere in the console.
 *
 * <h2>Why the declared set is deliberately small</h2>
 *
 * <p>Each capability names the smallest set of {@link SystemPolicyControl}s that
 * makes the service task possible. Nothing implies anything else — in
 * particular {@link #ADB_DEBUGGING} is never a side effect of another
 * capability, because clearing {@code DISALLOW_DEBUGGING_FEATURES} exposes a
 * privileged transport and that decision must be made explicitly, by name, with
 * its own warning.
 *
 * <p>The price of that narrowness is honest but real: opening one capability can
 * leave a second, still-enforced control blocking the same task.
 * {@link #blockedBy()} records those neighbours so
 * {@link MaintenancePlan#residualBlockers()} can say so on screen instead of
 * letting a technician watch an "open" window fail silently.
 *
 * <h2>No resource identifiers here</h2>
 *
 * <p>Like {@link SystemPolicyControl}, this enum stays free of {@code R} so the
 * decision classes remain ordinary JVM-testable code. The localized title,
 * consequence and warning live in {@link MaintenanceLabels}, keyed by
 * {@link #storageKey()}; {@code MaintenanceStringsParityTest} ties the two
 * together so a capability cannot reach the console as a blank row.
 */
public enum MaintenanceCapability {

    /**
     * Installing and updating through an application store or package installer.
     *
     * <p>Relaxes {@link SystemPolicyControl#APP_STORES_AND_INSTALLERS}, which is
     * opt-in on every profile. On a device where the administrator never turned
     * that control on, opening this capability changes nothing — and
     * {@link MaintenancePlan} reports it as relaxing nothing rather than
     * claiming an effect it did not have.
     */
    APP_STORE_ACCESS(
            "app_store_access",
            false,
            List.of(SystemPolicyControl.APP_STORES_AND_INSTALLERS),
            List.of()),

    /**
     * Installing a local APK from storage.
     *
     * <p>Relaxes the unknown-sources controls only. {@code DISALLOW_INSTALL_APPS}
     * blocks every installation path including this one, so when the base policy
     * also enforces {@link SystemPolicyControl#APP_STORES_AND_INSTALLERS} the
     * administrator has to open {@link #APP_STORE_ACCESS} as well. That is
     * reported as a residual blocker rather than quietly opened here: widening a
     * requested capability without being asked is exactly the behaviour this
     * feature exists to prevent.
     */
    LOCAL_APK_INSTALL(
            "local_apk_install",
            false,
            List.of(SystemPolicyControl.UNKNOWN_SOURCE_INSTALLS),
            List.of(SystemPolicyControl.APP_STORES_AND_INSTALLERS)),

    /**
     * The application controls in Settings — force stop, clear data, clear cache.
     *
     * <p>These are the Settings screens a service visit actually needs. The
     * capability deliberately does not reach date and time, users and profiles,
     * factory reset or Safe Boot: those are escape surfaces rather than repair
     * surfaces, and none of them is required to fix an application.
     */
    SELECTED_SETTINGS(
            "selected_settings",
            false,
            List.of(SystemPolicyControl.APP_CONTROL_SETTINGS),
            List.of()),

    /** Mounting the device as storage over USB, for moving files during a service visit. */
    USB_FILE_TRANSFER(
            "usb_file_transfer",
            false,
            List.of(SystemPolicyControl.USB_FILE_TRANSFER),
            List.of()),

    /**
     * Developer options, USB debugging and ADB. Break-glass.
     *
     * <p>The one capability that hands out a privileged transport rather than a
     * user-visible feature: with {@code DISALLOW_DEBUGGING_FEATURES} cleared, a
     * cable and an authorised host can drive the device outside everything this
     * console enforces. It therefore carries {@link #breakGlass()}, is never
     * implied by another capability, and — like every other window — closes on
     * expiry, on reboot and on cancel, with the previous policy restored and
     * read back afterwards.
     *
     * <p>Being reachable over the management transport is not a reason to open
     * it. Remote reachability and local debugging are different privileges.
     */
    ADB_DEBUGGING(
            "adb_debugging",
            true,
            List.of(SystemPolicyControl.DEVELOPER_OPTIONS_AND_ADB),
            List.of());

    private final String storageKey;
    private final boolean breakGlass;
    private final Set<SystemPolicyControl> relaxes;
    private final Set<SystemPolicyControl> blockedBy;

    MaintenanceCapability(
            String storageKey,
            boolean breakGlass,
            List<SystemPolicyControl> relaxes,
            List<SystemPolicyControl> blockedBy
    ) {
        this.storageKey = storageKey;
        this.breakGlass = breakGlass;
        this.relaxes = unmodifiableSetOf(relaxes);
        this.blockedBy = unmodifiableSetOf(blockedBy);
    }

    private static Set<SystemPolicyControl> unmodifiableSetOf(List<SystemPolicyControl> controls) {
        if (controls.isEmpty()) {
            return Collections.unmodifiableSet(EnumSet.noneOf(SystemPolicyControl.class));
        }
        return Collections.unmodifiableSet(EnumSet.copyOf(controls));
    }

    /** Stable persistence key, independent of the enum constant's name. */
    public String storageKey() {
        return storageKey;
    }

    /**
     * Whether opening this capability exposes a privileged transport rather than
     * a user-facing feature. The console must warn separately before confirming
     * one, and the audit log records it on its own line.
     */
    public boolean breakGlass() {
        return breakGlass;
    }

    /** Every control this capability is permitted to relax, and no other. */
    public Set<SystemPolicyControl> relaxes() {
        return relaxes;
    }

    /**
     * Controls that are not part of this capability but that will still block the
     * task while the base policy enforces them.
     *
     * <p>Reported, never opened. A technician who sees "still blocked by
     * application stores and installers" can decide to open that capability too;
     * a technician who sees nothing just watches an install fail.
     */
    public Set<SystemPolicyControl> blockedBy() {
        return blockedBy;
    }

    /** Looks a capability up by its stored key; {@code null} for an unknown key. */
    public static MaintenanceCapability fromStorageKey(String storageKey) {
        return Arrays.stream(values())
                .filter(capability -> capability.storageKey.equals(storageKey))
                .findFirst()
                .orElse(null);
    }

    /** Whether any capability in the set is break-glass. */
    public static boolean anyBreakGlass(Set<MaintenanceCapability> capabilities) {
        return capabilities != null && capabilities.stream().anyMatch(MaintenanceCapability::breakGlass);
    }

    /**
     * The union of everything the given capabilities may relax.
     *
     * <p>This is the ceiling {@link MaintenancePlan} is checked against: a plan
     * that would relax a control outside this set is rejected rather than
     * applied.
     */
    public static Set<SystemPolicyControl> relaxedControls(Set<MaintenanceCapability> capabilities) {
        LinkedHashSet<SystemPolicyControl> controls = new LinkedHashSet<>();
        if (capabilities != null) {
            for (SystemPolicyControl control : SystemPolicyControl.values()) {
                for (MaintenanceCapability capability : capabilities) {
                    if (capability != null && capability.relaxes.contains(control)) {
                        controls.add(control);
                        break;
                    }
                }
            }
        }
        return Collections.unmodifiableSet(controls);
    }

    /** A stable, non-sensitive list of storage keys, in enum order, for the audit log. */
    public static String summarize(Set<MaintenanceCapability> capabilities) {
        if (capabilities == null || capabilities.isEmpty()) {
            return "";
        }
        StringBuilder summary = new StringBuilder();
        for (MaintenanceCapability capability : values()) {
            if (capabilities.contains(capability)) {
                if (summary.length() > 0) {
                    summary.append(',');
                }
                summary.append(capability.storageKey);
            }
        }
        return summary.toString();
    }
}
