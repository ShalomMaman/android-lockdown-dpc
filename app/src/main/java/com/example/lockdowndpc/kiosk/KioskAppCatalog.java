package com.example.lockdowndpc.kiosk;

import com.example.lockdowndpc.policy.LockdownPackages;
import com.example.lockdowndpc.security.AppLabelSanitizer;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Which installed applications an administrator may pin as a single-app kiosk
 * target, decided purely.
 *
 * <p>One source of truth on purpose. The console picker filters with
 * {@link #selectable(List)} and {@link KioskController#resolveTarget} feeds the
 * same rule into {@link KioskConfigValidator}, so an entry that never appears in
 * the picker is also rejected when it arrives from stored configuration, a stale
 * preference or a future caller.
 *
 * <p>The exclusions are not cosmetic. Pinning a file manager, a documents
 * picker or the setup wizard as "the one allowed app" hands the student the
 * exact escape surface kiosk hides everywhere else, and pinning an essential
 * system component or the management transport takes the device somewhere the
 * console cannot repair.
 */
public final class KioskAppCatalog {

    private KioskAppCatalog() {}

    /**
     * What the device reports about one candidate, before any kiosk rule applies.
     *
     * @param packageName       candidate package
     * @param label             user-visible label, or the package name when unknown
     * @param installed         present with {@code FLAG_INSTALLED} for this user
     * @param enabled           application component state is enabled
     * @param launchable        resolves a MAIN/LAUNCHER entry point, including
     *                          while Device Guard currently hides the package
     * @param deviceGuardItself the DPC's own package
     */
    public record Candidate(
            String packageName,
            String label,
            boolean installed,
            boolean enabled,
            boolean launchable,
            boolean deviceGuardItself
    ) {
        public Candidate {
            packageName = packageName == null ? "" : packageName.trim();
            label = AppLabelSanitizer.sanitize(label);
            label = label == null || label.isBlank() ? packageName : label;
        }
    }

    /**
     * Packages that must never become a kiosk target, whatever the device says
     * about them.
     *
     * <p>Classified with an empty administrator-selected set on purpose: an
     * operator opting a system app into ordinary allow/block management must not
     * thereby make an escape surface eligible as the pinned kiosk application.
     */
    public static boolean isProtectedFromKiosk(String packageName) {
        if (packageName == null || packageName.isEmpty()) {
            return true;
        }
        if (LockdownPackages.ALWAYS_BLOCKED.contains(packageName)) {
            return true;
        }
        LockdownPackages.PackageClass packageClass =
                LockdownPackages.classify(packageName, Set.of());
        return packageClass == LockdownPackages.PackageClass.ESSENTIAL_SYSTEM_PACKAGE
                || packageClass == LockdownPackages.PackageClass.MANAGEMENT
                || packageClass == LockdownPackages.PackageClass.KIOSK_ESCAPE_SURFACE;
    }

    /** Whether {@code candidate} may be offered to, and chosen by, an administrator. */
    public static boolean isSelectable(Candidate candidate) {
        return candidate != null
                && !candidate.packageName().isEmpty()
                && !candidate.deviceGuardItself()
                && candidate.installed()
                && candidate.enabled()
                && candidate.launchable()
                && !isProtectedFromKiosk(candidate.packageName());
    }

    /**
     * The eligible subset, de-duplicated by package and ordered the way an
     * operator reads it: by label, case-insensitively, with the package name as
     * the tie-breaker so the order is stable between two identically labelled
     * applications.
     */
    public static List<Candidate> selectable(List<Candidate> candidates) {
        if (candidates == null) {
            return List.of();
        }
        LinkedHashSet<String> seen = new LinkedHashSet<>();
        ArrayList<Candidate> eligible = new ArrayList<>();
        for (Candidate candidate : candidates) {
            if (isSelectable(candidate) && seen.add(candidate.packageName())) {
                eligible.add(candidate);
            }
        }
        eligible.sort(Comparator
                .comparing((Candidate candidate) -> candidate.label().toLowerCase(Locale.ROOT))
                .thenComparing(Candidate::packageName));
        return List.copyOf(eligible);
    }
}
