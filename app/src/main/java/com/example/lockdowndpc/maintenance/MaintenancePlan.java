package com.example.lockdowndpc.maintenance;

import com.example.lockdowndpc.policy.SystemPolicyControl;
import com.example.lockdowndpc.policy.SystemPolicyEnforcer;
import com.example.lockdowndpc.policy.SystemPolicyProfile;

import java.util.Collections;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * The pure function from (base policy, open window) to the policy that should be
 * in force during maintenance — and back again.
 *
 * <p>Everything here is expressed in the existing vocabulary: a
 * {@link SystemPolicyProfile} and the administrator's stored choices, resolved
 * exactly the way {@link SystemPolicyEnforcer#requestedFor} resolves them. A
 * plan is therefore something the existing enforcer can apply unchanged, and the
 * read-back rule that governs every other policy pass governs this one too.
 *
 * <h2>Additive, reversible, and bounded</h2>
 *
 * <ul>
 *   <li><b>Additive.</b> A maintenance plan can only turn a control <em>off</em>.
 *       It never enforces something the base policy does not, so no window can
 *       leave a device more restricted than the administrator configured.</li>
 *   <li><b>Reversible.</b> {@link #restore} is the base choices, byte for byte.
 *       The inverse of a window is not "re-apply what maintenance changed" — it
 *       is the map that existed before, so a partially applied window still
 *       restores to the same place.</li>
 *   <li><b>Bounded.</b> Only controls a selected capability declares can be
 *       relaxed, and only when the base policy actually enforces them. A control
 *       the base leaves alone stays absent from the effective choices, so
 *       maintenance never starts managing something nobody asked it to
 *       manage.</li>
 * </ul>
 *
 * @param profile          the profile the choices are resolved against
 * @param baseChoices      the administrator's stored choices, unchanged
 * @param effectiveChoices what the enforcer should apply right now
 * @param relaxed          controls this plan actually turns off, which is the
 *                         subset of the window's declared set that the base
 *                         policy was enforcing
 * @param residualBlockers controls the base policy still enforces that will keep
 *                         a selected capability from working
 */
public record MaintenancePlan(
        SystemPolicyProfile profile,
        Map<SystemPolicyControl, Boolean> baseChoices,
        Map<SystemPolicyControl, Boolean> effectiveChoices,
        Set<SystemPolicyControl> relaxed,
        Set<SystemPolicyControl> residualBlockers
) {

    public MaintenancePlan {
        if (profile == null) {
            throw new IllegalArgumentException("A maintenance plan needs a profile");
        }
        baseChoices = copyChoices(baseChoices);
        effectiveChoices = copyChoices(effectiveChoices);
        relaxed = copyControls(relaxed);
        residualBlockers = copyControls(residualBlockers);
        for (SystemPolicyControl control : relaxed) {
            if (Boolean.TRUE.equals(effectiveChoices.get(control))) {
                throw new IllegalArgumentException(
                        "A relaxed control cannot still be requested: " + control);
            }
        }
    }

    /**
     * The policy to apply while {@code window} is open.
     *
     * @throws IllegalArgumentException when the window is {@code null}, which is
     *         not a plan the caller may guess at
     */
    public static MaintenancePlan forWindow(
            SystemPolicyProfile profile,
            Map<SystemPolicyControl, Boolean> baseChoices,
            MaintenanceWindow window
    ) {
        if (window == null) {
            throw new IllegalArgumentException("A maintenance plan needs an open window");
        }
        // copyChoices hands back an unmodifiable view, which is what the record
        // stores; the working copy has to be a map this method can still write to.
        Map<SystemPolicyControl, Boolean> effective = new LinkedHashMap<>(copyChoices(baseChoices));
        Set<SystemPolicyControl> relaxed = EnumSet.noneOf(SystemPolicyControl.class);
        Set<SystemPolicyControl> permitted = window.relaxableControls();

        for (SystemPolicyControl control : SystemPolicyControl.values()) {
            if (!permitted.contains(control)) {
                continue;
            }
            if (!SystemPolicyEnforcer.requestedFor(control, profile, baseChoices)) {
                // The base policy does not enforce it, so there is nothing to
                // relax. Writing an explicit "off" here would quietly make
                // maintenance the owner of a control the administrator never set.
                continue;
            }
            effective.put(control, false);
            relaxed.add(control);
        }

        Set<SystemPolicyControl> residual = EnumSet.noneOf(SystemPolicyControl.class);
        for (MaintenanceCapability capability : window.capabilities()) {
            for (SystemPolicyControl blocker : capability.blockedBy()) {
                if (relaxed.contains(blocker)) {
                    continue;
                }
                if (SystemPolicyEnforcer.requestedFor(blocker, profile, baseChoices)) {
                    residual.add(blocker);
                }
            }
        }

        return new MaintenancePlan(profile, baseChoices, effective, relaxed, residual);
    }

    /**
     * The plan that puts the device back exactly as the administrator configured
     * it, whatever a window did or half-did.
     */
    public static MaintenancePlan restore(
            SystemPolicyProfile profile,
            Map<SystemPolicyControl, Boolean> baseChoices
    ) {
        Map<SystemPolicyControl, Boolean> base = copyChoices(baseChoices);
        return new MaintenancePlan(
                profile,
                base,
                base,
                EnumSet.noneOf(SystemPolicyControl.class),
                EnumSet.noneOf(SystemPolicyControl.class));
    }

    /** Whether this plan changes anything at all. */
    public boolean relaxesAnything() {
        return !relaxed.isEmpty();
    }

    /** Whether any relaxed control is one of the break-glass surfaces. */
    public boolean relaxesDebugging() {
        return relaxed.contains(SystemPolicyControl.DEVELOPER_OPTIONS_AND_ADB);
    }

    /** What the base policy asks of one control, ignoring the window. */
    public boolean baseRequests(SystemPolicyControl control) {
        return SystemPolicyEnforcer.requestedFor(control, profile, baseChoices);
    }

    /** A stable, non-sensitive summary of what this plan relaxes, for the audit log. */
    public String relaxedSummary() {
        StringBuilder summary = new StringBuilder();
        for (SystemPolicyControl control : relaxed) {
            if (summary.length() > 0) {
                summary.append(',');
            }
            summary.append(control.storageKey());
        }
        return summary.toString();
    }

    private static Map<SystemPolicyControl, Boolean> copyChoices(
            Map<SystemPolicyControl, Boolean> choices
    ) {
        LinkedHashMap<SystemPolicyControl, Boolean> copy = new LinkedHashMap<>();
        if (choices != null) {
            for (SystemPolicyControl control : SystemPolicyControl.values()) {
                Boolean value = choices.get(control);
                if (value != null) {
                    copy.put(control, value);
                }
            }
        }
        return Collections.unmodifiableMap(copy);
    }

    private static Set<SystemPolicyControl> copyControls(Set<SystemPolicyControl> controls) {
        LinkedHashSet<SystemPolicyControl> copy = new LinkedHashSet<>();
        if (controls != null) {
            for (SystemPolicyControl control : SystemPolicyControl.values()) {
                if (controls.contains(control)) {
                    copy.add(control);
                }
            }
        }
        return Collections.unmodifiableSet(copy);
    }
}
