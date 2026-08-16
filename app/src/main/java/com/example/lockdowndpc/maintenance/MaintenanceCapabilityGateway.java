package com.example.lockdowndpc.maintenance;

import java.util.List;

/**
 * Applies and verifies the non-restriction effects of a maintenance window.
 *
 * <p>Most capabilities are expressed entirely as Android user restrictions and
 * are handled by the system-policy gateway. Application-store access is the
 * exception: Device Guard also hides known stores as applications, so opening
 * that capability has to restore their visibility and closing it has to hide
 * them again. Keeping that second device boundary behind a seam lets the
 * coordinator preserve its central rule: a window is never reported as open or
 * closed until every affected layer has been read back.
 */
public interface MaintenanceCapabilityGateway {

    /**
     * Withdraws application state that must not survive into {@code window},
     * before any restriction is relaxed.
     *
     * <p>This is a precondition, not an effect. The Google Play compatibility
     * exception leaves an application store available on a protected device; a
     * window that opens installation from unknown sources without opening
     * application-store access must not run beside it. Hiding the Store
     * afterwards, or on a later reconciliation pass, is not good enough: the
     * exposure is the Store's own interface and network surface, which an
     * installation restriction does not close, so the interval between relaxing
     * and hiding is a real one.
     *
     * <p>Failures here must prevent the window from opening. Nothing has been
     * relaxed at this point, so a refusal costs the administrator a retry and
     * costs the device nothing.
     *
     * @return the failures that must stop this window from opening, empty when
     *         the precondition is satisfied or there is nothing to withdraw
     */
    List<String> prepare(MaintenanceWindow window);

    /** Applies the non-restriction effects declared by {@code window}. */
    List<String> open(MaintenanceWindow window);

    /** Restores the protected application state after any maintenance window. */
    List<String> restore();
}
