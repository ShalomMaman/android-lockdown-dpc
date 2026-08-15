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

    /** Applies the non-restriction effects declared by {@code window}. */
    List<String> open(MaintenanceWindow window);

    /** Restores the protected application state after any maintenance window. */
    List<String> restore();
}
