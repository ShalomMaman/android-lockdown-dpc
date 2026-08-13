package com.example.lockdowndpc.ui

import com.example.lockdowndpc.policy.SystemAppClassifier
import com.example.lockdowndpc.policy.SystemAppClassifier.Category
import com.example.lockdowndpc.policy.SystemAppClassifier.Classification
import com.example.lockdowndpc.policy.SystemAppClassifier.PackageSnapshot
import com.example.lockdowndpc.policy.SystemAppClassifier.ProtectedContext
import com.example.lockdowndpc.policy.SystemAppClassifier.RiskAcceptanceStatus
import com.example.lockdowndpc.policy.SystemAppClassifier.RowState
import com.example.lockdowndpc.policy.SystemAppClassifier.Tier
import java.util.Locale

/**
 * The inventory row model and the pure logic over it — searching, filtering and
 * ordering. Everything in this file is free of Android and Compose types so it
 * can be covered by plain JVM unit tests; `SystemAppInventoryLoader.kt` builds
 * these rows from `PackageManager`, and `AllowedAppsActivity.kt` renders them.
 */

/**
 * One row of the application inventory.
 *
 * @param label already sanitized by `AppLabelSanitizer`; it is untrusted text
 *              from another application and is isolated again at render time
 * @param riskStatus freshness of any advanced risk acceptance on file for this
 *                   package; meaningful only for an unclassified OEM component
 * @param signerDigest lower-case hex SHA-256 of the installed signer, or empty
 *                     when the platform reported none. Recorded verbatim into a
 *                     risk acceptance so a later signer change is detectable.
 */
internal data class InventoryRow(
    val snapshot: PackageSnapshot,
    val classification: Classification,
    val label: String,
    val riskStatus: RiskAcceptanceStatus,
    val signerDigest: String,
    val version: String,
    val selected: Boolean,
) {
    val packageName: String get() = snapshot.packageName

    /** Whether the administrator may toggle this row right now. */
    val toggleable: Boolean get() = classification.blockable

    /**
     * Whether this row is an unclassified OEM component that needs an explicit
     * risk acceptance before it can be toggled at all.
     */
    val needsRiskAcceptance: Boolean
        get() = classification.tier == Tier.UNCLASSIFIED_OEM && !classification.blockable

    /** Rows whose selection is written to the guarded system-package store. */
    val isAdminSelectableSystem: Boolean
        get() = snapshot.anySystem() &&
            (classification.tier == Tier.KNOWN_MANAGEABLE || classification.tier == Tier.UNCLASSIFIED_OEM)
}

/**
 * Free-text search over a row. Matches the label or the package name, so an
 * operator can look for either "Photos" or `com.google.android.apps.photos`
 * without choosing a mode first.
 *
 * The comparison is case-insensitive in the root locale rather than the display
 * locale: package names are Latin identifiers, and a Turkish device would
 * otherwise fold `I` to a dotless `ı` and stop matching `com.instagram.android`.
 */
internal fun matchesInventoryQuery(label: String, packageName: String, query: String): Boolean {
    val trimmed = query.trim()
    if (trimmed.isEmpty()) return true
    return label.contains(trimmed, ignoreCase = true) ||
        packageName.lowercase(Locale.ROOT).contains(trimmed.lowercase(Locale.ROOT))
}

/** Applies the active category filter and search query, preserving order. */
internal fun filterInventory(
    rows: List<InventoryRow>,
    protectedContext: ProtectedContext,
    category: Category,
    query: String,
): List<InventoryRow> = rows.filter { row ->
    SystemAppClassifier.matchesCategory(
        row.classification,
        row.snapshot,
        protectedContext,
        category,
    ) && matchesInventoryQuery(row.label, row.packageName, query)
}

/**
 * Orders the inventory the way an administrator reads it: the rows they can act
 * on first, then the ones the policy already decides, then the protected core —
 * and alphabetically by label within each group.
 *
 * Sorting by label is done in the display locale (that is what the operator
 * sees), while the package-name tiebreak uses the root locale so two rows with
 * identical labels always land in a stable, device-independent order.
 */
internal fun sortInventory(rows: List<InventoryRow>): List<InventoryRow> =
    rows.sortedWith(
        compareBy<InventoryRow> { orderOf(it.classification.tier) }
            .thenBy { it.label.lowercase(Locale.getDefault()) }
            .thenBy { it.packageName.lowercase(Locale.ROOT) },
    )

private fun orderOf(tier: Tier): Int = when (tier) {
    Tier.ORDINARY -> 0
    Tier.KNOWN_MANAGEABLE -> 1
    Tier.UNCLASSIFIED_OEM -> 2
    Tier.POLICY_RULED -> 3
    Tier.PROTECTED_CORE -> 4
}

/**
 * Resolves a row's displayed state from its classification and the operator's
 * pending, unsaved selection.
 *
 * A protected or policy-ruled row ignores the selection entirely — its state is
 * whatever the policy engine will do regardless — which is what keeps the screen
 * from showing a state the next reconciliation pass would contradict.
 */
internal fun pendingRowState(
    row: InventoryRow,
    selected: Boolean,
    allowSelected: Boolean,
): RowState {
    if (!row.toggleable) return row.classification.state
    // "Allow only what I select" makes a ticked box mean allowed; "block what I
    // select" makes the same box mean blocked. The stored set is the same one in
    // both modes, which is why the meaning has to be resolved here and not by the
    // checkbox itself.
    val allowed = if (allowSelected) selected else !selected
    return if (allowed) RowState.ALLOWED else RowState.BLOCKED
}

/**
 * The system packages to write to `AllowedAppsStore.setAdminSelectedSystemPackages`.
 *
 * A system package is only put under allow/block control when the administrator
 * has actually engaged with it: it is opted in, and — for an unclassified OEM
 * component — its risk acceptance is still fresh. Everything else is left out, so
 * a package the operator merely scrolled past is untouched by the policy engine.
 */
internal fun adminSelectedSystemPackages(
    rows: List<InventoryRow>,
    optedIn: Set<String>,
): Set<String> = rows.asSequence()
    .filter { it.isAdminSelectableSystem }
    .filter { it.packageName in optedIn }
    .filter { it.classification.tier != Tier.UNCLASSIFIED_OEM || it.riskStatus == RiskAcceptanceStatus.FRESH }
    .map { it.packageName }
    .toSet()

/**
 * The selection to persist as the allow/block set.
 *
 * Ordinary third-party rows carry their ticks straight through. A system row
 * contributes only when it is also being opted into management, because the
 * policy engine reads one set for both and a stale tick on a package that is not
 * under management would resurface the moment someone opted it in later.
 */
internal fun persistedSelection(
    rows: List<InventoryRow>,
    ticked: Set<String>,
    adminSelectedSystem: Set<String>,
): Set<String> = rows.asSequence()
    .filter { it.toggleable && it.packageName in ticked }
    .filter { !it.snapshot.anySystem() || it.packageName in adminSelectedSystem }
    .map { it.packageName }
    .toSet()

/**
 * The third-party packages to persist as "managed".
 *
 * System packages are deliberately excluded. `LockdownPolicyController` puts
 * every managed package under the allow/block rules on its own, with no second
 * gate, so a system package in this set would be blockable without ever passing
 * the guarded system-package store — the exact bypass the risk acceptance exists
 * to prevent.
 */
internal fun managedPackagesToPersist(rows: List<InventoryRow>): Set<String> =
    rows.asSequence()
        .filter { !it.snapshot.anySystem() }
        .filter { it.classification.tier == Tier.ORDINARY }
        .map { it.packageName }
        .toSet()
