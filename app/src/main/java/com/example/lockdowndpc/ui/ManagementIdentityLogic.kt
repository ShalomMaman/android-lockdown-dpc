package com.example.lockdowndpc.ui

import com.example.lockdowndpc.policy.LockdownPackages
import com.example.lockdowndpc.policy.LockdownPackages.SignerVerdict
import com.example.lockdowndpc.policy.ManagementIdentityInspector
import com.example.lockdowndpc.policy.ManagementIdentityStatus
import java.util.Locale

/**
 * Pure decisions and formatting for the management identity console (Issue #27).
 *
 * Free of Android and Compose types on purpose, exactly like [KioskConsoleLogic]:
 * the parts worth proving are "what does this verdict mean for an operator",
 * "may this pasted digest be stored", and "which row needs attention first", and
 * those are provable on the JVM instead of on a device that has to be
 * re-provisioned after every wrong answer.
 *
 * Resource identifiers deliberately stay out of this file. The state enums below
 * are mapped to `management_identity_strings.xml` inside the composable, which
 * keeps every operator-facing word where the locale parity check can see it and
 * keeps this file loadable by a plain JUnit test.
 */

/**
 * How much attention a row needs, worst first.
 *
 * The declaration order is the order the console reads in, and it is what both
 * the row sort and [worstSeverityOf] rely on, so a state added later cannot
 * quietly sort itself above a refusal.
 */
internal enum class ManagementIdentitySeverity {
    /** Management privilege is being withheld from an installed package. */
    REFUSED,

    /** Trusted, but on a package name alone — the documented proof gap. */
    NOT_PROVEN,

    /** Nothing is trusted here because the package is not on this device. */
    ABSENT,

    /** An installed signer matched an approved certificate. */
    PROVEN,
}

/**
 * One management package's identity, in the terms the screen states.
 *
 * [SignerVerdict] is the enforcement seam's vocabulary and stays that way; this
 * enum is the operator's, which is why it splits "not installed" out of
 * `UNKNOWN_SIGNER` and keeps the two refusals apart — a mismatch and an
 * unreadable signer need different next steps from whoever is holding the
 * device.
 */
internal enum class ManagementIdentityState(val severity: ManagementIdentitySeverity) {
    PROVEN(ManagementIdentitySeverity.PROVEN),
    NAME_ONLY(ManagementIdentitySeverity.NOT_PROVEN),
    SIGNER_MISMATCH(ManagementIdentitySeverity.REFUSED),
    SIGNER_UNREADABLE(ManagementIdentitySeverity.REFUSED),
    NOT_INSTALLED(ManagementIdentitySeverity.ABSENT),
}

/**
 * Resolves the displayed state from an inspected status.
 *
 * A package that is not installed reports [ManagementIdentityState.NOT_INSTALLED]
 * whatever its verdict says, because the apply pass skips an absent package
 * entirely: telling an operator their transport was "refused" when it is simply
 * not there would send them to fix the wrong thing.
 */
internal fun managementIdentityStateOf(status: ManagementIdentityStatus): ManagementIdentityState {
    if (!status.installed()) return ManagementIdentityState.NOT_INSTALLED
    return when (status.verdict()) {
        SignerVerdict.MATCH -> ManagementIdentityState.PROVEN
        SignerVerdict.UNPINNED -> ManagementIdentityState.NAME_ONLY
        SignerVerdict.MISMATCH -> ManagementIdentityState.SIGNER_MISMATCH
        SignerVerdict.UNKNOWN_SIGNER -> ManagementIdentityState.SIGNER_UNREADABLE
    }
}

/** One rendered row: the evidence, plus what it means. */
internal data class ManagementIdentityRow(
    val status: ManagementIdentityStatus,
    val state: ManagementIdentityState,
) {
    val packageName: String get() = status.packageName()
    val installed: Boolean get() = status.installed()
    val severity: ManagementIdentitySeverity get() = state.severity

    /** Observed digests, in a stable order so the same device reads the same way. */
    val observedDigests: List<String> get() = status.observedCertificateSha256().sorted()

    val pinnedDigests: List<String> get() = status.pinnedCertificateSha256().sorted()

    /** Whether "pin the signer installed now" has anything to write. */
    val canPinInstalledSigner: Boolean get() = status.canPinInstalledSigner()

    /** The digests that action would add. */
    val pinnableObservedDigests: List<String> get() = status.unpinnedObservedDigests().sorted()
}

/**
 * Builds the rows an administrator reads, worst first.
 *
 * A refusal is at the top because it is already costing the device its
 * management transport; the unproven rows come next because they are the gap
 * this screen exists to close; a proven row needs nothing and sits last. Ties
 * break on the package name in the root locale, so the order is the same on
 * every device regardless of display language.
 */
internal fun managementIdentityRows(
    statuses: List<ManagementIdentityStatus>,
): List<ManagementIdentityRow> = statuses
    .map { ManagementIdentityRow(it, managementIdentityStateOf(it)) }
    .sortedWith(
        compareBy<ManagementIdentityRow> { it.severity.ordinal }
            .thenBy { it.packageName.lowercase(Locale.ROOT) },
    )

/**
 * The single line the summary card states: the worst row wins.
 *
 * An empty catalogue reports [ManagementIdentitySeverity.ABSENT] rather than
 * anything reassuring — "nothing to show" is not "everything is proven".
 */
internal fun worstSeverityOf(rows: List<ManagementIdentityRow>): ManagementIdentitySeverity =
    rows.minByOrNull { it.severity.ordinal }?.severity ?: ManagementIdentitySeverity.ABSENT

/** Why a pasted digest cannot be stored. */
internal enum class DigestProblem {
    NONE,
    EMPTY,
    NOT_HEXADECIMAL,
    WRONG_LENGTH,
    ALREADY_PINNED,
}

/**
 * A digest an operator typed or pasted, normalized and judged.
 *
 * [length] is the normalized length, which is what the "64 characters" error has
 * to quote: an operator who pasted a truncated digest needs to see how far off
 * it is, and counting the colons they pasted would be misleading.
 */
internal data class PastedDigest(
    val normalized: String,
    val length: Int,
    val problem: DigestProblem,
) {
    val usable: Boolean get() = problem == DigestProblem.NONE
}

/**
 * Normalizes and judges a pasted digest.
 *
 * Vendors publish certificate digests in several shapes — colon-separated,
 * space-separated, upper-case — and an operator pastes whichever one they were
 * given. All of those are accepted and folded to the stored form by
 * [LockdownPackages.normalizeDigest]; whether the result may actually be stored
 * is decided by [ManagementIdentityInspector.isPinnableDigest], the same rule the
 * store-write path applies, so this screen can explain a rejection without being
 * able to widen it.
 *
 * @param alreadyPinned the package's current approved certificates, normalized
 */
internal fun pastedDigestOf(raw: String, alreadyPinned: Set<String>): PastedDigest {
    val normalized = LockdownPackages.normalizeDigest(raw)
    val problem = when {
        normalized.isEmpty() -> DigestProblem.EMPTY
        normalized.any { it !in HEX_CHARACTERS } -> DigestProblem.NOT_HEXADECIMAL
        !ManagementIdentityInspector.isPinnableDigest(normalized) -> DigestProblem.WRONG_LENGTH
        normalized in alreadyPinned -> DigestProblem.ALREADY_PINNED
        else -> DigestProblem.NONE
    }
    return PastedDigest(normalized, normalized.length, problem)
}

private val HEX_CHARACTERS = ('0'..'9') + ('a'..'f')

/**
 * The audit key for one row's current identity: package name and verdict, and
 * deliberately nothing else.
 *
 * The audit log is readable by anyone who can reach the console with the
 * administrator PIN, so an entry carries what an operator has to be able to
 * reconstruct — which package, and what the engine decided — and no material an
 * attacker could use, in particular no PIN, no recovery code and no digest.
 */
internal fun managementAuditKeyOf(row: ManagementIdentityRow): String =
    "${row.packageName}:${row.status.verdict().name}"

/**
 * The refusals that still have to be recorded.
 *
 * A refusal is a security event — the device is running without its management
 * transport exempted — so it is audited when the console observes it, not only
 * when an operator acts. [alreadyAudited] holds the keys recorded in this
 * session, which keeps re-reading the screen from filling the fifty-entry log
 * with the same line.
 */
internal fun refusalsToAudit(
    rows: List<ManagementIdentityRow>,
    alreadyAudited: Set<String>,
): List<ManagementIdentityRow> = rows.filter { row ->
    row.status.refused() && managementAuditKeyOf(row) !in alreadyAudited
}
