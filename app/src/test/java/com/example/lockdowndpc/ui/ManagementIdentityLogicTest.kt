package com.example.lockdowndpc.ui

import com.example.lockdowndpc.policy.LockdownPackages.SignerVerdict
import com.example.lockdowndpc.policy.ManagementIdentityStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The presentation decisions of the management identity console.
 *
 * Compose is never touched here. What is worth proving is the meaning the screen
 * assigns to a verdict, the shape of a digest an operator may paste, and the
 * order the rows are read in — and all three are ordinary values.
 */
class ManagementIdentityLogicTest {

    private val digestA = "a".repeat(64)
    private val digestB = "b".repeat(64)

    @Test
    fun everyVerdictOfAnInstalledPackageHasItsOwnMeaning() {
        assertEquals(
            ManagementIdentityState.PROVEN,
            managementIdentityStateOf(status(verdict = SignerVerdict.MATCH)),
        )
        assertEquals(
            ManagementIdentityState.NAME_ONLY,
            managementIdentityStateOf(status(verdict = SignerVerdict.UNPINNED)),
        )
        assertEquals(
            ManagementIdentityState.SIGNER_MISMATCH,
            managementIdentityStateOf(status(verdict = SignerVerdict.MISMATCH)),
        )
        assertEquals(
            ManagementIdentityState.SIGNER_UNREADABLE,
            managementIdentityStateOf(status(verdict = SignerVerdict.UNKNOWN_SIGNER)),
        )
    }

    @Test
    fun anAbsentPackageIsNeverPresentedAsARefusal() {
        // The apply pass skips a package that is not installed, so calling it
        // "refused" would send an operator to fix the wrong thing.
        val absent = status(installed = false, verdict = SignerVerdict.UNKNOWN_SIGNER)

        assertEquals(ManagementIdentityState.NOT_INSTALLED, managementIdentityStateOf(absent))
        assertEquals(
            ManagementIdentitySeverity.ABSENT,
            managementIdentityStateOf(absent).severity,
        )
    }

    @Test
    fun trustedByNameOnlyIsNeverTheSameSeverityAsProven() {
        // The whole point of the screen: an unpinned record is trusted by the
        // engine and unproven to the operator, and those must not read alike.
        assertEquals(
            ManagementIdentitySeverity.NOT_PROVEN,
            ManagementIdentityState.NAME_ONLY.severity,
        )
        assertEquals(ManagementIdentitySeverity.PROVEN, ManagementIdentityState.PROVEN.severity)
    }

    @Test
    fun rowsAreOrderedWorstFirstAndThenByPackageName() {
        val rows = managementIdentityRows(
            listOf(
                status(packageName = "com.example.proven", verdict = SignerVerdict.MATCH),
                status(packageName = "com.example.absent", installed = false),
                status(packageName = "com.example.unproven", verdict = SignerVerdict.UNPINNED),
                status(packageName = "com.example.refused.b", verdict = SignerVerdict.MISMATCH),
                status(packageName = "com.example.refused.a", verdict = SignerVerdict.UNKNOWN_SIGNER),
            )
        )

        assertEquals(
            listOf(
                "com.example.refused.a",
                "com.example.refused.b",
                "com.example.unproven",
                "com.example.absent",
                "com.example.proven",
            ),
            rows.map { it.packageName },
        )
    }

    @Test
    fun theSummaryReportsTheWorstRowAndNeverTheAverage() {
        val rows = managementIdentityRows(
            listOf(
                status(packageName = "com.example.proven", verdict = SignerVerdict.MATCH),
                status(packageName = "com.example.refused", verdict = SignerVerdict.MISMATCH),
            )
        )

        assertEquals(ManagementIdentitySeverity.REFUSED, worstSeverityOf(rows))
    }

    @Test
    fun anEmptyCatalogueIsNotReportedAsProven() {
        assertEquals(ManagementIdentitySeverity.ABSENT, worstSeverityOf(emptyList()))
    }

    @Test
    fun observedAndApprovedDigestsAreShownInAStableOrder() {
        val row = managementIdentityRows(
            listOf(
                status(
                    observed = setOf(digestB, digestA),
                    pinned = setOf(digestB, digestA),
                    verdict = SignerVerdict.MATCH,
                )
            )
        ).single()

        assertEquals(listOf(digestA, digestB), row.observedDigests)
        assertEquals(listOf(digestA, digestB), row.pinnedDigests)
    }

    @Test
    fun theShapesAVendorPublishesAreAllAccepted() {
        val colonUpperCase = digestA.chunked(2).joinToString(":").uppercase()
        val spaced = digestA.chunked(2).joinToString(" ")

        listOf(digestA, colonUpperCase, spaced, "  $digestA  ").forEach { raw ->
            val pasted = pastedDigestOf(raw, emptySet())
            assertTrue("rejected $raw", pasted.usable)
            assertEquals(digestA, pasted.normalized)
            assertEquals(64, pasted.length)
        }
    }

    @Test
    fun anEmptyFieldReportsThatNothingWasEnteredYet() {
        val pasted = pastedDigestOf("   ", emptySet())

        assertEquals(DigestProblem.EMPTY, pasted.problem)
        assertFalse(pasted.usable)
    }

    @Test
    fun aValueThatIsNotHexadecimalSaysSo() {
        val pasted = pastedDigestOf("z".repeat(64), emptySet())

        assertEquals(DigestProblem.NOT_HEXADECIMAL, pasted.problem)
    }

    @Test
    fun aTruncatedDigestReportsItsNormalizedLength() {
        // The operator pasted separators too; quoting the raw length would be
        // misleading about how far off the value is.
        val truncated = digestA.substring(0, 62).chunked(2).joinToString(":")

        val pasted = pastedDigestOf(truncated, emptySet())

        assertEquals(DigestProblem.WRONG_LENGTH, pasted.problem)
        assertEquals(62, pasted.length)
    }

    @Test
    fun anOverlongDigestIsRefused() {
        val pasted = pastedDigestOf(digestA + "ab", emptySet())

        assertEquals(DigestProblem.WRONG_LENGTH, pasted.problem)
    }

    @Test
    fun aCertificateThatIsAlreadyApprovedIsNotAddedTwice() {
        val pasted = pastedDigestOf(digestA.uppercase(), setOf(digestA))

        assertEquals(DigestProblem.ALREADY_PINNED, pasted.problem)
        assertFalse(pasted.usable)
    }

    @Test
    fun anAuditKeyCarriesThePackageAndTheVerdictAndNoDigest() {
        val row = managementIdentityRows(
            listOf(
                status(
                    packageName = "com.example.transport",
                    observed = setOf(digestA),
                    pinned = setOf(digestB),
                    verdict = SignerVerdict.MISMATCH,
                )
            )
        ).single()

        val key = managementAuditKeyOf(row)

        assertEquals("com.example.transport:MISMATCH", key)
        assertFalse(key.contains(digestA))
        assertFalse(key.contains(digestB))
    }

    @Test
    fun onlyRefusalsAreAuditedAndOnlyOnce() {
        val rows = managementIdentityRows(
            listOf(
                status(packageName = "com.example.refused", verdict = SignerVerdict.MISMATCH),
                status(packageName = "com.example.unproven", verdict = SignerVerdict.UNPINNED),
                status(packageName = "com.example.absent", installed = false),
                status(packageName = "com.example.proven", verdict = SignerVerdict.MATCH),
            )
        )

        val first = refusalsToAudit(rows, emptySet())
        assertEquals(listOf("com.example.refused"), first.map { it.packageName })

        val again = refusalsToAudit(rows, first.map { managementAuditKeyOf(it) }.toSet())
        assertTrue(again.isEmpty())
    }

    @Test
    fun aRefusalThatChangedVerdictIsAuditedAgain() {
        // A package that went from "no signer readable" to "signer does not
        // match" is a new fact about the device, not a repeat of the old one.
        val mismatch = managementIdentityRows(
            listOf(status(packageName = "com.example.transport", verdict = SignerVerdict.MISMATCH))
        )
        val unreadable = managementIdentityRows(
            listOf(
                status(
                    packageName = "com.example.transport",
                    verdict = SignerVerdict.UNKNOWN_SIGNER,
                )
            )
        )
        val recorded = setOf(managementAuditKeyOf(unreadable.single()))

        assertEquals(mismatch, refusalsToAudit(mismatch, recorded))
    }

    private fun status(
        packageName: String = "com.example.transport",
        installed: Boolean = true,
        observed: Set<String> = setOf(digestA),
        pinned: Set<String> = setOf(digestB),
        verdict: SignerVerdict = SignerVerdict.UNPINNED,
    ) = ManagementIdentityStatus(packageName, installed, observed, pinned, verdict)
}
