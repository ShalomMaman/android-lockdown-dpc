package com.example.lockdowndpc.ui

import com.example.lockdowndpc.policy.LockdownPackages
import com.example.lockdowndpc.policy.SystemAppClassifier
import com.example.lockdowndpc.policy.SystemAppClassifier.Category
import com.example.lockdowndpc.policy.SystemAppClassifier.PackageSnapshot
import com.example.lockdowndpc.policy.SystemAppClassifier.ProtectedContext
import com.example.lockdowndpc.policy.SystemAppClassifier.RiskAcceptanceStatus
import com.example.lockdowndpc.policy.SystemAppClassifier.RowState
import com.example.lockdowndpc.policy.SystemAppClassifier.Tier
import com.example.lockdowndpc.security.AppLabelSanitizer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Covers the pure inventory logic: search, filtering, ordering, and — the part
 * that actually decides what reaches the policy engine — which packages a save
 * writes to the guarded system-package store and to the allow/block set.
 */
class SystemAppInventoryTest {

    private val protectedContext = ProtectedContext(
        OWN,
        LockdownPackages.ESSENTIAL_SYSTEM,
        LockdownPackages.managementPackageNames(),
        "com.oem.keyboard",
        "com.google.android.webview",
    )

    private fun row(
        packageName: String,
        label: String = packageName,
        system: Boolean = false,
        updatedSystem: Boolean = false,
        installed: Boolean = true,
        hidden: Boolean = false,
        risk: RiskAcceptanceStatus = RiskAcceptanceStatus.NONE,
        effectivelyAllowed: Boolean = true,
        signerDigest: String = "aa11",
        version: String = "1.0 (1)",
    ): InventoryRow {
        val snapshot = PackageSnapshot(packageName, system, updatedSystem, installed, hidden)
        return InventoryRow(
            snapshot = snapshot,
            classification = SystemAppClassifier.classify(
                snapshot,
                protectedContext,
                SystemAppClassifier.CatalogContext.fromLockdownPackages(),
                effectivelyAllowed,
                risk,
            ),
            label = label,
            riskStatus = risk,
            signerDigest = signerDigest,
            version = version,
            selected = false,
        )
    }

    // --- Search -------------------------------------------------------------

    @Test
    fun `an empty query matches everything`() {
        assertTrue(matchesInventoryQuery("Signal", "org.thoughtcrime.securesms", ""))
        assertTrue(matchesInventoryQuery("Signal", "org.thoughtcrime.securesms", "   "))
    }

    @Test
    fun `a query matches either the label or the package name`() {
        assertTrue(matchesInventoryQuery("Signal", "org.thoughtcrime.securesms", "sig"))
        assertTrue(matchesInventoryQuery("Signal", "org.thoughtcrime.securesms", "thoughtcrime"))
        assertFalse(matchesInventoryQuery("Signal", "org.thoughtcrime.securesms", "telegram"))
    }

    @Test
    fun `a Hebrew label is searchable in Hebrew`() {
        assertTrue(matchesInventoryQuery("מצלמה", "com.oem.camera", "מצ"))
    }

    @Test
    fun `package matching folds case in the root locale`() {
        // A Turkish device folds `I` to a dotless `ı`. Using the display locale
        // here would stop `com.instagram.android` matching a typed `IN`.
        assertTrue(matchesInventoryQuery("Instagram", "com.instagram.android", "IN"))
        assertTrue(matchesInventoryQuery("Instagram", "com.instagram.android", "Instagram"))
    }

    // --- Filtering ----------------------------------------------------------

    @Test
    fun `the filter and the query compose`() {
        val rows = listOf(
            row("org.thoughtcrime.securesms", label = "Signal"),
            row("com.android.systemui", label = "System UI", system = true),
            row("com.instagram.android", label = "Instagram"),
        )

        assertEquals(3, filterInventory(rows, protectedContext, Category.ALL, "").size)
        assertEquals(
            listOf("com.android.systemui"),
            filterInventory(rows, protectedContext, Category.SYSTEM, "").map { it.packageName },
        )
        assertEquals(
            listOf("com.instagram.android"),
            filterInventory(rows, protectedContext, Category.SOCIAL, "insta").map { it.packageName },
        )
        assertTrue(filterInventory(rows, protectedContext, Category.SOCIAL, "signal").isEmpty())
    }

    @Test
    fun `a package hidden by policy is still listed`() {
        // PackageManager omits a DPC-hidden package from bulk queries, so this is
        // the one case where the screen that blocked an app could lose sight of it.
        val hidden = row("com.instagram.android", label = "Instagram", hidden = true)

        assertTrue(hidden.snapshot.hiddenByPolicy)
        assertEquals(
            listOf("com.instagram.android"),
            filterInventory(listOf(hidden), protectedContext, Category.ALL, "")
                .map { it.packageName },
        )
    }

    @Test
    fun `an uninstalled but previously managed package keeps its saved row`() {
        val gone = row("com.example.removed", label = "Removed app", installed = false)

        assertFalse(gone.snapshot.installed)
        assertEquals(1, filterInventory(listOf(gone), protectedContext, Category.ALL, "").size)
    }

    // --- Ordering -----------------------------------------------------------

    @Test
    fun `actionable rows sort above ruled rows and the protected core`() {
        val rows = listOf(
            row("com.android.systemui", label = "AAA System UI", system = true),
            row("com.android.chrome", label = "AAB Chrome", system = true),
            row("com.oem.weatherwidget", label = "AAC Weather", system = true),
            row("com.google.android.apps.photos", label = "AAD Photos", system = true),
            row("org.thoughtcrime.securesms", label = "AAE Signal"),
        )

        assertEquals(
            listOf(
                Tier.ORDINARY,
                Tier.KNOWN_MANAGEABLE,
                Tier.UNCLASSIFIED_OEM,
                Tier.POLICY_RULED,
                Tier.PROTECTED_CORE,
            ),
            sortInventory(rows).map { it.classification.tier },
        )
    }

    @Test
    fun `rows in the same tier sort by label`() {
        val rows = listOf(
            row("com.b.app", label = "Zebra"),
            row("com.a.app", label = "Apple"),
        )

        assertEquals(listOf("Apple", "Zebra"), sortInventory(rows).map { it.label })
    }

    // --- Pending row state --------------------------------------------------

    @Test
    fun `a tick means blocked in block mode and allowed in allow mode`() {
        val app = row("org.thoughtcrime.securesms")

        assertEquals(RowState.BLOCKED, pendingRowState(app, selected = true, allowSelected = false))
        assertEquals(RowState.ALLOWED, pendingRowState(app, selected = false, allowSelected = false))
        assertEquals(RowState.ALLOWED, pendingRowState(app, selected = true, allowSelected = true))
        assertEquals(RowState.BLOCKED, pendingRowState(app, selected = false, allowSelected = true))
    }

    @Test
    fun `a protected row ignores the pending selection entirely`() {
        val systemUi = row("com.android.systemui", system = true)

        assertEquals(RowState.PROTECTED, pendingRowState(systemUi, true, allowSelected = true))
        assertEquals(RowState.PROTECTED, pendingRowState(systemUi, false, allowSelected = false))
    }

    @Test
    fun `a catalogue-ruled row keeps the state the catalogue dictates`() {
        val chrome = row("com.android.chrome", system = true)

        assertEquals(RowState.BLOCKED, pendingRowState(chrome, true, allowSelected = true))
        assertEquals(RowState.BLOCKED, pendingRowState(chrome, false, allowSelected = true))
    }

    // --- What a save actually writes ----------------------------------------

    @Test
    fun `only opted-in manageable system packages reach the guarded store`() {
        val rows = listOf(
            row("com.google.android.apps.photos", system = true),
            row("com.oem.weatherwidget", system = true, risk = RiskAcceptanceStatus.FRESH),
            row("com.oem.untouched", system = true),
            row("org.thoughtcrime.securesms"),
        )
        val optedIn = setOf(
            "com.google.android.apps.photos",
            "com.oem.weatherwidget",
            "org.thoughtcrime.securesms",
        )

        assertEquals(
            setOf("com.google.android.apps.photos", "com.oem.weatherwidget"),
            adminSelectedSystemPackages(rows, optedIn),
        )
    }

    @Test
    fun `an OEM component with no fresh acceptance never reaches the guarded store`() {
        val rows = listOf(
            row("com.oem.weatherwidget", system = true, risk = RiskAcceptanceStatus.NONE),
            row("com.oem.gallery", system = true, risk = RiskAcceptanceStatus.DRIFTED),
        )
        val optedIn = setOf("com.oem.weatherwidget", "com.oem.gallery")

        // Both were opted in at some point; neither may be written now, because a
        // missing or drifted acceptance is exactly the fail-closed case.
        assertEquals(emptySet<String>(), adminSelectedSystemPackages(rows, optedIn))
    }

    @Test
    fun `a package nobody touched is left out of the system store`() {
        val rows = listOf(row("com.google.android.apps.photos", system = true))

        assertEquals(emptySet<String>(), adminSelectedSystemPackages(rows, emptySet()))
    }

    @Test
    fun `a system tick is persisted only when the package is also under management`() {
        val rows = listOf(
            row("com.google.android.apps.photos", system = true),
            row("com.oem.weatherwidget", system = true, risk = RiskAcceptanceStatus.FRESH),
            row("org.thoughtcrime.securesms"),
        )
        val ticked = setOf(
            "com.google.android.apps.photos",
            "com.oem.weatherwidget",
            "org.thoughtcrime.securesms",
        )
        val adminSelected = setOf("com.google.android.apps.photos")

        assertEquals(
            setOf("com.google.android.apps.photos", "org.thoughtcrime.securesms"),
            persistedSelection(rows, ticked, adminSelected),
        )
    }

    @Test
    fun `a tick on a row that is not toggleable is never persisted`() {
        val rows = listOf(
            row("com.android.systemui", system = true),
            row("com.android.chrome", system = true),
            row(OWN),
        )
        val ticked = setOf("com.android.systemui", "com.android.chrome", OWN)

        assertEquals(emptySet<String>(), persistedSelection(rows, ticked, emptySet()))
    }

    @Test
    fun `the managed set stays free of system packages`() {
        // LockdownPolicyController puts every managed package under the allow/block
        // rules with no second gate, so a system package here would be blockable
        // without ever passing the guarded store. In "allow only what I select"
        // that would hide every system package an operator merely scrolled past.
        val rows = listOf(
            row("org.thoughtcrime.securesms"),
            row("com.google.android.apps.photos", system = true),
            row("com.oem.gallery", system = true, updatedSystem = true),
            row("com.android.chrome", system = true),
            row(OWN),
        )

        assertEquals(setOf("org.thoughtcrime.securesms"), managedPackagesToPersist(rows))
    }

    @Test
    fun `an updated system app is treated as a system package on save`() {
        val updated = row("com.oem.gallery", system = false, updatedSystem = true)

        assertTrue(updated.snapshot.anySystem())
        assertFalse(managedPackagesToPersist(listOf(updated)).contains("com.oem.gallery"))
    }

    // --- Untrusted label handling -------------------------------------------

    @Test
    fun `a label carrying bidi controls is stripped before it is stored or rendered`() {
        // An app whose label embeds a right-to-left override can otherwise redraw
        // the trusted package name rendered beside it.
        val hostile = "Calculator‮moc.live‬"
        val sanitized = AppLabelSanitizer.sanitize(hostile)!!

        assertFalse(sanitized.any { it in '‪'..'‮' })
        assertFalse(sanitized.any { it in '⁦'..'⁩' })
        assertEquals("Calculatormoc.live", sanitized)
    }

    @Test
    fun `a sanitized label is still isolated at render time`() {
        // Stripping the label's own controls is only half of it: Device Guard adds
        // its own balanced isolate so a Hebrew or Arabic label cannot reorder the
        // Latin package name on the line below.
        val label = AppLabelSanitizer.sanitize("מצלמה")!!
        val rendered = label.bidiIsolated()

        assertEquals(FIRST_STRONG_ISOLATE, rendered.first())
        assertEquals(POP_ISOLATE, rendered.last())
        assertEquals(label, rendered.trim(*ISOLATE_MARKS))
    }

    @Test
    fun `a package name is isolated left to right`() {
        val rendered = "com.oem.weatherwidget".ltrIsolated()

        assertEquals(LTR_ISOLATE, rendered.first())
        assertEquals(POP_ISOLATE, rendered.last())
        assertEquals("com.oem.weatherwidget", rendered.trim(*ISOLATE_MARKS))
    }

    // --- Row model ----------------------------------------------------------

    @Test
    fun `only an unreviewed OEM component asks to be reviewed`() {
        assertTrue(row("com.oem.weatherwidget", system = true).needsRiskAcceptance)
        assertFalse(
            row("com.oem.weatherwidget", system = true, risk = RiskAcceptanceStatus.FRESH)
                .needsRiskAcceptance,
        )
        assertTrue(
            row("com.oem.weatherwidget", system = true, risk = RiskAcceptanceStatus.DRIFTED)
                .needsRiskAcceptance,
        )
        assertFalse(row("com.android.systemui", system = true).needsRiskAcceptance)
        assertFalse(row("org.thoughtcrime.securesms").needsRiskAcceptance)
    }

    @Test
    fun `only a system row in a selectable tier is written to the system store`() {
        assertTrue(row("com.google.android.apps.photos", system = true).isAdminSelectableSystem)
        assertTrue(row("com.oem.weatherwidget", system = true).isAdminSelectableSystem)
        assertFalse(row("com.android.systemui", system = true).isAdminSelectableSystem)
        assertFalse(row("com.android.chrome", system = true).isAdminSelectableSystem)
        assertFalse(row("org.thoughtcrime.securesms").isAdminSelectableSystem)
    }

    private companion object {
        const val OWN = "com.example.lockdowndpc"
    }
}
