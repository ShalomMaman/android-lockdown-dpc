package com.example.lockdowndpc.ui

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import android.provider.Settings
import android.webkit.WebView
import com.example.lockdowndpc.admin.LockdownAdminReceiver
import com.example.lockdowndpc.policy.AllowedAppsStore
import com.example.lockdowndpc.policy.LockdownPackages
import com.example.lockdowndpc.policy.SystemAppClassifier
import com.example.lockdowndpc.policy.SystemAppClassifier.PackageSnapshot
import com.example.lockdowndpc.policy.SystemAppClassifier.ProtectedContext
import com.example.lockdowndpc.policy.SystemAppClassifier.RiskAcceptanceStatus
import com.example.lockdowndpc.security.AppLabelSanitizer
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.util.Locale

/**
 * Builds the inventory from the device. Everything Android-specific lives here so
 * `SystemAppInventory.kt` and `policy/SystemAppClassifier.java` can stay pure and
 * unit-testable.
 */
internal data class LoadedInventory(
    val rows: List<InventoryRow>,
    val protectedContext: ProtectedContext,
    val ticked: Set<String>,
    val optedInSystem: Set<String>,
    val firmwareBuild: String,
)

private val INVENTORY_FLAGS: Long =
    (PackageManager.MATCH_UNINSTALLED_PACKAGES or PackageManager.MATCH_DISABLED_COMPONENTS).toLong()

internal fun loadInventory(context: Context, allowSelected: Boolean): LoadedInventory {
    val pm = context.packageManager
    val protectedContext = readProtectedContext(context)
    val catalog = SystemAppClassifier.CatalogContext.fromLockdownPackages()

    val allowed = AllowedAppsStore.getAllowedPackages(context)
    val configured = AllowedAppsStore.isAllowlistConfigured(context)
    val managed = AllowedAppsStore.getManagedPackages(context)
    val optedInSystem = AllowedAppsStore.getAdminSelectedSystemPackages(context)

    // Packages this DPC has hidden are omitted from bulk queries, so the visible
    // inventory is the union of what PackageManager reports and every package we
    // have persisted a reason to remember. Without the second half a blocked app
    // vanishes from the screen that blocked it.
    val visibleNow = LinkedHashMap<String, ApplicationInfo>()
    for (info in installedApplications(pm)) {
        if (info.flags and ApplicationInfo.FLAG_INSTALLED != 0) {
            visibleNow[info.packageName] = info
        }
    }

    val candidates = LinkedHashSet(visibleNow.keys)
    candidates += managed
    candidates += optedInSystem
    candidates += LockdownPackages.ALWAYS_BLOCKED
    candidates += LockdownPackages.KNOWN_BROWSER_AND_SOCIAL
    candidates += LockdownPackages.KIOSK_ESCAPE_SURFACES
    candidates += LockdownPackages.managementPackageNames()
    candidates += context.packageName

    val hiddenProbe = hiddenProbe(context)
    val rows = ArrayList<InventoryRow>(candidates.size)
    val ticked = LinkedHashSet<String>()

    for (packageName in candidates) {
        val fromBulkQuery = visibleNow[packageName]
        val info = fromBulkQuery ?: applicationInfo(pm, packageName)
        val installed = info != null && info.flags and ApplicationInfo.FLAG_INSTALLED != 0
        val persisted = packageName in managed || packageName in optedInSystem
        // A catalogue package that was never on this device is noise, not
        // inventory. One we have managed before stays listed even if it was
        // uninstalled, so its saved decision remains visible.
        if (!installed && !persisted) {
            continue
        }

        val system = info != null && info.flags and ApplicationInfo.FLAG_SYSTEM != 0
        val updatedSystem =
            info != null && info.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
        // Absence from the bulk query while a targeted lookup still finds the
        // package installed is the documented signature of a DPC-hidden package,
        // and it is the only signal available when we are not Device Owner yet.
        val hidden = hiddenProbe?.invoke(packageName) ?: (installed && fromBulkQuery == null)

        val snapshot = PackageSnapshot(packageName, system, updatedSystem, installed, hidden)

        val label = AppLabelSanitizer.sanitize(info?.loadLabel(pm)?.toString())
            ?.takeIf { it.isNotBlank() }
            ?: AllowedAppsStore.getRememberedLabel(context, packageName)
        AllowedAppsStore.rememberPackageLabel(context, packageName, label)

        val signerDigest = signerDigestOf(pm, packageName)
        val version = versionOf(pm, packageName)
        val riskStatus = SystemAppClassifier.riskStatusOf(
            AllowedAppsStore.getSystemRiskAcceptance(context, packageName),
            signerDigest,
            version,
        )

        // Mirrors the shipped picker: before anything has been saved, "block what
        // I select" starts with nothing selected and "allow only what I select"
        // starts with everything selected, so neither default silently changes
        // what is running on the device.
        val isTicked = if (configured) packageName in allowed else allowSelected
        val effectivelyAllowed = if (allowSelected) isTicked else !isTicked

        val classification = SystemAppClassifier.classify(
            snapshot,
            protectedContext,
            catalog,
            effectivelyAllowed,
            riskStatus,
        )
        if (isTicked && classification.blockable) {
            ticked += packageName
        }
        rows += InventoryRow(
            snapshot = snapshot,
            classification = classification,
            label = label,
            riskStatus = riskStatus,
            signerDigest = signerDigest,
            version = version,
            selected = isTicked,
        )
    }

    return LoadedInventory(
        rows = sortInventory(rows),
        protectedContext = protectedContext,
        ticked = ticked,
        optedInSystem = optedInSystem,
        firmwareBuild = Build.FINGERPRINT ?: "",
    )
}

/**
 * The packages that are protected on this particular device.
 *
 * The active keyboard and the active WebView provider are read from the running
 * system rather than from a catalogue: an OEM keyboard that is absent from
 * `ESSENTIAL_SYSTEM` still must not be blockable, because the device would be
 * left with no way to type and no way to fix it.
 */
internal fun readProtectedContext(context: Context): ProtectedContext = ProtectedContext(
    context.packageName,
    LockdownPackages.ESSENTIAL_SYSTEM,
    LockdownPackages.managementPackageNames(),
    activeInputMethodPackage(context),
    activeWebViewProviderPackage(),
)

/** `Settings.Secure.DEFAULT_INPUT_METHOD` holds a flattened ComponentName. */
private fun activeInputMethodPackage(context: Context): String = try {
    val flattened = Settings.Secure.getString(
        context.contentResolver,
        Settings.Secure.DEFAULT_INPUT_METHOD,
    )
    flattened?.let { ComponentName.unflattenFromString(it)?.packageName }.orEmpty()
} catch (ignored: RuntimeException) {
    ""
}

private fun activeWebViewProviderPackage(): String = try {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
        WebView.getCurrentWebViewPackage()?.packageName.orEmpty()
    } else {
        ""
    }
} catch (ignored: RuntimeException) {
    ""
}

/**
 * A probe for "is this package hidden by us", or `null` when Device Owner is not
 * established and the question cannot be asked authoritatively. Callers fall back
 * to the bulk-query-absence signal rather than guessing "not hidden".
 */
private fun hiddenProbe(context: Context): ((String) -> Boolean)? {
    val dpm = context.getSystemService(DevicePolicyManager::class.java) ?: return null
    if (!dpm.isDeviceOwnerApp(context.packageName)) return null
    val admin = LockdownAdminReceiver.componentName(context)
    return { packageName ->
        try {
            dpm.isApplicationHidden(admin, packageName)
        } catch (ignored: RuntimeException) {
            false
        }
    }
}

/**
 * Lower-case hex SHA-256 of the installed signer, or empty when the platform
 * reports none. Deliberately mirrors `LockdownPolicyController`'s digest
 * handling so a digest recorded in a risk acceptance is comparable with the one
 * the policy engine would compute.
 */
internal fun signerDigestOf(pm: PackageManager, packageName: String): String = try {
    val signatures: Array<Signature>? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        val info = packageInfo(pm, packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        info.signingInfo?.let {
            if (it.hasMultipleSigners()) it.apkContentsSigners else it.signingCertificateHistory
        }
    } else {
        @Suppress("DEPRECATION")
        packageInfo(pm, packageName, PackageManager.GET_SIGNATURES).signatures
    }
    val first = signatures?.firstOrNull()
    if (first == null) {
        ""
    } else {
        val sha256 = MessageDigest.getInstance("SHA-256")
        sha256.digest(first.toByteArray()).joinToString("") { "%02x".format(Locale.ROOT, it) }
    }
} catch (ignored: PackageManager.NameNotFoundException) {
    ""
} catch (ignored: NoSuchAlgorithmException) {
    ""
} catch (ignored: RuntimeException) {
    ""
}

/** `versionName (versionCode)`, stable enough to detect an OEM update in place. */
internal fun versionOf(pm: PackageManager, packageName: String): String = try {
    val info = packageInfo(pm, packageName, 0)
    val code = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        info.longVersionCode
    } else {
        @Suppress("DEPRECATION")
        info.versionCode.toLong()
    }
    "${info.versionName.orEmpty()} ($code)"
} catch (ignored: PackageManager.NameNotFoundException) {
    ""
} catch (ignored: RuntimeException) {
    ""
}

/**
 * The machine-readable state recorded alongside a risk acceptance. Stable tokens
 * rather than display text: this is an audit record that has to stay comparable
 * across releases and display languages.
 */
internal fun priorStateToken(snapshot: PackageSnapshot): String = buildString {
    append(if (snapshot.installed) "installed" else "not-installed")
    append(',')
    append(if (snapshot.hiddenByPolicy) "hidden" else "visible")
}

private fun packageInfo(pm: PackageManager, packageName: String, flags: Int): PackageInfo =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags.toLong()))
    } else {
        @Suppress("DEPRECATION")
        pm.getPackageInfo(packageName, flags)
    }

private fun applicationInfo(pm: PackageManager, packageName: String): ApplicationInfo? = try {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        pm.getApplicationInfo(
            packageName,
            PackageManager.ApplicationInfoFlags.of(INVENTORY_FLAGS),
        )
    } else {
        @Suppress("DEPRECATION")
        pm.getApplicationInfo(packageName, INVENTORY_FLAGS.toInt())
    }
} catch (ignored: PackageManager.NameNotFoundException) {
    null
}

private fun installedApplications(pm: PackageManager): List<ApplicationInfo> =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(INVENTORY_FLAGS))
    } else {
        @Suppress("DEPRECATION")
        pm.getInstalledApplications(INVENTORY_FLAGS.toInt())
    }

/** Marker for a risk acceptance the operator confirmed in the dialog. */
internal fun riskAcceptanceFor(
    row: InventoryRow,
    firmwareBuild: String,
    acceptedAtMillis: Long,
): com.example.lockdowndpc.policy.SystemAppRiskAcceptance =
    com.example.lockdowndpc.policy.SystemAppRiskAcceptance(
        row.packageName,
        row.signerDigest,
        row.version,
        priorStateToken(row.snapshot),
        firmwareBuild,
        acceptedAtMillis,
    )

/**
 * Re-classifies a row once its risk acceptance has been recorded, so it becomes
 * manageable in the same session without reloading the whole inventory.
 *
 * It runs the row through the same `classify` call as the initial load rather
 * than flipping `blockable` by hand: the protected checks come first there, so a
 * package that is protected on this device stays protected no matter what an
 * operator confirmed in a dialog.
 */
internal fun InventoryRow.withAcceptedRisk(
    protectedContext: ProtectedContext,
    effectivelyAllowed: Boolean,
): InventoryRow = copy(
    riskStatus = RiskAcceptanceStatus.FRESH,
    classification = SystemAppClassifier.classify(
        snapshot,
        protectedContext,
        SystemAppClassifier.CatalogContext.fromLockdownPackages(),
        effectivelyAllowed,
        RiskAcceptanceStatus.FRESH,
    ),
)
