package com.example.lockdowndpc.policy

import android.content.Context
import android.os.Build
import com.example.lockdowndpc.kiosk.KioskController
import com.example.lockdowndpc.remote.Generation
import com.example.lockdowndpc.remote.JsonObject
import com.example.lockdowndpc.remote.ReleaseLedger
import com.example.lockdowndpc.remote.RemoteProjection
import com.example.lockdowndpc.remote.asObject
import com.example.lockdowndpc.remote.items
import com.example.lockdowndpc.remote.number
import com.example.lockdowndpc.remote.obj
import com.example.lockdowndpc.remote.refuse
import com.example.lockdowndpc.remote.text
import com.example.lockdowndpc.security.DurablePreferences
import com.example.lockdowndpc.ui.AppLocales
import com.example.lockdowndpc.ui.LanguageChoice
import java.util.function.BooleanSupplier
import java.util.function.Predicate

internal class RemotePolicyProjection(
    private val context: Context,
    private val sdk: Int = Build.VERSION.SDK_INT
) : RemoteProjection {
    var lastResult: LockdownPolicyController.PolicyResult? = null
        private set

    private class Plan(
        val mode: AllowedAppsStore.ProtectionMode,
        val selection: Set<String>,
        val acceptances: List<SystemAppRiskAcceptance>,
        val playCompatibility: Boolean,
        val controls: Map<String, Boolean>,
        val pins: Map<String, Set<String>>,
        val filter: HomeFilterPolicy.Settings,
        val locale: LanguageChoice
    ) {
        val systemPackages: Set<String> get() = acceptances.map { it.packageName() }.toSet()
    }

    override fun validate(policy: JsonObject) {
        plan(policy)
    }

    /**
     * Builds and validates every compound value before any store is written.
     * A policy this device could store but never verify is refused here, while
     * the previous generation is still the journal's target.
     */
    private fun plan(policy: JsonObject): Plan {
        val apps = policy.obj("apps")
        val acceptances = (apps["systemSelection"] as List<*>?).orEmpty().map {
            val record = it.asObject()
            SystemAppRiskAcceptance(record.text("package"), record.text("signerSha256"),
                record.number("versionCode").toString(), "", "", 0)
        }
        val systemPackages = acceptances.map { it.packageName() }.toSet()
        if (AllowedAppsStore.guardedSystemSelection(systemPackages) != systemPackages) {
            refuse("doc-field-invalid", "/policy/apps/systemSelection")
        }
        val filter = filterSettings(policy["homeFilter"]?.asObject())
        if (filter.enabled() && BuiltInBlockExemptions.isBuiltInBlocked(filter.config().vpnPackage())) {
            // The same rule as the local console: a blocked package never becomes the VPN.
            refuse("doc-field-invalid", "/policy/homeFilter/vpnPackage")
        }
        if (filter.enabled() && filter.config().routing() == null) {
            // The VPN read-back needs the routing settings. Without them no pass could verify.
            refuse("doc-field-invalid", "/policy/homeFilter/routing")
        }
        // A kiosk needs a local way out, and the remote console has none yet.
        // Until it does, a fleet policy cannot contain a device in one.
        if ((policy["kiosk"]?.asObject()?.get("mode") ?: "OFF") != "OFF") {
            refuse("doc-field-invalid", "/policy/kiosk/mode")
        }
        return Plan(
            mode = when (apps.text("mode")) {
                "ALLOW_SELECTED" -> AllowedAppsStore.ProtectionMode.ALLOW_SELECTED
                "BLOCK_SELECTED" -> AllowedAppsStore.ProtectionMode.BLOCK_SELECTED
                else -> refuse("doc-field-invalid", "/policy/apps/mode")
            },
            selection = apps.items("allowed").map { it as String }.toSet(),
            acceptances = acceptances,
            playCompatibility = apps["playCompatibility"] == true,
            controls = policy["systemControls"]?.asObject().orEmpty().mapValues { it.value as Boolean },
            pins = policy["managementPins"]?.asObject().orEmpty().mapValues { (_, values) ->
                (values as List<*>).map { it as String }.toSet()
            },
            filter = filter,
            locale = when (policy["locale"]) {
                null -> LanguageChoice.SYSTEM
                "en" -> languageOnThisRelease(LanguageChoice.ENGLISH)
                "he", "iw" -> languageOnThisRelease(LanguageChoice.HEBREW)
                else -> refuse("doc-field-invalid", "/policy/locale")
            }
        )
    }

    override fun project(policy: JsonObject, target: Generation): Boolean {
        lastResult = null
        val plan = plan(policy)
        AdminAuthority.CommittedPolicy.forProjection(context).use { authority ->
            // The authority names the journal's own generation. Anything else is not projected.
            if (authority.generation() != target.sha256) return false
            return AuthorizedPolicyWriter.projectSelection(context, authority, plan.mode, plan.selection) &&
                AuthorizedPolicyWriter.projectSystemSelection(context, authority, plan.systemPackages) &&
                plan.acceptances.all { AuthorizedPolicyWriter.projectSystemAcceptance(context, authority, it) } &&
                AuthorizedPolicyWriter.projectPlayCompatibility(context, authority, plan.playCompatibility) &&
                AuthorizedPolicyWriter.projectControls(context, authority, plan.controls) &&
                AuthorizedPolicyWriter.projectFilter(context, authority, plan.filter) &&
                AuthorizedPolicyWriter.projectManagementPins(context, authority, plan.pins) &&
                KioskController.projectRemote(context, authority) &&
                projectLocale(authority, plan.locale)
        }
    }

    private fun projectLocale(authority: AdminAuthority, locale: LanguageChoice): Boolean {
        if (!AdminAuthority.CommittedPolicy.permits(context, authority)) return false
        val prefs = context.getSharedPreferences(LOCALE_PREFS, Context.MODE_PRIVATE)
        return DurablePreferences.commit(prefs, prefs.edit().putString(LOCALE, locale.name), LOCALE)
    }

    override fun apply(target: Generation, stillCurrent: () -> Boolean, releases: ReleaseLedger): Boolean {
        if (!stillCurrent()) return false
        val localeVerified = try {
            applyLocale()
        } catch (_: RuntimeException) {
            false
        }
        AdminAuthority.CommittedPolicy.forProjection(context).use { authority ->
            if (authority.generation() != target.sha256) return false
            val result = LockdownPolicyController.applyRemoteProjection(
                context, authority, BooleanSupplier(stillCurrent), localeVerified,
                Predicate { packages -> releases.record(packages) })
            lastResult = result
            return result.applied()
        }
    }

    override fun revoke(packages: Set<String>): Set<String> =
        LockdownPolicyController.revokeRemoteReleases(context, packages)

    /**
     * Android 13 and later keep the application language in the platform, where
     * a pass can read it back. Earlier releases keep it only inside AppCompat,
     * which reports what was asked of it and not what is on screen. A language
     * there could be stored and never verified, so the policy is refused instead.
     */
    private fun languageOnThisRelease(choice: LanguageChoice): LanguageChoice {
        if (sdk < Build.VERSION_CODES.TIRAMISU) refuse("doc-field-invalid", "/policy/locale")
        return choice
    }

    /** Before Android 13 the only choice a policy can carry is the device default, which needs no call. */
    private fun applyLocale(): Boolean {
        val prefs = context.getSharedPreferences(LOCALE_PREFS, Context.MODE_PRIVATE)
        val locale = LanguageChoice.valueOf(requireNotNull(prefs.getString(LOCALE, null)))
        if (sdk < Build.VERSION_CODES.TIRAMISU) return locale == LanguageChoice.SYSTEM
        return AppLocales.applyPolicyChoice(context, locale)
    }

    private fun filterSettings(filter: JsonObject?): HomeFilterPolicy.Settings {
        if (filter?.get("enabled") != true) return HomeFilterPolicy.Settings.OFF
        val routing = filter["routing"]?.asObject()?.let {
            HomeFilterPolicy.Routing(it.text("tailnetId"), it.text("loginUrl"), it.text("exitNodeId"), it.text("organizationName"))
        }
        val canary = filter["canary"]?.asObject()?.let { HomeFilterPolicy.Canary(it.text("url"), it.text("expectedBody")) }
        val config = HomeFilterPolicy.Config(filter.text("vpnPackage"), filter.text("pacUrl"),
            filter["vpnSignerSha256"] as String? ?: "", routing, canary)
        val certificate = filter["caCertificate"] as String?
        require(certificate == null || java.util.Base64.getDecoder().decode(certificate).size <= HomeFilterCertificate.MAX_BYTES)
        return HomeFilterPolicy.Settings(config, true, certificate, false)
    }

    private companion object {
        const val LOCALE_PREFS = "remote_policy_locale"
        const val LOCALE = "choice"
    }
}
