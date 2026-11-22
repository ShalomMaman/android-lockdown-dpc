package com.example.lockdowndpc.policy

import android.content.Context
import com.example.lockdowndpc.kiosk.KioskConfig
import com.example.lockdowndpc.kiosk.KioskController
import com.example.lockdowndpc.remote.Generation
import com.example.lockdowndpc.remote.JsonObject
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

internal class RemotePolicyProjection(private val context: Context) : RemoteProjection {
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
        val kiosk: KioskConfig,
        val locale: LanguageChoice
    ) {
        val systemPackages: Set<String> get() = acceptances.map { it.packageName() }.toSet()
    }

    override fun validate(policy: JsonObject) {
        plan(policy)
    }

    /** Builds and validates every compound value before any store is written. */
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
        return Plan(
            mode = AllowedAppsStore.ProtectionMode.valueOf(apps.text("mode")),
            selection = apps.items("allowed").map { it as String }.toSet(),
            acceptances = acceptances,
            playCompatibility = apps["playCompatibility"] == true,
            controls = policy["systemControls"]?.asObject().orEmpty().mapValues { it.value as Boolean },
            pins = policy["managementPins"]?.asObject().orEmpty().mapValues { (_, values) ->
                (values as List<*>).map { it as String }.toSet()
            },
            filter = filter,
            kiosk = policy["kiosk"]?.asObject()?.let {
                when (it.text("mode")) {
                    "SINGLE_APP" -> KioskConfig.singleApp(it.text("targetPackage"))
                    "SINGLE_SITE" -> KioskConfig.singleSite(it.text("siteUrl"))
                    else -> KioskConfig.OFF
                }
            } ?: KioskConfig.OFF,
            locale = when (policy["locale"]) {
                "en" -> LanguageChoice.ENGLISH
                "he", "iw" -> LanguageChoice.HEBREW
                else -> LanguageChoice.SYSTEM
            }
        )
    }

    override fun project(policy: JsonObject, target: Generation): Boolean {
        lastResult = null
        val plan = plan(policy)
        AdminAuthority.CommittedPolicy.forProjection(context, target.sha256).use { authority ->
            return AuthorizedPolicyWriter.projectSelection(context, authority, plan.mode, plan.selection) &&
                AuthorizedPolicyWriter.projectSystemSelection(context, authority, plan.systemPackages) &&
                plan.acceptances.all { AuthorizedPolicyWriter.projectSystemAcceptance(context, authority, it) } &&
                AuthorizedPolicyWriter.projectPlayCompatibility(context, authority, plan.playCompatibility) &&
                AuthorizedPolicyWriter.projectControls(context, authority, plan.controls) &&
                AuthorizedPolicyWriter.projectFilter(context, authority, plan.filter) &&
                AuthorizedPolicyWriter.projectManagementPins(context, authority, plan.pins) &&
                KioskController.projectRemote(context, authority, plan.kiosk) &&
                projectLocale(authority, plan.locale)
        }
    }

    private fun projectLocale(authority: AdminAuthority, locale: LanguageChoice): Boolean {
        if (!AdminAuthority.CommittedPolicy.permits(context, authority)) return false
        val prefs = context.getSharedPreferences(LOCALE_PREFS, Context.MODE_PRIVATE)
        return DurablePreferences.commit(prefs, prefs.edit().putString(LOCALE, locale.name), LOCALE)
    }

    override fun apply(target: Generation, stillCurrent: () -> Boolean): Boolean {
        if (!stillCurrent()) return false
        val prefs = context.getSharedPreferences(LOCALE_PREFS, Context.MODE_PRIVATE)
        val locale = LanguageChoice.valueOf(requireNotNull(prefs.getString(LOCALE, null)))
        val localeVerified = try {
            AppLocales.applyPolicyChoice(context, locale)
        } catch (_: RuntimeException) {
            false
        }
        AdminAuthority.CommittedPolicy.forProjection(context, target.sha256).use { authority ->
            val result = LockdownPolicyController.applyRemoteProjection(
                context, authority, BooleanSupplier(stillCurrent), localeVerified)
            lastResult = result
            return result.applied()
        }
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
