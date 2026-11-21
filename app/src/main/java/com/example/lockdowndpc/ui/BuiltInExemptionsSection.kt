package com.example.lockdowndpc.ui

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.example.lockdowndpc.R
import com.example.lockdowndpc.policy.BuiltInBlockExemptions
import com.example.lockdowndpc.policy.BuiltInBlockExemptionsStore
import com.example.lockdowndpc.policy.ChromeFilterExemption
import com.example.lockdowndpc.policy.ExemptionObserver
import com.example.lockdowndpc.policy.PackageIdentity
import com.example.lockdowndpc.security.AppLabelSanitizer

/** One installed package from an exemptable catalogue, with its display label. */
internal data class ExemptionCandidate(val packageName: String, val label: String)

/** A pending loosening change, held until the administrator confirms it. */
internal sealed interface PendingExemption {
    data object Chrome : PendingExemption
    data class Social(val candidate: ExemptionCandidate) : PendingExemption
}

/**
 * Everything the section shows, read once per revision (every action and every
 * resume). Android states are observed live here; only the reason for the
 * last pass's Chrome decision comes from storage.
 */
internal data class ExemptionsView(
    val settings: BuiltInBlockExemptions.Settings,
    /** The last pass's Chrome decision, only when it was taken for the current decision. */
    val chromeDecision: ChromeFilterExemption.Decision?,
    val chromeObserved: BuiltInBlockExemptions.Observed,
    val social: List<ExemptionCandidate>,
    val socialObserved: Map<String, BuiltInBlockExemptions.Observed>,
    /** Approved social packages whose installed signer differs from the pin, read live. */
    val socialSignerMismatch: Set<String>,
    /** Approved, installed social packages whose signer could not be read live. */
    val socialSignerUnreadable: Set<String>,
    /** The stored approval record cannot be read; only "clear approvals" may change it. */
    val recordUnreadable: Boolean,
) {
    val chromeInstalled: Boolean
        get() = chromeObserved != BuiltInBlockExemptions.Observed.NOT_INSTALLED
}

/**
 * Installed packages from [catalogue], including ones this device has hidden:
 * hidden packages still report `FLAG_INSTALLED` with `MATCH_UNINSTALLED_PACKAGES`.
 */
internal fun installedExemptionCandidates(
    context: Context,
    catalogue: Set<String>,
): List<ExemptionCandidate> {
    val pm = context.packageManager
    return catalogue.mapNotNull { packageName ->
        try {
            val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getApplicationInfo(
                    packageName,
                    PackageManager.ApplicationInfoFlags.of(
                        PackageManager.MATCH_UNINSTALLED_PACKAGES.toLong()
                    ),
                )
            } else {
                @Suppress("DEPRECATION")
                pm.getApplicationInfo(packageName, PackageManager.MATCH_UNINSTALLED_PACKAGES)
            }
            if (info.flags and ApplicationInfo.FLAG_INSTALLED == 0) {
                null
            } else {
                val label = AppLabelSanitizer.sanitize(info.loadLabel(pm).toString())
                ExemptionCandidate(packageName, label.ifBlank { packageName })
            }
        } catch (_: PackageManager.NameNotFoundException) {
            null
        }
    }
}

internal fun loadExemptionsView(context: Context): ExemptionsView {
    val settings = BuiltInBlockExemptionsStore.readForEdit(context)
    val social = socialRows(context, settings)
    val observed = social.associate { it.packageName to ExemptionObserver.observe(context, it.packageName) }
    val installedApprovals = settings.socialPins().keys.filter { packageName ->
        observed[packageName] != BuiltInBlockExemptions.Observed.NOT_INSTALLED
    }
    val signers = installedApprovals.associateWith { packageName ->
        PackageIdentity.currentSignerSha256IncludingHidden(context.packageManager, packageName)
    }
    val unreadable = signers.filterValues { it.isEmpty() }.keys
    val mismatch = signers.filter { (packageName, signer) ->
        signer.isNotEmpty() && !BuiltInBlockExemptions.socialVisible(packageName, settings, signer)
    }.keys
    return ExemptionsView(
        settings = settings,
        chromeDecision = BuiltInBlockExemptionsStore.readback(context)
            ?.takeIf { it.describes(settings) }
            ?.chromeDecision(),
        chromeObserved = ExemptionObserver.observe(context, BuiltInBlockExemptions.CHROME),
        social = social,
        socialObserved = observed,
        socialSignerMismatch = mismatch,
        socialSignerUnreadable = unreadable,
        recordUnreadable = BuiltInBlockExemptionsStore.chromeFlag(context) ==
            BuiltInBlockExemptions.ChromeFlag.UNREADABLE,
    )
}

/**
 * Installed catalogue social apps plus every saved approval, installed or not,
 * so an approval for an uninstalled app can still be removed before a later
 * reinstall would bring the app back.
 */
internal fun socialRows(
    context: Context,
    settings: BuiltInBlockExemptions.Settings,
): List<ExemptionCandidate> {
    val installed = installedExemptionCandidates(context, BuiltInBlockExemptions.EXEMPTABLE_SOCIAL)
    val listed = installed.map { it.packageName }.toSet()
    val uninstalledApprovals = settings.socialPins().keys
        .filter { it !in listed }
        .map { ExemptionCandidate(it, it) }
    return installed + uninstalledApprovals
}

/** The administrator's reason line for Chrome's decision on the last pass. */
internal fun chromeReasonRes(decision: ChromeFilterExemption.Decision): Int = when (decision) {
    ChromeFilterExemption.Decision.SHOWN -> R.string.system_policy_exempt_chrome_reason_shown
    ChromeFilterExemption.Decision.NOT_AVAILABLE_WEBVIEW_PROVIDER ->
        R.string.system_policy_exempt_chrome_reason_not_available_webview
    ChromeFilterExemption.Decision.NOT_AVAILABLE_WEBVIEW_UNCONFIRMED ->
        R.string.system_policy_exempt_chrome_reason_not_available_webview_unconfirmed
    ChromeFilterExemption.Decision.NOT_AVAILABLE_ANDROID_VERSION ->
        R.string.system_policy_exempt_chrome_reason_not_available_android_version
    ChromeFilterExemption.Decision.NOT_EXEMPTED -> R.string.system_policy_exempt_chrome_reason_not_exempted
    ChromeFilterExemption.Decision.PROTECTION_PAUSED -> R.string.system_policy_exempt_chrome_reason_paused
    ChromeFilterExemption.Decision.FILTER_DISABLED -> R.string.system_policy_exempt_chrome_reason_filter_off
    ChromeFilterExemption.Decision.NOT_INSTALLED -> R.string.system_policy_exempt_chrome_reason_not_installed
    ChromeFilterExemption.Decision.DISABLED -> R.string.system_policy_exempt_chrome_reason_disabled
    ChromeFilterExemption.Decision.SIGNER_UNVERIFIED -> R.string.system_policy_exempt_chrome_reason_signer
    ChromeFilterExemption.Decision.CONTAIN_UNVERIFIED ->
        R.string.system_policy_exempt_chrome_reason_contain_unverified
    ChromeFilterExemption.Decision.CONFIG_UNVERIFIED ->
        R.string.system_policy_exempt_chrome_reason_config_unverified
    ChromeFilterExemption.Decision.FILTER_UNCONFIRMED ->
        R.string.system_policy_exempt_chrome_reason_filter_unconfirmed
    ChromeFilterExemption.Decision.SHOW_UNVERIFIED ->
        R.string.system_policy_exempt_chrome_reason_show_unverified
    ChromeFilterExemption.Decision.HIDE_REFUSED ->
        R.string.system_policy_exempt_chrome_reason_hide_refused
    ChromeFilterExemption.Decision.ERROR -> R.string.system_policy_exempt_chrome_reason_error
}

/** What Android reported, word for word; no inference about why. */
internal fun observedRes(state: BuiltInBlockExemptions.Observed?): Int = when (state) {
    BuiltInBlockExemptions.Observed.VISIBLE -> R.string.system_policy_exempt_observed_visible
    BuiltInBlockExemptions.Observed.HIDDEN -> R.string.system_policy_exempt_observed_hidden
    BuiltInBlockExemptions.Observed.SUSPENDED -> R.string.system_policy_exempt_observed_suspended
    BuiltInBlockExemptions.Observed.DISABLED -> R.string.system_policy_exempt_observed_disabled
    BuiltInBlockExemptions.Observed.UNKNOWN -> R.string.system_policy_exempt_observed_unknown
    BuiltInBlockExemptions.Observed.NOT_INSTALLED, null ->
        R.string.system_policy_exempt_observed_not_installed
}

/** The approval line for a social row: the stored decision, not Android's state. */
internal fun socialApprovalRes(packageName: String, view: ExemptionsView): Int = when {
    packageName !in view.settings.socialPins() -> R.string.system_policy_exempt_social_not_approved
    packageName in view.socialSignerUnreadable -> R.string.system_policy_exempt_social_signer_unreadable_row
    packageName in view.socialSignerMismatch -> R.string.system_policy_exempt_social_signer_mismatch
    else -> R.string.system_policy_exempt_social_approved
}

/** A reason line (if any) and what Android reports right now. */
@Composable
private fun ObservedLines(reason: String?, observed: BuiltInBlockExemptions.Observed) {
    listOfNotNull(
        reason,
        stringResource(R.string.system_policy_exempt_android_state, stringResource(observedRes(observed))),
    ).forEach { line ->
        Text(
            text = line,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

private fun ExemptionCandidate.displayName(): String =
    "${label.bidiIsolated()} · ${packageName.bidiIsolated()}"

/**
 * The administrator's exemptions from the built-in block catalogues: what each
 * does, what Android confirmed, and the controls.
 */
@Composable
internal fun BuiltInExemptionsSection(
    view: ExemptionsView,
    enabled: Boolean,
    onRequestChrome: () -> Unit,
    onRemoveChrome: () -> Unit,
    onRequestSocial: (ExemptionCandidate) -> Unit,
    onRemoveSocial: (ExemptionCandidate) -> Unit,
    onClearApprovals: () -> Unit,
) {
    SectionCard(title = stringResource(R.string.system_policy_section_exemptions)) {
        if (view.recordUnreadable) {
            Text(
                text = stringResource(R.string.system_policy_exempt_record_unreadable),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 12.dp),
            )
            TextButton(
                onClick = onClearApprovals,
                enabled = enabled,
                modifier = Modifier.padding(horizontal = 8.dp),
            ) {
                Text(stringResource(R.string.system_policy_exempt_clear_approvals))
            }
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        }
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 64.dp)
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = stringResource(R.string.system_policy_exempt_chrome_row),
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                ObservedLines(
                    reason = view.chromeDecision?.let { stringResource(chromeReasonRes(it)) },
                    observed = view.chromeObserved,
                )
            }
            Spacer(Modifier.size(16.dp))
            Switch(
                checked = view.settings.chrome(),
                onCheckedChange = { requested ->
                    if (requested) onRequestChrome() else onRemoveChrome()
                },
                enabled = enabled && (view.chromeInstalled || view.settings.chrome()),
            )
        }
        Text(
            text = stringResource(R.string.system_policy_exempt_chrome_body),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
        )

        HorizontalDivider(
            color = MaterialTheme.colorScheme.outlineVariant,
            modifier = Modifier.padding(top = 12.dp),
        )
        Text(
            text = stringResource(R.string.system_policy_exempt_social_title),
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 12.dp),
        )
        Text(
            text = stringResource(R.string.system_policy_exempt_social_body),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
        )
        if (view.social.isEmpty()) {
            Text(
                text = stringResource(R.string.system_policy_exempt_social_none_installed),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
            )
        }
        view.social.forEach { candidate ->
            val approved = candidate.packageName in view.settings.socialPins()
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 64.dp)
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = candidate.displayName(),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    ObservedLines(
                        reason = stringResource(socialApprovalRes(candidate.packageName, view)),
                        observed = view.socialObserved[candidate.packageName]
                            ?: BuiltInBlockExemptions.Observed.UNKNOWN,
                    )
                }
                Spacer(Modifier.size(16.dp))
                Switch(
                    checked = approved,
                    onCheckedChange = { requested ->
                        if (requested) onRequestSocial(candidate) else onRemoveSocial(candidate)
                    },
                    enabled = enabled,
                )
            }
        }
    }
}

/** The consequence of a loosening exemption, stated before anything is written. */
@Composable
internal fun ExemptionConfirmDialog(
    pending: PendingExemption,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    val title = when (pending) {
        PendingExemption.Chrome -> R.string.system_policy_exempt_confirm_chrome_title
        is PendingExemption.Social -> R.string.system_policy_exempt_confirm_social_title
    }
    val body = when (pending) {
        PendingExemption.Chrome -> stringResource(R.string.system_policy_exempt_confirm_chrome_body)
        is PendingExemption.Social -> stringResource(
            R.string.system_policy_exempt_confirm_social_body,
            pending.candidate.displayName(),
        )
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(title)) },
        text = { Text(body) },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text(stringResource(R.string.system_policy_confirm_apply))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.action_cancel))
            }
        },
    )
}
