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
import com.example.lockdowndpc.security.AppLabelSanitizer

/** One installed package from an exemptable catalogue, with its display label. */
internal data class ExemptionCandidate(val packageName: String, val label: String)

/** A pending loosening change, held until the administrator confirms it. */
internal sealed interface PendingExemption {
    data object Chrome : PendingExemption
    data class Social(val candidate: ExemptionCandidate) : PendingExemption
}

/** Everything the section shows, read once per revision. */
internal data class ExemptionsView(
    val settings: BuiltInBlockExemptions.Settings,
    /** The last read-back, only when it was taken for the current decision. */
    val readback: BuiltInBlockExemptionsStore.Readback?,
    val chromeInstalled: Boolean,
    val social: List<ExemptionCandidate>,
)

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
    return ExemptionsView(
        settings = settings,
        readback = BuiltInBlockExemptionsStore.readback(context)?.takeIf { it.describes(settings) },
        chromeInstalled = installedExemptionCandidates(
            context,
            setOf(BuiltInBlockExemptions.CHROME),
        ).isNotEmpty(),
        social = installedExemptionCandidates(context, BuiltInBlockExemptions.EXEMPTABLE_SOCIAL),
    )
}

/** The administrator's reason line for Chrome's decision on the last pass. */
internal fun chromeReasonRes(decision: ChromeFilterExemption.Decision): Int = when (decision) {
    ChromeFilterExemption.Decision.SHOWN -> R.string.system_policy_exempt_chrome_reason_shown
    ChromeFilterExemption.Decision.NOT_AVAILABLE ->
        R.string.system_policy_exempt_chrome_reason_not_available
    ChromeFilterExemption.Decision.NOT_EXEMPTED -> R.string.system_policy_exempt_chrome_reason_not_exempted
    ChromeFilterExemption.Decision.PROTECTION_PAUSED -> R.string.system_policy_exempt_chrome_reason_paused
    ChromeFilterExemption.Decision.FILTER_DISABLED -> R.string.system_policy_exempt_chrome_reason_filter_off
    ChromeFilterExemption.Decision.NOT_INSTALLED -> R.string.system_policy_exempt_chrome_reason_not_installed
    ChromeFilterExemption.Decision.SIGNER_UNVERIFIED -> R.string.system_policy_exempt_chrome_reason_signer
    ChromeFilterExemption.Decision.CONTAIN_UNVERIFIED ->
        R.string.system_policy_exempt_chrome_reason_contain_unverified
    ChromeFilterExemption.Decision.CONFIG_UNVERIFIED ->
        R.string.system_policy_exempt_chrome_reason_config_unverified
    ChromeFilterExemption.Decision.ERROR -> R.string.system_policy_exempt_chrome_reason_error
}

/** What Android reported, word for word; no inference about why. */
internal fun observedRes(state: BuiltInBlockExemptions.Observed?): Int = when (state) {
    BuiltInBlockExemptions.Observed.VISIBLE -> R.string.system_policy_exempt_observed_visible
    BuiltInBlockExemptions.Observed.HIDDEN -> R.string.system_policy_exempt_observed_hidden
    BuiltInBlockExemptions.Observed.SUSPENDED -> R.string.system_policy_exempt_observed_suspended
    BuiltInBlockExemptions.Observed.UNKNOWN -> R.string.system_policy_exempt_observed_unknown
    BuiltInBlockExemptions.Observed.NOT_INSTALLED, null ->
        R.string.system_policy_exempt_observed_not_installed
}

/** The approval line for a social row: the stored decision, not Android's state. */
internal fun socialApprovalRes(packageName: String, view: ExemptionsView): Int = when {
    packageName !in view.settings.socialPins() -> R.string.system_policy_exempt_social_not_approved
    view.readback?.socialSignerMismatch()?.contains(packageName) == true ->
        R.string.system_policy_exempt_social_signer_mismatch
    else -> R.string.system_policy_exempt_social_approved
}

/** Status lines from the read-back taken for the current decision only. */
@Composable
private fun ObservedLines(reason: String?, observed: BuiltInBlockExemptions.Observed?, view: ExemptionsView) {
    val readback = view.readback
    val lines = if (readback == null) {
        listOfNotNull(reason, stringResource(R.string.system_policy_exempt_state_pending))
    } else {
        listOfNotNull(
            reason,
            stringResource(R.string.system_policy_exempt_android_state, stringResource(observedRes(observed))),
            if (readback.passVerified()) null else stringResource(R.string.system_policy_exempt_pass_unverified),
        )
    }
    lines.forEach { line ->
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
) {
    SectionCard(title = stringResource(R.string.system_policy_section_exemptions)) {
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
                    reason = view.readback?.let { stringResource(chromeReasonRes(it.chromeDecision())) },
                    observed = view.readback?.chromeObserved(),
                    view = view,
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
                        observed = view.readback?.social()?.get(candidate.packageName),
                        view = view,
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
