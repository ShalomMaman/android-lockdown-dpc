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
    val settings = BuiltInBlockExemptionsStore.read(context)
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

/**
 * The status line for Chrome, from the read-back taken for the current
 * decision only. "Available" is shown only when Android reported Chrome neither
 * hidden nor suspended; a withdrawn exemption reads as pending until Android
 * reports it blocked.
 */
internal fun chromeStatusRes(view: ExemptionsView): Int {
    val readback = view.readback ?: return R.string.system_policy_exempt_state_pending
    if (!view.settings.chrome()) {
        return if (readback.chromeVisible()) {
            R.string.system_policy_exempt_chrome_state_revocation_pending
        } else {
            R.string.system_policy_exempt_chrome_state_off
        }
    }
    return when (readback.chromeDecision()) {
        ChromeFilterExemption.Decision.SHOWN -> if (readback.chromeVisible()) {
            R.string.system_policy_exempt_chrome_state_active
        } else {
            R.string.system_policy_exempt_chrome_state_unconfirmed
        }
        ChromeFilterExemption.Decision.NOT_EXEMPTED -> R.string.system_policy_exempt_state_pending
        ChromeFilterExemption.Decision.PROTECTION_PAUSED ->
            R.string.system_policy_exempt_chrome_state_paused
        ChromeFilterExemption.Decision.FILTER_DISABLED ->
            R.string.system_policy_exempt_chrome_state_filter_off
        ChromeFilterExemption.Decision.NOT_INSTALLED ->
            R.string.system_policy_exempt_chrome_state_not_installed
        ChromeFilterExemption.Decision.SIGNER_UNVERIFIED ->
            R.string.system_policy_exempt_chrome_state_signer_unverified
        ChromeFilterExemption.Decision.CONFIG_UNVERIFIED ->
            R.string.system_policy_exempt_chrome_state_restrictions_unverified
        ChromeFilterExemption.Decision.ERROR -> R.string.system_policy_exempt_chrome_state_error
    }
}

internal fun socialStatusRes(packageName: String, view: ExemptionsView): Int {
    val readback = view.readback ?: return R.string.system_policy_exempt_state_pending
    val approved = packageName in view.settings.socialPins()
    val visible = packageName in readback.socialVisible()
    return when {
        !approved && visible -> R.string.system_policy_exempt_social_revocation_pending
        !approved -> R.string.system_policy_exempt_social_blocked
        packageName in readback.socialSignerMismatch() ->
            R.string.system_policy_exempt_social_signer_mismatch
        visible -> R.string.system_policy_exempt_social_confirmed
        else -> R.string.system_policy_exempt_social_unconfirmed
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
                Text(
                    text = stringResource(
                        R.string.system_policy_status_line,
                        stringResource(chromeStatusRes(view)),
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
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
                    Text(
                        text = stringResource(socialStatusRes(candidate.packageName, view)),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
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
