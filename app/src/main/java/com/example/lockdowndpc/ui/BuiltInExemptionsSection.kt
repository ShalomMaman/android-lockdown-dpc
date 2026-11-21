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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import com.example.lockdowndpc.R
import com.example.lockdowndpc.policy.BuiltInBlockExemptions
import com.example.lockdowndpc.policy.BuiltInBlockExemptionsStore
import com.example.lockdowndpc.security.AppLabelSanitizer

/** One installed package from an exemptable catalogue, with its display label. */
internal data class ExemptionCandidate(val packageName: String, val label: String)

/** A pending loosening change, held until the administrator confirms it. */
internal sealed interface PendingExemption {
    data class Browser(val candidate: ExemptionCandidate) : PendingExemption
    data class Social(val candidate: ExemptionCandidate) : PendingExemption
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

/**
 * The status line for the browser exemption, from the last read-back.
 *
 * A saved choice with no read-back yet is reported as exactly that; "available"
 * is shown only when Android itself confirmed the browser is neither hidden
 * nor suspended.
 */
internal fun exemptBrowserStatusRes(
    settings: BuiltInBlockExemptions.Settings,
    readback: BuiltInBlockExemptionsStore.Readback?,
): Int {
    if (settings.browserPackage() == null) {
        return R.string.system_policy_exempt_browser_state_off
    }
    if (readback == null) {
        return R.string.system_policy_exempt_state_pending
    }
    return when (readback.browserState()) {
        BuiltInBlockExemptions.BrowserState.OFF -> R.string.system_policy_exempt_state_pending
        BuiltInBlockExemptions.BrowserState.ACTIVE -> if (readback.browserConfirmedAvailable()) {
            R.string.system_policy_exempt_browser_state_active
        } else {
            R.string.system_policy_exempt_browser_state_unconfirmed
        }
        BuiltInBlockExemptions.BrowserState.FILTER_UNVERIFIED ->
            R.string.system_policy_exempt_browser_state_filter_unverified
        BuiltInBlockExemptions.BrowserState.CANARY_UNVERIFIED ->
            R.string.system_policy_exempt_browser_state_canary_unverified
        BuiltInBlockExemptions.BrowserState.NOT_INSTALLED ->
            R.string.system_policy_exempt_browser_state_not_installed
        BuiltInBlockExemptions.BrowserState.LINK_ROUTE_UNVERIFIED ->
            R.string.system_policy_exempt_browser_state_route_unverified
    }
}

internal fun exemptSocialStatusRes(
    packageName: String,
    settings: BuiltInBlockExemptions.Settings,
    readback: BuiltInBlockExemptionsStore.Readback?,
): Int = when {
    packageName !in settings.socialExemptions() -> R.string.system_policy_exempt_social_blocked
    readback == null -> R.string.system_policy_exempt_state_pending
    packageName in readback.socialConfirmedAvailable() ->
        R.string.system_policy_exempt_social_confirmed
    else -> R.string.system_policy_exempt_social_unconfirmed
}

private fun ExemptionCandidate.displayName(): String =
    "${label.bidiIsolated()} · ${packageName.bidiIsolated()}"

/**
 * The administrator's exemptions from the built-in browser and social
 * catalogues: what each does, what Android confirmed, and the controls.
 */
@Composable
internal fun BuiltInExemptionsSection(
    settings: BuiltInBlockExemptions.Settings,
    readback: BuiltInBlockExemptionsStore.Readback?,
    browsers: List<ExemptionCandidate>,
    social: List<ExemptionCandidate>,
    enabled: Boolean,
    onRequestBrowser: (ExemptionCandidate) -> Unit,
    onRemoveBrowser: () -> Unit,
    onRequestSocial: (ExemptionCandidate) -> Unit,
    onRemoveSocial: (ExemptionCandidate) -> Unit,
) {
    var choosingBrowser by remember { mutableStateOf(false) }
    val chosen = settings.browserPackage()
    val chosenName = browsers.firstOrNull { it.packageName == chosen }?.displayName()
        ?: chosen?.bidiIsolated()

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
                    text = stringResource(R.string.system_policy_exempt_browser_row),
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Text(
                    text = chosenName?.let {
                        stringResource(R.string.system_policy_exempt_browser_choice, it)
                    } ?: stringResource(R.string.system_policy_exempt_browser_none),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Text(
                    text = stringResource(
                        R.string.system_policy_status_line,
                        stringResource(exemptBrowserStatusRes(settings, readback)),
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.size(16.dp))
            TextButton(onClick = { choosingBrowser = true }, enabled = enabled) {
                Text(stringResource(R.string.system_policy_exempt_browser_choose))
            }
        }
        Text(
            text = stringResource(R.string.system_policy_exempt_browser_body),
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
        if (social.isEmpty()) {
            Text(
                text = stringResource(R.string.system_policy_exempt_social_none_installed),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
            )
        }
        social.forEach { candidate ->
            val exempt = candidate.packageName in settings.socialExemptions()
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
                        text = stringResource(
                            exemptSocialStatusRes(candidate.packageName, settings, readback)
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Spacer(Modifier.size(16.dp))
                Switch(
                    checked = exempt,
                    onCheckedChange = { requested ->
                        if (requested) onRequestSocial(candidate) else onRemoveSocial(candidate)
                    },
                    enabled = enabled,
                )
            }
        }
    }

    if (choosingBrowser) {
        BrowserChoiceDialog(
            browsers = browsers,
            current = chosen,
            onChoose = { candidate ->
                choosingBrowser = false
                when {
                    candidate == null -> if (chosen != null) onRemoveBrowser()
                    candidate.packageName != chosen -> onRequestBrowser(candidate)
                }
            },
            onDismiss = { choosingBrowser = false },
        )
    }
}

@Composable
private fun BrowserChoiceDialog(
    browsers: List<ExemptionCandidate>,
    current: String?,
    onChoose: (ExemptionCandidate?) -> Unit,
    onDismiss: () -> Unit,
) {
    var selected by remember { mutableStateOf(current) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.system_policy_exempt_browser_choose)) },
        text = {
            Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                ChoiceRow(
                    text = stringResource(R.string.system_policy_exempt_browser_none),
                    selected = selected == null,
                    onSelect = { selected = null },
                )
                if (browsers.isEmpty()) {
                    Text(
                        text = stringResource(R.string.system_policy_exempt_browser_no_candidates),
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(vertical = 8.dp),
                    )
                }
                browsers.forEach { candidate ->
                    ChoiceRow(
                        text = candidate.displayName(),
                        selected = selected == candidate.packageName,
                        onSelect = { selected = candidate.packageName },
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                onChoose(browsers.firstOrNull { it.packageName == selected })
            }) {
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

@Composable
private fun ChoiceRow(text: String, selected: Boolean, onSelect: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .selectable(selected = selected, role = Role.RadioButton, onClick = onSelect),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = selected, onClick = null)
        Spacer(Modifier.size(12.dp))
        Text(text = text, style = MaterialTheme.typography.bodyMedium)
    }
}

/** The consequence of a loosening exemption, stated before anything is written. */
@Composable
internal fun ExemptionConfirmDialog(
    pending: PendingExemption,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    val (titleRes, bodyRes, candidate) = when (pending) {
        is PendingExemption.Browser -> Triple(
            R.string.system_policy_exempt_confirm_browser_title,
            R.string.system_policy_exempt_confirm_browser_body,
            pending.candidate,
        )
        is PendingExemption.Social -> Triple(
            R.string.system_policy_exempt_confirm_social_title,
            R.string.system_policy_exempt_confirm_social_body,
            pending.candidate,
        )
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(titleRes)) },
        text = { Text(stringResource(bodyRes, candidate.displayName())) },
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
