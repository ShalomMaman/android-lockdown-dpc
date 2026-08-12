package com.example.lockdowndpc.ui

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.selection.selectable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.Language
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.LockOpen
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.lockdowndpc.R
import com.example.lockdowndpc.kiosk.KioskAppCatalog
import com.example.lockdowndpc.kiosk.KioskConfigStore
import com.example.lockdowndpc.kiosk.KioskController
import com.example.lockdowndpc.kiosk.KioskLabels
import com.example.lockdowndpc.kiosk.KioskMode
import com.example.lockdowndpc.kiosk.KioskStateMachine.KioskState
import com.example.lockdowndpc.policy.AllowedAppsStore
import com.example.lockdowndpc.policy.LockdownPackages
import com.example.lockdowndpc.security.AppLabelSanitizer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * The kiosk administration flow of the authenticated console.
 *
 * Four screens, in the order an administrator walks them: pick a profile, say
 * what it points at, confirm the locking step on its own screen, and only then
 * lock. Nothing here decides authorization — every action goes through
 * [KioskController], which derives the administrator session from `AdminSession`
 * itself, so a screen cannot assert that it is authenticated.
 */

/** Everything the kiosk screens render, read once off the main thread. */
internal data class KioskSnapshot(
    val mode: KioskMode,
    val state: KioskState,
    val targetPackage: String,
    val targetLabel: String,
    val siteUrl: String,
    val origin: String,
    val faultReason: String,
    val problems: List<String>,
) {
    val configValid: Boolean get() = problems.isEmpty()

    /**
     * What the activation row and the confirmation card name as "the target",
     * already isolated for the direction the value actually has.
     *
     * A single-app target is a third-party label whose language is unknown at
     * build time, so it takes first-strong isolation: forcing it left-to-right
     * made a right-to-left third-party label resolve its parentheses against
     * an L base and render visibly scrambled. An origin is a Latin identifier and
     * genuinely is left-to-right.
     */
    val targetDisplay: String
        get() = when (mode) {
            KioskMode.SINGLE_APP -> targetLabel.ifBlank { targetPackage }.bidiIsolated()
            KioskMode.SINGLE_SITE -> origin.ifBlank { siteUrl }.ltrIsolated()
            else -> ""
        }

    companion object {
        val Empty = KioskSnapshot(
            mode = KioskMode.OFF,
            state = KioskState.OFF,
            targetPackage = "",
            targetLabel = "",
            siteUrl = "",
            origin = "",
            faultReason = "",
            problems = emptyList(),
        )
    }
}

/** One installed application offered as a single-app kiosk target. */
internal data class KioskAppRow(val packageName: String, val label: String)

/** One configured management package, presented honestly. */
internal data class ManagementEntry(
    val packageName: String,
    val pinned: Boolean,
    val installed: Boolean,
)

private val KIOSK_PROFILES = listOf(KioskMode.OFF, KioskMode.SINGLE_APP, KioskMode.SINGLE_SITE)

/**
 * Reads stored kiosk state and re-validates it against the device.
 *
 * Touches `PackageManager`, so callers run it on [Dispatchers.IO]. Re-validating
 * on every read is what makes the console honest about a target that has been
 * uninstalled or disabled since it was configured.
 */
internal fun readKioskSnapshot(context: Context): KioskSnapshot {
    val settings = KioskConfigStore.read(context)
    val validation = KioskController.validate(context)
    val target = settings.config().targetPackage()
    return KioskSnapshot(
        mode = settings.config().mode(),
        state = settings.state(),
        targetPackage = target,
        targetLabel = if (target.isEmpty()) "" else applicationLabel(context, target),
        siteUrl = settings.config().siteUrl(),
        origin = validation.origin()?.value().orEmpty(),
        faultReason = settings.faultReason(),
        problems = validation.errors().toList(),
    )
}

internal fun readManagementEntries(context: Context): List<ManagementEntry> =
    LockdownPackages.managementPackages(AllowedAppsStore.getManagementCertificatePins(context))
        .map { record ->
            ManagementEntry(
                packageName = record.packageName(),
                pinned = record.hasPinnedCertificate(),
                installed = isPackagePresent(context.packageManager, record.packageName()),
            )
        }

// ------------------------------------------------------------------- profile

@Composable
internal fun KioskProfileScreen(
    snapshot: KioskSnapshot,
    busy: Boolean,
    message: UiMessage?,
    onConfigureApp: () -> Unit,
    onConfigureSite: () -> Unit,
    onClear: () -> Unit,
    onActivate: () -> Unit,
    onExit: () -> Unit,
    onBack: () -> Unit,
) {
    // The radio group is a *pending* choice. Saving it is a separate, explicit
    // step, and locking the device is a third one behind its own screen, so no
    // single tap can take a classroom device away from whoever is holding it.
    var pending by remember(snapshot.mode) { mutableStateOf(snapshot.mode) }

    LockdownScreen(
        title = stringResource(R.string.kiosk_title),
        subtitle = stringResource(R.string.kiosk_subtitle),
    ) {
        KioskStatusCard(snapshot)
        if (message != null) {
            Spacer(Modifier.height(16.dp))
            MessageBanner(message)
        }

        Spacer(Modifier.height(24.dp))
        SectionCard(title = stringResource(R.string.kiosk_section_profile)) {
            KIOSK_PROFILES.forEachIndexed { index, mode ->
                if (index > 0) {
                    HorizontalDivider(
                        color = MaterialTheme.colorScheme.outlineVariant,
                        modifier = Modifier.padding(start = 56.dp),
                    )
                }
                ProfileOption(
                    mode = mode,
                    selected = pending == mode,
                    current = snapshot.mode == mode,
                    onSelect = { pending = mode },
                )
            }
        }

        Spacer(Modifier.height(20.dp))
        when (pending) {
            KioskMode.SINGLE_APP -> PrimaryAction(
                text = stringResource(
                    if (busy) R.string.kiosk_action_working else R.string.kiosk_action_choose_app
                ),
                icon = Icons.Rounded.Apps,
                enabled = !busy,
                onClick = onConfigureApp,
            )

            KioskMode.SINGLE_SITE -> PrimaryAction(
                text = stringResource(
                    if (busy) R.string.kiosk_action_working else R.string.kiosk_action_choose_site
                ),
                icon = Icons.Rounded.Language,
                enabled = !busy,
                onClick = onConfigureSite,
            )

            else -> if (snapshot.mode != KioskMode.OFF) {
                PrimaryAction(
                    text = stringResource(
                        if (busy) R.string.kiosk_action_working else R.string.kiosk_action_clear
                    ),
                    icon = Icons.Rounded.Close,
                    enabled = !busy,
                    onClick = onClear,
                )
            }
        }

        if (snapshot.state != KioskState.OFF) {
            Spacer(Modifier.height(28.dp))
            SectionCard(title = stringResource(R.string.kiosk_section_actions)) {
                if (snapshot.state == KioskState.ACTIVE) {
                    ActionRow(
                        icon = Icons.Rounded.LockOpen,
                        title = stringResource(R.string.kiosk_action_exit),
                        // What this row *will* do. `kiosk_exited` is the result
                        // message for the transition, and reading it here — a few
                        // dp under a status card that says "Active — the device is
                        // locked" — asserted the opposite of the card.
                        supporting = stringResource(R.string.kiosk_action_exit_supporting),
                        enabled = !busy,
                        onClick = onExit,
                    )
                } else if (snapshot.configValid) {
                    ActionRow(
                        icon = Icons.Rounded.Lock,
                        title = stringResource(R.string.kiosk_action_activate),
                        supporting = snapshot.targetDisplay,
                        enabled = !busy,
                        onClick = onActivate,
                    )
                } else {
                    // An armed profile whose target has gone stale gets the
                    // reasons instead of a button that would only fail.
                    KioskProblemList(snapshot.problems)
                }
            }
        }

        Spacer(Modifier.height(28.dp))
        RecoveryNote(snapshot.mode)

        Spacer(Modifier.height(24.dp))
        SecondaryAction(text = stringResource(R.string.kiosk_back), onClick = onBack)
    }
}

@Composable
private fun ProfileOption(
    mode: KioskMode,
    selected: Boolean,
    current: Boolean,
    onSelect: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 64.dp)
            .selectable(selected = selected, role = Role.RadioButton, onClick = onSelect)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = selected, onClick = null)
        Spacer(Modifier.size(16.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = stringResource(KioskLabels.profile(mode)),
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                text = stringResource(KioskLabels.profileSummary(mode)),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (current) {
            Spacer(Modifier.size(12.dp))
            Icon(
                imageVector = Icons.Rounded.Shield,
                contentDescription = stringResource(R.string.kiosk_status_label_profile),
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(20.dp),
            )
        }
    }
}

@Composable
private fun KioskStatusCard(snapshot: KioskSnapshot) {
    val none = stringResource(R.string.kiosk_status_none)
    // A package name and an origin are Latin identifiers that have to keep their
    // own segment order inside a right-to-left page, so both are isolated
    // left-to-right rather than left to inherit the paragraph direction.
    val target: Pair<String, String>? = when (snapshot.mode) {
        KioskMode.SINGLE_APP -> stringResource(R.string.kiosk_status_label_target) to
            snapshot.targetPackage.ifBlank { none }.ltrIsolated()

        KioskMode.SINGLE_SITE -> stringResource(R.string.kiosk_status_label_origin) to
            snapshot.origin.ifBlank { snapshot.siteUrl }.ifBlank { none }.ltrIsolated()

        else -> null
    }
    val facts = listOfNotNull(
        stringResource(R.string.kiosk_status_label_profile) to
            stringResource(KioskLabels.profile(snapshot.mode)),
        stringResource(R.string.kiosk_status_label_state) to
            stringResource(KioskLabels.state(snapshot.state)),
        target,
    )
    // The stored fault reason is a machine code list from the validator, so it is
    // isolated before it is embedded in a localized sentence.
    val detail = if (snapshot.faultReason.isNotBlank()) {
        stringResource(R.string.kiosk_status_detail, snapshot.faultReason.bidiIsolated())
    } else {
        null
    }
    PolicyStatusCard(
        tone = when (snapshot.state) {
            KioskState.ACTIVE -> StatusTone.VERIFIED
            KioskState.FAULT -> StatusTone.FAILED
            KioskState.ARMED -> StatusTone.APPLYING
            else -> StatusTone.INACTIVE
        },
        headline = stringResource(KioskLabels.state(snapshot.state)),
        facts = facts,
        detail = detail,
    )
}

@Composable
private fun KioskProblemList(problems: List<String>) {
    Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
        problems.forEach { code ->
            Row(verticalAlignment = Alignment.Top, modifier = Modifier.padding(vertical = 4.dp)) {
                Icon(
                    imageVector = Icons.Rounded.Warning,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.error,
                    modifier = Modifier.size(18.dp),
                )
                Spacer(Modifier.size(12.dp))
                Text(
                    text = kioskProblemText(code),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        }
    }
}

/**
 * How an administrator gets back in, stated per profile.
 *
 * The shared paragraph describes the gesture; the profile-specific sentence says
 * where that screen actually is, because the answer differs. A single-site kiosk
 * *is* the Device Guard screen. A single-app kiosk hands the display to another
 * package, and the way back is the HOME key returning to this DPC — which the
 * platform only offers from API 28 up.
 */
@Composable
private fun RecoveryNote(mode: KioskMode) {
    Card(
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer,
            contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Text(
                text = stringResource(R.string.kiosk_recovery_title),
                style = MaterialTheme.typography.titleSmall,
            )
            Spacer(Modifier.height(8.dp))
            Text(
                text = stringResource(R.string.kiosk_recovery_body),
                style = MaterialTheme.typography.bodyMedium,
            )
            val perProfile = when (mode) {
                KioskMode.SINGLE_APP -> R.string.kiosk_recovery_single_app
                KioskMode.SINGLE_SITE -> R.string.kiosk_recovery_single_site
                else -> null
            }
            if (perProfile != null) {
                Spacer(Modifier.height(8.dp))
                Text(
                    text = stringResource(perProfile),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }
}

// ---------------------------------------------------------------- app picker

@Composable
internal fun KioskAppPickerScreen(
    busy: Boolean,
    onSelect: (String) -> Unit,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    var loading by remember { mutableStateOf(true) }
    var rows by remember { mutableStateOf(emptyList<KioskAppRow>()) }
    var query by remember { mutableStateOf("") }

    LaunchedEffect(Unit) {
        rows = withContext(Dispatchers.IO) { loadKioskAppRows(context) }
        loading = false
    }
    val filtered = remember(rows, query) {
        rows.filter { matchesAppQuery(it.label, it.packageName, query) }
    }

    LockdownScreen(
        title = stringResource(R.string.kiosk_app_title),
        subtitle = stringResource(R.string.kiosk_app_subtitle),
    ) {
        Text(
            text = stringResource(R.string.kiosk_app_note),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(16.dp))
        OutlinedTextField(
            value = query,
            onValueChange = { query = it },
            label = { Text(stringResource(R.string.apps_search)) },
            singleLine = true,
            shape = MaterialTheme.shapes.small,
            leadingIcon = { Icon(Icons.Rounded.Search, contentDescription = null) },
            trailingIcon = {
                if (query.isNotEmpty()) {
                    IconButton(onClick = { query = "" }) {
                        Icon(
                            imageVector = Icons.Rounded.Close,
                            contentDescription = stringResource(R.string.apps_search_clear),
                        )
                    }
                }
            },
            // A query is as likely to be a package-name fragment as a Hebrew
            // label, so the field resolves its own direction from what was typed
            // rather than inheriting the page's. The platform equivalent of
            // `dir="auto"` on an input.
            textStyle = LocalTextStyle.current.copy(textDirection = TextDirection.Content),
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(16.dp))

        when {
            loading -> Text(
                text = stringResource(R.string.apps_loading),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            rows.isEmpty() -> KioskEmptyNote(
                title = stringResource(R.string.kiosk_app_empty_title),
                body = stringResource(R.string.kiosk_app_empty_body),
            )

            filtered.isEmpty() -> KioskEmptyNote(
                title = stringResource(R.string.apps_no_results_title),
                body = stringResource(R.string.apps_no_results_body),
            )

            // A plain Column inside the page's own scroll, not a nested
            // LazyColumn: an eligible-target list is short, and nesting two
            // scrollers in one direction is a measurement error in Compose.
            else -> SectionCard(title = stringResource(R.string.kiosk_app_title)) {
                filtered.forEachIndexed { index, row ->
                    KioskAppEntry(
                        row = row,
                        showDivider = index > 0,
                        enabled = !busy,
                        onClick = { onSelect(row.packageName) },
                    )
                }
            }
        }

        Spacer(Modifier.height(24.dp))
        SecondaryAction(text = stringResource(R.string.action_back), onClick = onBack)
    }
}

@Composable
private fun KioskAppEntry(
    row: KioskAppRow,
    showDivider: Boolean,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    val description = stringResource(
        R.string.kiosk_app_row_description,
        row.label,
        row.packageName,
    )
    if (showDivider) {
        HorizontalDivider(
            color = MaterialTheme.colorScheme.outlineVariant,
            modifier = Modifier.padding(start = 56.dp),
        )
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 64.dp)
            .semantics(mergeDescendants = true) { contentDescription = description }
            .padding(horizontal = 16.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            imageVector = Icons.Rounded.Apps,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(24.dp),
        )
        Spacer(Modifier.size(16.dp))
        Column(modifier = Modifier.weight(1f).padding(vertical = 12.dp)) {
            Text(
                // A third-party label can be in any language, so it is isolated
                // without a forced direction; the package name below it is a
                // Latin identifier and is forced left-to-right.
                text = row.label.bidiIsolated(),
                style = MaterialTheme.typography.bodyLarge,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = row.packageName.ltrIsolated(),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Spacer(Modifier.size(12.dp))
        TextButton(enabled = enabled, onClick = onClick) {
            Text(stringResource(R.string.action_save))
        }
    }
}

@Composable
private fun KioskEmptyNote(title: String, body: String) {
    Column {
        Text(text = title, style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(8.dp))
        Text(
            text = body,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

// --------------------------------------------------------------- site editor

@Composable
internal fun KioskSiteScreen(
    initialUrl: String,
    busy: Boolean,
    message: UiMessage?,
    onSave: (String) -> Unit,
    onBack: () -> Unit,
) {
    var raw by remember { mutableStateOf(initialUrl) }
    val preview = remember(raw) { kioskSitePreviewOf(raw) }

    LockdownScreen(
        title = stringResource(R.string.kiosk_site_title),
        subtitle = stringResource(R.string.kiosk_site_subtitle),
    ) {
        OutlinedTextField(
            value = raw,
            onValueChange = { raw = it },
            label = { Text(stringResource(R.string.kiosk_site_field)) },
            singleLine = true,
            shape = MaterialTheme.shapes.small,
            keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                keyboardType = KeyboardType.Uri,
                imeAction = ImeAction.Done,
            ),
            // The field is pinned left-to-right while the page keeps mirroring.
            // A URL is almost entirely neutral and weak characters — `:` `/` `.`
            // and the port digits — so in a right-to-left paragraph the
            // punctuation and the port are displaced and the caret jumps while
            // typing. The three preview lines below are already isolated, and the
            // field is the one place an operator checks their own typing.
            textStyle = LocalTextStyle.current.copy(
                textDirection = TextDirection.Ltr,
                textAlign = TextAlign.Left,
            ),
            isError = preview.entered && preview.problem != null,
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(16.dp))
        if (preview.usable) {
            // The normalized address and the origin are shown before anything is
            // stored, because "https://portal.school.example" and
            // "https://school.example" are different containments and an
            // operator has to see which one they just asked for.
            Text(
                text = stringResource(
                    R.string.kiosk_site_opens,
                    preview.normalizedUrl.ltrIsolated()
                ),
                style = MaterialTheme.typography.bodyMedium,
            )
            Spacer(Modifier.height(6.dp))
            Text(
                text = stringResource(R.string.kiosk_site_origin, preview.origin.ltrIsolated()),
                style = MaterialTheme.typography.bodyMedium,
            )
            Spacer(Modifier.height(12.dp))
            Text(
                text = stringResource(
                    R.string.kiosk_site_boundary,
                    preview.origin.ltrIsolated()
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else if (preview.problem != null) {
            MessageBanner(
                UiMessage(stringResource(kioskProblemLabel(preview.problem)), isError = true)
            )
        }

        if (message != null) {
            Spacer(Modifier.height(16.dp))
            MessageBanner(message)
        }

        Spacer(Modifier.height(24.dp))
        PrimaryAction(
            text = stringResource(
                if (busy) R.string.kiosk_action_working else R.string.kiosk_site_save
            ),
            icon = Icons.Rounded.Language,
            enabled = !busy && preview.usable,
            onClick = { onSave(raw) },
        )
        Spacer(Modifier.height(12.dp))
        SecondaryAction(text = stringResource(R.string.action_back), onClick = onBack)
    }
}

// -------------------------------------------------------------- confirmation

@Composable
internal fun KioskConfirmScreen(
    snapshot: KioskSnapshot,
    busy: Boolean,
    message: UiMessage?,
    onConfirm: () -> Unit,
    onCancel: () -> Unit,
) {
    LockdownScreen(
        title = stringResource(R.string.kiosk_confirm_title),
        subtitle = stringResource(R.string.kiosk_confirm_subtitle),
    ) {
        Card(
            shape = MaterialTheme.shapes.large,
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.errorContainer,
                contentColor = MaterialTheme.colorScheme.onErrorContainer,
            ),
            elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.padding(20.dp)) {
                Row(verticalAlignment = Alignment.Top) {
                    Icon(
                        imageVector = Icons.Rounded.Warning,
                        contentDescription = null,
                        modifier = Modifier.size(22.dp),
                    )
                    Spacer(Modifier.size(12.dp))
                    Text(
                        text = stringResource(
                            if (snapshot.mode == KioskMode.SINGLE_SITE) {
                                R.string.kiosk_confirm_site
                            } else {
                                R.string.kiosk_confirm_app
                            },
                            snapshot.targetDisplay,
                        ),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
                Spacer(Modifier.height(12.dp))
                Text(
                    text = stringResource(R.string.kiosk_confirm_reboot),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }

        Spacer(Modifier.height(20.dp))
        RecoveryNote(snapshot.mode)

        if (message != null) {
            Spacer(Modifier.height(16.dp))
            MessageBanner(message)
        }

        Spacer(Modifier.height(28.dp))
        PrimaryAction(
            text = stringResource(
                if (busy) R.string.kiosk_action_working else R.string.kiosk_action_activate
            ),
            icon = Icons.Rounded.Lock,
            enabled = !busy,
            onClick = onConfirm,
        )
        Spacer(Modifier.height(12.dp))
        SecondaryAction(text = stringResource(R.string.kiosk_confirm_cancel), onClick = onCancel)
    }
}

// -------------------------------------------------------- management packages

/**
 * The one place management connectivity is presented.
 *
 * It states the pin status rather than implying trust: an unpinned record — the
 * shipped Tailscale default — authenticates a package *name* and nothing else,
 * and the dialog says so in as many words.
 */
@Composable
internal fun ManagementPackagesDialog(entries: List<ManagementEntry>, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.management_dialog_title)) },
        text = {
            Column {
                entries.forEach { entry ->
                    Text(
                        text = entry.packageName.ltrIsolated(),
                        style = MaterialTheme.typography.bodyLarge,
                    )
                    Text(
                        text = stringResource(
                            when {
                                !entry.installed -> R.string.management_status_absent
                                entry.pinned -> R.string.management_status_pinned
                                else -> R.string.management_status_unpinned
                            }
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(12.dp))
                }
                Text(
                    text = stringResource(R.string.management_dialog_note),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_close)) }
        },
    )
}

// ------------------------------------------------------------------- helpers

/** Localized sentence for one validator error code, raw code as the fallback. */
@Composable
internal fun kioskProblemText(code: String): String {
    val problem = kioskConfigProblemOf(code)
    return if (problem == KioskConfigProblem.UNKNOWN) {
        stringResource(R.string.kiosk_problem_unknown, code.bidiIsolated())
    } else {
        stringResource(kioskProblemLabel(problem))
    }
}

@StringRes
internal fun kioskProblemLabel(problem: KioskConfigProblem): Int = when (problem) {
    KioskConfigProblem.TARGET_NOT_SELECTED -> R.string.kiosk_problem_target_not_selected
    KioskConfigProblem.TARGET_INVALID_NAME -> R.string.kiosk_problem_target_invalid_name
    KioskConfigProblem.TARGET_UNRESOLVED -> R.string.kiosk_problem_target_unresolved
    KioskConfigProblem.TARGET_MISMATCH -> R.string.kiosk_problem_target_mismatch
    KioskConfigProblem.TARGET_DEVICE_GUARD -> R.string.kiosk_problem_target_device_guard
    KioskConfigProblem.TARGET_PROTECTED -> R.string.kiosk_problem_target_protected
    KioskConfigProblem.TARGET_NOT_INSTALLED -> R.string.kiosk_problem_target_not_installed
    KioskConfigProblem.TARGET_NOT_ENABLED -> R.string.kiosk_problem_target_not_enabled
    KioskConfigProblem.TARGET_NOT_LAUNCHABLE -> R.string.kiosk_problem_target_not_launchable
    KioskConfigProblem.SITE_MISSING -> R.string.kiosk_problem_site_missing
    KioskConfigProblem.SITE_SCHEME -> R.string.kiosk_problem_site_scheme
    KioskConfigProblem.SITE_CREDENTIALS -> R.string.kiosk_problem_site_credentials
    KioskConfigProblem.SITE_HOST -> R.string.kiosk_problem_site_host
    KioskConfigProblem.SITE_PORT -> R.string.kiosk_problem_site_port
    KioskConfigProblem.SITE_MALFORMED -> R.string.kiosk_problem_site_malformed
    KioskConfigProblem.UNKNOWN -> R.string.kiosk_problem_unknown
}

/**
 * Turns a refusal into a sentence that names the next step.
 *
 * Refusals that carry validator errors show the first concrete problem rather
 * than the generic "invalid configuration", because "the chosen app is no longer
 * installed" is the actionable half of that answer.
 */
internal fun kioskFailureMessage(
    context: Context,
    reason: String?,
    problems: List<String>,
): String = when (kioskFailureOf(reason)) {
    KioskFailure.AUTH_REQUIRED -> context.getString(R.string.kiosk_error_auth)
    KioskFailure.NOT_CONFIGURED -> context.getString(R.string.kiosk_error_not_configured)
    KioskFailure.NOT_ACTIVE -> context.getString(R.string.kiosk_error_not_active)
    KioskFailure.NOT_DEVICE_OWNER -> context.getString(R.string.not_device_owner)
    KioskFailure.INVALID_CONFIGURATION -> context.getString(
        R.string.kiosk_error_invalid,
        problemSentence(context, problems),
    )

    KioskFailure.UNKNOWN -> context.getString(
        R.string.kiosk_error_refused,
        reason.orEmpty().bidiIsolated(),
    )
}

/** Message for a request that was accepted but whose device pass reported errors. */
internal fun kioskApplyErrorMessage(context: Context, errors: List<String>): String =
    context.getString(
        R.string.kiosk_error_apply,
        errors.firstOrNull()?.bidiIsolated() ?: context.getString(R.string.error_unknown),
    )

private fun problemSentence(context: Context, problems: List<String>): String {
    val first = problems.firstOrNull() ?: return context.getString(R.string.error_unknown)
    val problem = kioskConfigProblemOf(first)
    return if (problem == KioskConfigProblem.UNKNOWN) {
        context.getString(R.string.kiosk_problem_unknown, first.bidiIsolated())
    } else {
        context.getString(kioskProblemLabel(problem))
    }
}

// ------------------------------------------------------------ device queries

/**
 * Every installed, launchable application an administrator may pin.
 *
 * Hidden packages are included on purpose: an app this policy currently blocks
 * is a perfectly reasonable kiosk target, and pinning it is what unhides it on
 * the next policy pass. Remembered packages are folded in so an application the
 * DPC has managed before stays selectable even while bulk queries omit it.
 *
 * The eligibility rule itself is [KioskAppCatalog], which is also what
 * `KioskController.resolveTarget` feeds into the validator, so the picker cannot
 * offer something the controller would then refuse.
 */
private fun loadKioskAppRows(context: Context): List<KioskAppRow> {
    val pm = context.packageManager
    val flags = (
        PackageManager.MATCH_UNINSTALLED_PACKAGES or PackageManager.MATCH_DISABLED_COMPONENTS
        ).toLong()

    val installed: List<ApplicationInfo> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(flags))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledApplications(flags.toInt())
        }
    val infoByPackage = installed
        .filter { it.flags and ApplicationInfo.FLAG_INSTALLED != 0 }
        .associateBy { it.packageName }

    val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
    val launchable: Set<String> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.queryIntentActivities(launcherIntent, PackageManager.ResolveInfoFlags.of(flags))
        } else {
            @Suppress("DEPRECATION")
            pm.queryIntentActivities(launcherIntent, flags.toInt())
        }.mapNotNullTo(HashSet()) { it.activityInfo?.packageName }

    val candidatePackages = LinkedHashSet(infoByPackage.keys)
    candidatePackages.addAll(AllowedAppsStore.getManagedPackages(context))

    val candidates = candidatePackages.map { packageName ->
        val info = infoByPackage[packageName]
        KioskAppCatalog.Candidate(
            packageName,
            AppLabelSanitizer.sanitize(info?.loadLabel(pm)?.toString())
                ?: AllowedAppsStore.getRememberedLabel(context, packageName),
            info != null,
            info?.enabled ?: false,
            packageName in launchable,
            packageName == context.packageName,
        )
    }
    return KioskAppCatalog.selectable(candidates)
        .map { KioskAppRow(it.packageName(), it.label()) }
}

private fun applicationLabel(context: Context, packageName: String): String {
    val pm = context.packageManager
    val flags = (
        PackageManager.MATCH_UNINSTALLED_PACKAGES or PackageManager.MATCH_DISABLED_COMPONENTS
        ).toLong()
    return try {
        val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getApplicationInfo(packageName, PackageManager.ApplicationInfoFlags.of(flags))
        } else {
            @Suppress("DEPRECATION")
            pm.getApplicationInfo(packageName, flags.toInt())
        }
        AppLabelSanitizer.sanitize(info.loadLabel(pm).toString())
    } catch (ignored: PackageManager.NameNotFoundException) {
        AllowedAppsStore.getRememberedLabel(context, packageName)
    }
}

private fun isPackagePresent(pm: PackageManager, packageName: String): Boolean = try {
    val flags = (
        PackageManager.MATCH_UNINSTALLED_PACKAGES or PackageManager.MATCH_DISABLED_COMPONENTS
        ).toLong()
    val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        pm.getApplicationInfo(packageName, PackageManager.ApplicationInfoFlags.of(flags))
    } else {
        @Suppress("DEPRECATION")
        pm.getApplicationInfo(packageName, flags.toInt())
    }
    info.flags and ApplicationInfo.FLAG_INSTALLED != 0
} catch (ignored: PackageManager.NameNotFoundException) {
    false
}
