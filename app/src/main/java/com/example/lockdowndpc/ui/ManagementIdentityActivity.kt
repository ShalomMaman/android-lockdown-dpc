package com.example.lockdowndpc.ui

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import com.example.lockdowndpc.R
import com.example.lockdowndpc.policy.AllowedAppsStore
import com.example.lockdowndpc.policy.AuditLog
import com.example.lockdowndpc.policy.ManagementIdentityInspector
import com.example.lockdowndpc.security.AdminSession
import com.example.lockdowndpc.ui.theme.LockdownTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.util.Locale

/**
 * The authenticated management identity console (Issue #27).
 *
 * Device Guard exempts the management transport from blocking. Until this
 * screen existed, nothing in the console could configure the certificate that
 * exemption is supposed to rest on, so the shipped Tailscale record authenticated
 * a package *name* and any application installed under that name inherited the
 * exemption. That is the spoofing gap this screen closes.
 *
 * Three rules shape it, all from the security model rather than from taste:
 *
 * 1. It is reachable only inside a live administrator session and abandons itself
 *    the moment that session lapses — including on resume, exactly like
 *    [SystemPolicyActivity].
 * 2. Nothing on it is optimistic. Each row separates what the platform reported
 *    from what an administrator approved, and states the resulting verdict in
 *    those terms: proven, trusted by name only, or refused.
 * 3. Pinning what is installed is only safe on a device known to be clean, so the
 *    screen says that before the action is offered and again in the confirmation.
 *
 * `AppCompatActivity` is the base class for the same localization reason as the
 * other console screens: below API 33 it is what applies the persisted display
 * language.
 */
class ManagementIdentityActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!AdminSession.isUnlocked()) {
            finish()
            return
        }
        // This screen names the packages that hold management privilege on this
        // device and the certificates that prove it, so it follows the console's
        // fail-closed screenshot rule.
        if (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE == 0) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.light(Color.TRANSPARENT, SYSTEM_BAR_DARK_SCRIM),
            navigationBarStyle = SystemBarStyle.light(Color.TRANSPARENT, SYSTEM_BAR_DARK_SCRIM),
        )
        setTitle(R.string.mgmtid_title)
        setContent {
            LockdownTheme {
                ManagementIdentityScreen(onBack = { finish() })
            }
        }
    }

    override fun onResume() {
        super.onResume()
        if (!AdminSession.isUnlocked()) {
            finish()
        }
    }
}

/** A pending removal of one approved certificate, held until it is confirmed. */
private data class PendingRemoval(val row: ManagementIdentityRow, val digest: String)

/** The result of one store write, plus the re-read that follows it. */
private class WriteOutcome(val rows: List<ManagementIdentityRow>?, val failure: String)

@Composable
private fun ManagementIdentityScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()

    // Every write re-reads the device rather than patching the rows in memory:
    // what is on screen has to be what the next apply pass would compute, not
    // what this screen believes it just stored.
    var loading by remember { mutableStateOf(true) }
    var working by remember { mutableStateOf(false) }
    var rows by remember { mutableStateOf(emptyList<ManagementIdentityRow>()) }
    var message by remember { mutableStateOf<UiMessage?>(null) }
    var pendingPin by remember { mutableStateOf<ManagementIdentityRow?>(null) }
    var pendingRemoval by remember { mutableStateOf<PendingRemoval?>(null) }
    var manualEntryFor by remember { mutableStateOf<ManagementIdentityRow?>(null) }
    var auditedRefusals by remember { mutableStateOf(emptySet<String>()) }

    fun requireSession(): Boolean {
        if (AdminSession.isUnlocked()) {
            AdminSession.extend()
            return true
        }
        message = UiMessage(context.getString(R.string.mgmtid_error_auth), isError = true)
        return false
    }

    /**
     * Records refusals once each. A refusal means the device is running with its
     * management transport unexempted, which is worth an audit entry whether or
     * not the operator did anything about it.
     */
    suspend fun auditRefusals(loaded: List<ManagementIdentityRow>) {
        val refusals = refusalsToAudit(loaded, auditedRefusals)
        if (refusals.isEmpty()) {
            return
        }
        auditedRefusals = auditedRefusals + refusals.map { managementAuditKeyOf(it) }
        val app = context.applicationContext
        withContext(Dispatchers.IO) {
            refusals.forEach { row ->
                AuditLog.append(
                    app,
                    app.getString(
                        R.string.mgmtid_audit_refused,
                        row.packageName.ltrIsolated(),
                        row.status.verdict().name.ltrIsolated(),
                    ),
                )
            }
        }
    }

    LaunchedEffect(Unit) {
        loading = true
        val app = context.applicationContext
        val loaded = withContext(Dispatchers.IO) { readManagementIdentityRows(app) }
        rows = loaded
        loading = false
        auditRefusals(loaded)
    }

    /**
     * Writes one package's approved certificates and re-reads the device.
     *
     * The audit entry is written after the re-read and carries the verdict that
     * came back, so the log records what the change actually produced rather than
     * what it was expected to produce.
     */
    fun write(
        row: ManagementIdentityRow,
        computePins: () -> Set<String>,
        resultTemplate: Int,
        auditTemplate: Int,
    ) {
        if (working || !requireSession()) {
            return
        }
        // The pin set is built by the same guard the store write applies, and a
        // value it refuses is reported instead of thrown: a screen that crashes
        // on a bad digest tells the operator nothing about what was stored.
        val pins = try {
            computePins()
        } catch (exception: IllegalArgumentException) {
            message = UiMessage(
                context.getString(
                    R.string.mgmtid_result_write_failed,
                    exception.javaClass.simpleName.bidiIsolated(),
                ),
                isError = true,
            )
            return
        }
        working = true
        message = null
        coroutineScope.launch {
            val app = context.applicationContext
            val outcome = withContext(Dispatchers.IO) {
                writeManagementPins(app, row.packageName, pins)
            }
            working = false
            val updated = outcome.rows
            if (updated == null) {
                message = UiMessage(
                    context.getString(
                        R.string.mgmtid_result_write_failed,
                        outcome.failure.bidiIsolated(),
                    ),
                    isError = true,
                )
                return@launch
            }
            rows = updated
            val after = updated.firstOrNull { it.packageName == row.packageName }
            val identity = context.getString(labelOf(after?.state ?: row.state))
            withContext(Dispatchers.IO) {
                AuditLog.append(
                    app,
                    app.getString(
                        auditTemplate,
                        row.packageName.ltrIsolated(),
                        (after?.status?.verdict()?.name ?: row.status.verdict().name).ltrIsolated(),
                    ),
                )
            }
            // The tone comes from the re-read, not from the write having
            // returned. A well-formed but wrong digest is stored successfully
            // and leaves the package refused, which is the state that will
            // withhold management privilege at the next apply — it must not be
            // announced in the same neutral line as a success.
            message = UiMessage(
                text = context.getString(resultTemplate, identity),
                isError = after?.status?.refused() ?: true,
            )
            auditRefusals(updated)
        }
    }

    LockdownScreen(
        title = stringResource(R.string.mgmtid_title),
        subtitle = stringResource(R.string.mgmtid_subtitle),
    ) {
        val worst = worstSeverityOf(rows)
        PolicyStatusCard(
            tone = toneOf(worst),
            headline = stringResource(summaryOf(worst)),
            facts = emptyList(),
            detail = stringResource(R.string.mgmtid_apply_note),
        )

        Spacer(Modifier.height(16.dp))
        MessageBanner(message)

        Spacer(Modifier.height(20.dp))
        // Stated before the action, not after it: an operator who pins a signer
        // from a device that is already compromised makes the compromise
        // permanent, and that is not something to learn from a result banner.
        SectionCard(title = stringResource(R.string.mgmtid_section_caution)) {
            Text(
                text = stringResource(R.string.mgmtid_caution_body),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(16.dp),
            )
        }

        if (loading) {
            Spacer(Modifier.height(20.dp))
            Text(
                text = stringResource(R.string.mgmtid_loading),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        rows.forEach { row ->
            Spacer(Modifier.height(20.dp))
            ManagementIdentityCard(
                row = row,
                enabled = !working,
                onPinInstalled = { pendingPin = row },
                onAddManual = { manualEntryFor = row },
                onRemove = { digest -> pendingRemoval = PendingRemoval(row, digest) },
            )
        }

        Spacer(Modifier.height(28.dp))
        SecondaryAction(text = stringResource(R.string.action_back), onClick = onBack)
    }

    pendingPin?.let { row ->
        ConfirmPinDialog(
            row = row,
            onConfirm = {
                pendingPin = null
                write(
                    row = row,
                    computePins = {
                        ManagementIdentityInspector.pinsAfterAdding(
                            row.status.pinnedCertificateSha256(),
                            row.pinnableObservedDigests,
                        )
                    },
                    resultTemplate = R.string.mgmtid_result_pinned,
                    auditTemplate = R.string.mgmtid_audit_pin_added,
                )
            },
            onDismiss = { pendingPin = null },
        )
    }

    pendingRemoval?.let { removal ->
        ConfirmRemoveDialog(
            onConfirm = {
                pendingRemoval = null
                write(
                    row = removal.row,
                    computePins = {
                        ManagementIdentityInspector.pinsAfterRemoving(
                            removal.row.status.pinnedCertificateSha256(),
                            removal.digest,
                        )
                    },
                    resultTemplate = R.string.mgmtid_result_removed,
                    auditTemplate = R.string.mgmtid_audit_pin_removed,
                )
            },
            onDismiss = { pendingRemoval = null },
        )
    }

    manualEntryFor?.let { row ->
        ManualDigestDialog(
            row = row,
            onConfirm = { digest ->
                manualEntryFor = null
                write(
                    row = row,
                    computePins = {
                        ManagementIdentityInspector.pinsAfterAdding(
                            row.status.pinnedCertificateSha256(),
                            listOf(digest),
                        )
                    },
                    resultTemplate = R.string.mgmtid_result_pinned,
                    auditTemplate = R.string.mgmtid_audit_pin_added,
                )
            },
            onDismiss = { manualEntryFor = null },
        )
    }
}

/**
 * One management package: what the platform reported, what was approved, and the
 * verdict that follows from the two.
 *
 * The evidence is above the verdict on purpose. The verdict is a conclusion, and
 * an operator deciding whether to pin needs to be able to check it.
 */
@Composable
private fun ManagementIdentityCard(
    row: ManagementIdentityRow,
    enabled: Boolean,
    onPinInstalled: () -> Unit,
    onAddManual: () -> Unit,
    onRemove: (String) -> Unit,
) {
    SectionCard(title = row.packageName.ltrIsolated()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = stringResource(
                    if (row.installed) R.string.mgmtid_row_installed else R.string.mgmtid_row_not_installed
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(10.dp))
            Text(
                text = stringResource(R.string.mgmtid_identity_line, stringResource(labelOf(row.state))),
                style = MaterialTheme.typography.bodyLarge,
                color = if (row.severity == ManagementIdentitySeverity.REFUSED) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.onSurface
                },
            )
            Spacer(Modifier.height(6.dp))
            Text(
                text = stringResource(detailOf(row.state)),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Spacer(Modifier.height(16.dp))
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            Spacer(Modifier.height(12.dp))
            Text(
                text = stringResource(R.string.mgmtid_observed_title),
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onSurface,
            )
            if (row.observedDigests.isEmpty()) {
                Text(
                    text = stringResource(R.string.mgmtid_observed_none),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                row.observedDigests.forEach { digest -> DigestText(digest) }
            }

            Spacer(Modifier.height(16.dp))
            Text(
                text = stringResource(R.string.mgmtid_pinned_title),
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onSurface,
            )
            if (row.pinnedDigests.isEmpty()) {
                Text(
                    text = stringResource(R.string.mgmtid_pinned_none),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                row.pinnedDigests.forEach { digest ->
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        // `weight` keeps the digest wrapping instead of pushing
                        // the action past the trailing edge; both are resolved
                        // against the layout direction, so the button sits on the
                        // trailing side in Hebrew as well as in English.
                        Column(modifier = Modifier.weight(1f)) { DigestText(digest) }
                        Spacer(Modifier.size(8.dp))
                        TextButton(onClick = { onRemove(digest) }, enabled = enabled) {
                            Text(stringResource(R.string.mgmtid_action_remove))
                        }
                    }
                }
            }

            Spacer(Modifier.height(12.dp))
            if (row.canPinInstalledSigner) {
                TextButton(onClick = onPinInstalled, enabled = enabled) {
                    Text(stringResource(R.string.mgmtid_action_pin_installed))
                }
            } else {
                // Why the action is absent, rather than a disabled control that
                // explains nothing.
                Text(
                    text = stringResource(pinUnavailableReasonOf(row)),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            TextButton(onClick = onAddManual, enabled = enabled) {
                Text(stringResource(R.string.mgmtid_action_add_manual))
            }
        }
    }
}

/**
 * A digest is Latin hex. It is isolated left-to-right so it keeps its own
 * direction inside a Hebrew page, and it is left-aligned within that isolate so
 * two digests can be compared character by character.
 */
@Composable
private fun DigestText(digest: String) {
    Text(
        text = digest.ltrIsolated(),
        style = MaterialTheme.typography.bodySmall.copy(
            textDirection = TextDirection.Ltr,
            textAlign = TextAlign.Left,
        ),
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 6.dp),
    )
}

/** Consequences first, then the choice. Nothing is written before this returns. */
@Composable
private fun ConfirmPinDialog(
    row: ManagementIdentityRow,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.mgmtid_confirm_pin_title)) },
        text = {
            Column {
                Text(
                    stringResource(
                        R.string.mgmtid_confirm_pin_body,
                        row.packageName.ltrIsolated(),
                    )
                )
                Spacer(Modifier.height(10.dp))
                row.pinnableObservedDigests.forEach { digest -> DigestText(digest) }
            }
        },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text(stringResource(R.string.mgmtid_confirm_action))
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
private fun ConfirmRemoveDialog(onConfirm: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.mgmtid_confirm_remove_title)) },
        text = { Text(stringResource(R.string.mgmtid_confirm_remove_body)) },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text(stringResource(R.string.mgmtid_confirm_action))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.action_cancel))
            }
        },
    )
}

/**
 * Manual entry of a digest an operator obtained out of band.
 *
 * The field is validated as it is typed and shows the normalized form that would
 * actually be stored, because the shape a vendor publishes and the shape the
 * store keeps are not the same and an operator should not have to trust that the
 * conversion happened.
 */
@Composable
private fun ManualDigestDialog(
    row: ManagementIdentityRow,
    onConfirm: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    var typed by remember { mutableStateOf("") }
    val pasted = pastedDigestOf(typed, row.status.pinnedCertificateSha256())
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.mgmtid_manual_title)) },
        text = {
            Column {
                Text(stringResource(R.string.mgmtid_manual_body))
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    value = typed,
                    onValueChange = { typed = it },
                    label = { Text(stringResource(R.string.mgmtid_manual_field)) },
                    singleLine = true,
                    isError = typed.isNotEmpty() && !pasted.usable,
                    shape = MaterialTheme.shapes.small,
                    // The content is Latin hex, and letting a right-to-left
                    // paragraph lay it out moves the caret to the far side of
                    // what is being typed. Same reasoning as the PIN field.
                    textStyle = LocalTextStyle.current.copy(
                        textDirection = TextDirection.Ltr,
                        textAlign = TextAlign.Left,
                    ),
                    modifier = Modifier.fillMaxWidth(),
                )
                if (typed.isNotEmpty() && !pasted.usable) {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        text = digestProblemMessage(pasted),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
                if (pasted.usable) {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        text = stringResource(R.string.mgmtid_manual_normalized),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    DigestText(pasted.normalized)
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(pasted.normalized) },
                enabled = pasted.usable,
            ) {
                Text(stringResource(R.string.mgmtid_manual_save))
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
private fun digestProblemMessage(pasted: PastedDigest): String = when (pasted.problem) {
    DigestProblem.EMPTY -> stringResource(R.string.mgmtid_error_empty)
    DigestProblem.NOT_HEXADECIMAL -> stringResource(R.string.mgmtid_error_not_hex)
    DigestProblem.WRONG_LENGTH -> stringResource(R.string.mgmtid_error_length, pasted.length)
    DigestProblem.ALREADY_PINNED -> stringResource(R.string.mgmtid_error_already_pinned)
    DigestProblem.NONE -> ""
}

// ------------------------------------------------------------------- labels

/** The identity line. Exhaustive: a state added without wording will not compile. */
private fun labelOf(state: ManagementIdentityState): Int = when (state) {
    ManagementIdentityState.PROVEN -> R.string.mgmtid_state_proven
    ManagementIdentityState.NAME_ONLY -> R.string.mgmtid_state_name_only
    ManagementIdentityState.SIGNER_MISMATCH -> R.string.mgmtid_state_mismatch
    ManagementIdentityState.SIGNER_UNREADABLE -> R.string.mgmtid_state_unreadable
    ManagementIdentityState.NOT_INSTALLED -> R.string.mgmtid_state_not_installed
}

/** What the state means for the device, in the operator's terms. */
private fun detailOf(state: ManagementIdentityState): Int = when (state) {
    ManagementIdentityState.PROVEN -> R.string.mgmtid_detail_proven
    ManagementIdentityState.NAME_ONLY -> R.string.mgmtid_detail_name_only
    ManagementIdentityState.SIGNER_MISMATCH,
    ManagementIdentityState.SIGNER_UNREADABLE,
    -> R.string.mgmtid_detail_refused

    ManagementIdentityState.NOT_INSTALLED -> R.string.mgmtid_detail_not_installed
}

private fun summaryOf(severity: ManagementIdentitySeverity): Int = when (severity) {
    ManagementIdentitySeverity.REFUSED -> R.string.mgmtid_summary_refused
    ManagementIdentitySeverity.NOT_PROVEN -> R.string.mgmtid_summary_not_proven
    ManagementIdentitySeverity.ABSENT -> R.string.mgmtid_summary_absent
    ManagementIdentitySeverity.PROVEN -> R.string.mgmtid_summary_proven
}

private fun toneOf(severity: ManagementIdentitySeverity): StatusTone = when (severity) {
    ManagementIdentitySeverity.REFUSED -> StatusTone.FAILED
    // "Trusted by name only" and "not installed" are both honest gaps rather than
    // faults, and neither may be shown in the tone that means verified.
    ManagementIdentitySeverity.NOT_PROVEN, ManagementIdentitySeverity.ABSENT -> StatusTone.INACTIVE
    ManagementIdentitySeverity.PROVEN -> StatusTone.VERIFIED
}

private fun pinUnavailableReasonOf(row: ManagementIdentityRow): Int = when {
    !row.installed -> R.string.mgmtid_pin_unavailable_absent
    row.observedDigests.isEmpty() -> R.string.mgmtid_pin_unavailable_no_signer
    else -> R.string.mgmtid_pin_unavailable_already
}

// ------------------------------------------------------------------- device

/**
 * Reads every management record against this device.
 *
 * Touches `PackageManager`, so callers run it on [Dispatchers.IO].
 */
private fun readManagementIdentityRows(context: Context): List<ManagementIdentityRow> =
    managementIdentityRows(
        ManagementIdentityInspector.inspect(
            AllowedAppsStore.getManagementCertificatePins(context),
            InstalledSignerSource(context.packageManager),
        )
    )

/**
 * Stores one package's approved certificates and re-reads the device.
 *
 * A failed write reports the exception class rather than a generic apology: the
 * operator needs to know that nothing was stored, and support needs to know what
 * refused.
 */
private fun writeManagementPins(
    context: Context,
    packageName: String,
    pins: Set<String>,
): WriteOutcome = try {
    AllowedAppsStore.setManagementCertificatePins(context, packageName, pins)
    WriteOutcome(readManagementIdentityRows(context), "")
} catch (exception: RuntimeException) {
    WriteOutcome(null, exception.javaClass.simpleName)
}

/**
 * The production [ManagementIdentityInspector.SignerSource]: a thin
 * `PackageManager` adapter and nothing else, so every decision above it stays
 * JVM-testable.
 */
private class InstalledSignerSource(
    private val packageManager: PackageManager,
) : ManagementIdentityInspector.SignerSource {

    override fun isInstalled(packageName: String): Boolean = try {
        packageInfo(packageManager, packageName, 0)
        true
    } catch (ignored: PackageManager.NameNotFoundException) {
        false
    }

    override fun signingCertificateSha256(packageName: String): Set<String> =
        signerDigests(packageManager, packageName)
}

/**
 * Every signing certificate the platform reports, as lower-case hex SHA-256.
 *
 * Deliberately mirrors `LockdownPolicyController.signingCertificateDigests`,
 * including reading *all* signers rather than the first: a package signed by
 * several certificates matches when any one of them is approved, and showing an
 * operator one digest out of several would have them pin an incomplete set.
 *
 * An unreadable signer returns the empty set, which a pinned record treats as
 * `UNKNOWN_SIGNER` rather than as a pass.
 */
private fun signerDigests(packageManager: PackageManager, packageName: String): Set<String> = try {
    val signatures: Array<Signature>? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        val info = packageInfo(
            packageManager,
            packageName,
            PackageManager.GET_SIGNING_CERTIFICATES,
        )
        info.signingInfo?.let {
            if (it.hasMultipleSigners()) it.apkContentsSigners else it.signingCertificateHistory
        }
    } else {
        @Suppress("DEPRECATION")
        packageInfo(packageManager, packageName, PackageManager.GET_SIGNATURES).signatures
    }
    if (signatures == null) {
        emptySet()
    } else {
        val sha256 = MessageDigest.getInstance("SHA-256")
        signatures.mapTo(LinkedHashSet<String>()) { signature ->
            sha256.digest(signature.toByteArray())
                .joinToString("") { byte -> "%02x".format(Locale.ROOT, byte) }
        }
    }
} catch (ignored: PackageManager.NameNotFoundException) {
    emptySet()
} catch (ignored: NoSuchAlgorithmException) {
    emptySet()
} catch (ignored: RuntimeException) {
    emptySet()
}

private fun packageInfo(
    packageManager: PackageManager,
    packageName: String,
    flags: Int,
): PackageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
    packageManager.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags.toLong()))
} else {
    @Suppress("DEPRECATION")
    packageManager.getPackageInfo(packageName, flags)
}
