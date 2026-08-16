package com.example.lockdowndpc.ui

import android.content.Context
import android.content.pm.ApplicationInfo
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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.example.lockdowndpc.R
import com.example.lockdowndpc.maintenance.MaintenancePlan
import com.example.lockdowndpc.maintenance.MaintenanceStore
import com.example.lockdowndpc.policy.AllowedAppsStore
import com.example.lockdowndpc.policy.AuditLog
import com.example.lockdowndpc.policy.LockdownPolicyController
import com.example.lockdowndpc.policy.PlayStoreCompatibility
import com.example.lockdowndpc.policy.PlayStoreCompatibilityStore
import com.example.lockdowndpc.policy.PolicyReconciliationCoordinator
import com.example.lockdowndpc.policy.SystemPolicyControl
import com.example.lockdowndpc.policy.SystemPolicyLabels
import com.example.lockdowndpc.policy.SystemPolicyOutcome
import com.example.lockdowndpc.policy.SystemPolicyProfile
import com.example.lockdowndpc.policy.SystemPolicyStore
import com.example.lockdowndpc.security.AdminSession
import com.example.lockdowndpc.ui.theme.LockdownTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The authenticated system policy console.
 *
 * <p>Three rules shape this screen, all of them from the security model rather
 * than from taste:
 *
 * 1. It is reachable only inside a live administrator session, and it abandons
 *    itself the moment that session lapses — including on resume, exactly like
 *    [AllowedAppsActivity].
 * 2. A switch never reports enforcement. Each row shows the last *verified*
 *    outcome underneath, and flipping a switch marks that verification stale, so
 *    a saved choice reads as "saved, not verified yet" until an apply pass
 *    confirms it against the platform.
 * 3. Nothing is written until the operator confirms a dialog that says what the
 *    control does to the device in front of them.
 *
 * `AppCompatActivity` is the base class for the same localization reason as the
 * other console screens: below API 33 it is what applies the persisted display
 * language.
 */
class SystemPolicyActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!AdminSession.isUnlocked()) {
            finish()
            return
        }
        // This screen names the device recovery path and the exact restrictions
        // in force, so it follows the console's fail-closed screenshot rule.
        if (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE == 0) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.light(Color.TRANSPARENT, SYSTEM_BAR_DARK_SCRIM),
            navigationBarStyle = SystemBarStyle.light(Color.TRANSPARENT, SYSTEM_BAR_DARK_SCRIM),
        )
        setTitle(R.string.system_policy_title)
        setContent {
            LockdownTheme {
                SystemPolicyScreen(onBack = { finish() })
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

/** One pending switch change, held until the operator confirms it. */
private data class PendingChange(
    val control: SystemPolicyControl,
    val requested: Boolean,
)

/**
 * The controls a live maintenance window has legitimately relaxed.
 *
 * Read here for the same reason the policy engine reads it: a control an
 * authenticated, bounded window deliberately opened is not a control the device
 * refused to enforce, and the Google Play compatibility row must not report the
 * first as if it were the second.
 */
private fun relaxedByMaintenance(context: Context): Set<SystemPolicyControl> {
    val window = MaintenanceStore.liveWindow(context) ?: return emptySet()
    return MaintenancePlan.forWindow(
        SystemPolicyStore.effectiveProfile(context),
        SystemPolicyStore.baseChoices(context),
        window,
    ).relaxed()
}

/**
 * What the compatibility exception resolves to from the evidence on file.
 *
 * Verified outcomes, never the saved switch: an opt-in whose installation lock
 * this device has not confirmed is reported as exactly that, and the policy
 * engine keeps the Store hidden until it is.
 */
private fun playCompatibilityStateOf(context: Context): PlayStoreCompatibility.State =
    PlayStoreCompatibility.evaluateOutcomes(
        PlayStoreCompatibilityStore.isEnabled(context),
        relaxedByMaintenance(context),
        PlayStoreCompatibility.REQUIRED_INSTALL_CONTROLS.associateWith { control ->
            SystemPolicyStore.lastOutcome(context, control)
        },
    )

private fun playCompatibilityStatusRes(state: PlayStoreCompatibility.State): Int = when (state) {
    PlayStoreCompatibility.State.STRICT -> R.string.system_policy_play_compat_state_strict
    PlayStoreCompatibility.State.ACTIVE -> R.string.system_policy_play_compat_state_active
    PlayStoreCompatibility.State.RELAXED_BY_MAINTENANCE ->
        R.string.system_policy_play_compat_state_maintenance
    PlayStoreCompatibility.State.WITHHELD_DURING_MAINTENANCE ->
        R.string.system_policy_play_compat_state_withheld
    PlayStoreCompatibility.State.INSTALL_LOCK_UNVERIFIED ->
        R.string.system_policy_play_compat_state_unverified
}

@Composable
private fun SystemPolicyScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()

    // Bumped after every write so the rows re-read the store rather than caching
    // a copy that could drift from what the device was actually told.
    var revision by remember { mutableIntStateOf(0) }
    var pending by remember { mutableStateOf<PendingChange?>(null) }
    var pendingPlayCompatibility by remember { mutableStateOf<Boolean?>(null) }
    var working by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<UiMessage?>(null) }

    val profile = remember(revision) { SystemPolicyStore.effectiveProfile(context) }
    val protectionEnabled = remember(revision) { AllowedAppsStore.isProtectionEnabled(context) }
    val playCompatibilityRequested =
        remember(revision) { PlayStoreCompatibilityStore.isEnabled(context) }
    val playCompatibilityState = remember(revision) { playCompatibilityStateOf(context) }

    fun requireSession(): Boolean {
        if (AdminSession.isUnlocked()) {
            AdminSession.extend()
            return true
        }
        message = UiMessage(context.getString(R.string.system_policy_error_auth), isError = true)
        return false
    }

    fun commit(change: PendingChange) {
        if (!requireSession()) {
            return
        }
        SystemPolicyStore.setRequested(context, change.control, change.requested)
        // The previous verdict describes a policy that is no longer the one being
        // asked for, so it stops being evidence the instant the choice changes.
        SystemPolicyStore.invalidateVerification(context, change.control)
        AuditLog.append(
            context,
            context.getString(
                R.string.audit_system_policy_changed,
                "${change.control.storageKey()}=${change.requested}".bidiIsolated(),
            ),
        )
        revision++
        message = UiMessage(
            context.getString(
                if (protectionEnabled) {
                    R.string.system_policy_pending_note
                } else {
                    R.string.system_policy_paused_note
                }
            ),
            isError = false,
        )
    }

    /**
     * Records the Google Play compatibility decision.
     *
     * The store also drops the stale verification of the controls the mode pins
     * on, so nothing here can leave the rows asserting an enforcement that no
     * longer describes the policy being asked for.
     */
    fun commitPlayCompatibility(requested: Boolean) {
        if (!requireSession()) {
            return
        }
        PlayStoreCompatibilityStore.setEnabled(context, requested)
        AuditLog.append(
            context,
            context.getString(
                R.string.audit_play_compatibility_changed,
                "play_store_compatibility=$requested".bidiIsolated(),
            ),
        )
        revision++
        message = UiMessage(
            context.getString(
                if (protectionEnabled) {
                    R.string.system_policy_pending_note
                } else {
                    R.string.system_policy_paused_note
                }
            ),
            isError = false,
        )
    }

    fun applyNow() {
        if (working || !requireSession()) {
            return
        }
        working = true
        message = null
        coroutineScope.launch {
            val result = withContext(Dispatchers.IO) {
                PolicyReconciliationCoordinator.callOnPolicyThread {
                    LockdownPolicyController.apply(context.applicationContext)
                }
            }
            working = false
            revision++
            message = when {
                !result.deviceOwner() -> UiMessage(
                    context.getString(R.string.not_device_owner),
                    isError = true,
                )

                !result.applied() -> {
                    // Policy detail mixes prose with Latin restriction keys, so it
                    // is isolated before being embedded in a localized sentence.
                    val detail = result.errors().firstOrNull()
                        ?: context.getString(R.string.error_unknown)
                    UiMessage(
                        context.getString(
                            R.string.system_policy_applied_failed,
                            detail.bidiIsolated(),
                        ),
                        isError = true,
                    )
                }

                else -> {
                    AuditLog.append(
                        context,
                        context.getString(R.string.audit_system_policy_applied),
                    )
                    UiMessage(
                        context.getString(R.string.system_policy_applied_ok),
                        isError = false,
                    )
                }
            }
        }
    }

    LockdownScreen(
        title = stringResource(R.string.system_policy_title),
        subtitle = stringResource(R.string.system_policy_subtitle),
    ) {
        PolicyStatusCard(
            tone = if (profile == SystemPolicyProfile.PRODUCTION) {
                StatusTone.VERIFIED
            } else {
                StatusTone.INACTIVE
            },
            headline = stringResource(R.string.system_policy_profile_row),
            facts = emptyList(),
            detail = stringResource(SystemPolicyLabels.profile(profile)),
        )

        if (!protectionEnabled) {
            Spacer(Modifier.height(16.dp))
            MessageBanner(
                UiMessage(stringResource(R.string.system_policy_paused_note), isError = false)
            )
        }

        Spacer(Modifier.height(16.dp))
        MessageBanner(message)

        SystemPolicyLabels.Section.values().forEach { section ->
            Spacer(Modifier.height(20.dp))
            SectionCard(title = stringResource(section.titleRes())) {
                section.controls().forEachIndexed { index, control ->
                    key(revision, control) {
                        SystemPolicyControlRow(
                            control = control,
                            requested = SystemPolicyStore.isRequested(context, control),
                            outcome = SystemPolicyStore.lastOutcome(context, control),
                            detail = SystemPolicyStore.lastDetail(context, control),
                            supported = control.supportedOn(Build.VERSION.SDK_INT),
                            enabled = !working,
                            lockedByPlayCompatibility = PlayStoreCompatibility.locksControl(
                                control,
                                playCompatibilityRequested,
                            ),
                            showDivider = index > 0,
                            onToggle = { requested ->
                                pending = PendingChange(control, requested)
                            },
                        )
                    }
                }
            }
        }

        Spacer(Modifier.height(20.dp))
        SectionCard(title = stringResource(R.string.system_policy_section_play_compatibility)) {
            key(revision) {
                PlayCompatibilityRow(
                    requested = playCompatibilityRequested,
                    state = playCompatibilityState,
                    enabled = !working,
                    onToggle = { requested -> pendingPlayCompatibility = requested },
                )
            }
        }

        Spacer(Modifier.height(28.dp))
        PrimaryAction(
            text = stringResource(
                if (working) R.string.system_policy_applying else R.string.system_policy_apply
            ),
            onClick = { applyNow() },
            enabled = !working && protectionEnabled,
        )
        Spacer(Modifier.height(12.dp))
        SecondaryAction(text = stringResource(R.string.action_back), onClick = onBack)
    }

    pending?.let { change ->
        SystemPolicyConfirmDialog(
            change = change,
            onConfirm = {
                pending = null
                commit(change)
            },
            onDismiss = { pending = null },
        )
    }

    pendingPlayCompatibility?.let { requested ->
        PlayCompatibilityConfirmDialog(
            requested = requested,
            onConfirm = {
                pendingPlayCompatibility = null
                commitPlayCompatibility(requested)
            },
            onDismiss = { pendingPlayCompatibility = null },
        )
    }
}

/**
 * The Google Play compatibility exception: what it does, what this device
 * confirmed, and a switch.
 *
 * The boundary paragraph is always on screen rather than only inside the
 * confirmation dialog. An operator who inherits a configured device has to be
 * able to read why an application store is visible on a protected phone without
 * touching the switch to find out.
 */
@Composable
private fun PlayCompatibilityRow(
    requested: Boolean,
    state: PlayStoreCompatibility.State,
    enabled: Boolean,
    onToggle: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 64.dp)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = stringResource(R.string.system_policy_play_compat_row),
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                text = stringResource(
                    R.string.system_policy_status_line,
                    stringResource(playCompatibilityStatusRes(state)),
                ),
                style = MaterialTheme.typography.bodySmall,
                color = if (state == PlayStoreCompatibility.State.INSTALL_LOCK_UNVERIFIED) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
            )
        }
        Spacer(Modifier.size(16.dp))
        Switch(
            checked = requested,
            onCheckedChange = { onToggle(it) },
            enabled = enabled,
        )
    }
    Text(
        text = stringResource(R.string.system_policy_play_compat_body),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
    )
}

/** The price of the exception, stated before anything is written. */
@Composable
private fun PlayCompatibilityConfirmDialog(
    requested: Boolean,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                stringResource(
                    if (requested) {
                        R.string.system_policy_play_compat_confirm_enable_title
                    } else {
                        R.string.system_policy_play_compat_confirm_disable_title
                    }
                )
            )
        },
        text = {
            Text(
                stringResource(
                    if (requested) {
                        R.string.system_policy_play_compat_confirm_enable_body
                    } else {
                        R.string.system_policy_play_compat_confirm_disable_body
                    }
                )
            )
        },
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

/**
 * One control: what it is, what the device confirmed, and a switch.
 *
 * The status line is deliberately below the title and always present. It is the
 * only thing on this screen that is evidence; the switch beside it is an intent.
 */
@Composable
private fun SystemPolicyControlRow(
    control: SystemPolicyControl,
    requested: Boolean,
    outcome: SystemPolicyOutcome,
    detail: String,
    supported: Boolean,
    enabled: Boolean,
    lockedByPlayCompatibility: Boolean,
    showDivider: Boolean,
    onToggle: (Boolean) -> Unit,
) {
    if (showDivider) {
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 64.dp)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // `weight` keeps the text wrapping instead of pushing the switch past the
        // trailing edge; both are resolved against the layout direction, so the
        // switch sits on the trailing side in Hebrew as well as in English.
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = stringResource(SystemPolicyLabels.title(control)),
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                text = stringResource(
                    R.string.system_policy_status_line,
                    stringResource(SystemPolicyLabels.outcome(outcome)),
                ),
                style = MaterialTheme.typography.bodySmall,
                color = if (outcome == SystemPolicyOutcome.FAILED) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
            )
            if (detail.isNotBlank()) {
                Text(
                    // Restriction keys are Latin identifiers inside a localized
                    // sentence, so each one is isolated for bidirectional text.
                    text = stringResource(R.string.system_policy_detail, detail.bidiIsolated()),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (lockedByPlayCompatibility) {
                Text(
                    text = stringResource(R.string.system_policy_play_compat_locked_control),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        Spacer(Modifier.size(16.dp))
        Switch(
            checked = requested,
            onCheckedChange = { onToggle(it) },
            // An unsupported control can still be requested — the request is kept
            // so the device enforces it after an OS upgrade — but the row says
            // plainly that nothing was sent to this release. A control the Google
            // Play compatibility opt-in pins on is different: the next pass would
            // put it straight back, so the switch is disabled and says why rather
            // than accepting a change that cannot survive.
            enabled = enabled && !lockedByPlayCompatibility,
        )
    }
    if (!supported) {
        Text(
            text = stringResource(R.string.system_policy_status_unsupported),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
        )
    }
}

/** Consequences first, then the choice. Nothing is written before this returns. */
@Composable
private fun SystemPolicyConfirmDialog(
    change: PendingChange,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                stringResource(
                    if (change.requested) {
                        R.string.system_policy_confirm_enable_title
                    } else {
                        R.string.system_policy_confirm_disable_title
                    }
                )
            )
        },
        text = {
            Column {
                Text(stringResource(SystemPolicyLabels.title(change.control)))
                Spacer(Modifier.height(10.dp))
                Text(
                    stringResource(
                        if (change.requested) {
                            SystemPolicyLabels.consequence(change.control)
                        } else {
                            R.string.system_policy_confirm_disable_body
                        }
                    )
                )
            }
        },
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
