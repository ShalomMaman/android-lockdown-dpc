package com.example.lockdowndpc.ui

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import android.text.format.DateFormat
import android.view.WindowManager
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.annotation.StringRes
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
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
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.lockdowndpc.R
import com.example.lockdowndpc.admin.LockdownAdminReceiver
import com.example.lockdowndpc.maintenance.MaintenanceCapability
import com.example.lockdowndpc.maintenance.MaintenanceCoordinator
import com.example.lockdowndpc.maintenance.MaintenanceCoordinator.MaintenanceOutcome
import com.example.lockdowndpc.maintenance.MaintenanceGuard
import com.example.lockdowndpc.maintenance.MaintenanceLabels
import com.example.lockdowndpc.maintenance.MaintenancePlan
import com.example.lockdowndpc.maintenance.MaintenanceStateMachine.CloseReason
import com.example.lockdowndpc.maintenance.MaintenanceStateMachine.MaintenanceState
import com.example.lockdowndpc.maintenance.MaintenanceStateMachine.OpenRequest
import com.example.lockdowndpc.maintenance.MaintenanceStore
import com.example.lockdowndpc.maintenance.MaintenanceWindow
import com.example.lockdowndpc.policy.AllowedAppsStore
import com.example.lockdowndpc.policy.AuditLog
import com.example.lockdowndpc.policy.SystemPolicyControl
import com.example.lockdowndpc.policy.SystemPolicyDeviceGateway
import com.example.lockdowndpc.policy.SystemPolicyLabels
import com.example.lockdowndpc.policy.PolicyReconciliationCoordinator
import com.example.lockdowndpc.policy.SystemPolicyStore
import com.example.lockdowndpc.security.AdminSession
import com.example.lockdowndpc.ui.theme.LockdownTheme
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import java.util.Date
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import java.util.EnumSet

/**
 * The authenticated timed maintenance console.
 *
 * Maintenance is the one feature in this console whose purpose is to take
 * protection *off* a device, so the screen is built around four rules that come
 * from the security model rather than from taste:
 *
 * 1. It is reachable only inside a live administrator session and abandons itself
 *    the moment that session lapses — including on resume, exactly like
 *    [SystemPolicyActivity]. A lapsed session is refused here; it is never
 *    answered with a PIN prompt that then completes the request that was already
 *    in flight.
 * 2. Nothing is opened by default. Every capability is chosen by name, and the
 *    break-glass capability — developer options and ADB — sits in its own card
 *    and needs its own confirmation step that says what a privileged transport is
 *    and that it must not be left open.
 * 3. A window is reported as open only after [MaintenanceCoordinator] applied it
 *    and read it back. A failed open is a failure on screen, carrying the
 *    summaries the device reported, and never a window that looks open.
 * 4. Closing states whether the previous policy was restored *and verified*. A
 *    restore that could not be proved is a standing error card with the recovery
 *    instruction, because the device may still be relaxed.
 *
 * `AppCompatActivity` is the base class for the same localization reason as the
 * other console screens: below API 33 it is what applies the persisted display
 * language.
 */
class MaintenanceActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!AdminSession.isUnlocked()) {
            finish()
            return
        }
        // This screen names the restrictions currently withdrawn from the device,
        // which is exactly what someone photographing a console would want, so it
        // follows the fail-closed screenshot rule.
        if (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE == 0) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.light(Color.TRANSPARENT, SYSTEM_BAR_DARK_SCRIM),
            navigationBarStyle = SystemBarStyle.light(Color.TRANSPARENT, SYSTEM_BAR_DARK_SCRIM),
        )
        setTitle(R.string.maint_title)
        setContent {
            LockdownTheme {
                MaintenanceScreen(onBack = { finish() })
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

// ------------------------------------------------------------------ the screen

@Composable
private fun MaintenanceScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()

    var loading by remember { mutableStateOf(true) }
    var working by remember { mutableStateOf(false) }
    var snapshot by remember { mutableStateOf(MaintenanceSnapshot.unknown()) }
    var draft by remember { mutableStateOf(MaintenanceDraft()) }
    var blocked by remember { mutableStateOf<OpenBlocker?>(null) }
    // Read from the monotonic clock, the same reading the window itself is judged
    // against. A calendar clock that moves must not change what the remaining
    // line says.
    var elapsedNow by remember { mutableStateOf(SystemClock.elapsedRealtime()) }

    /** Every device call goes through here, so persistence and audit cannot be skipped. */
    fun perform(action: (Context) -> MaintenanceSnapshot) {
        if (working) {
            return
        }
        working = true
        blocked = null
        coroutineScope.launch {
            val app = context.applicationContext
            val result = onPolicyThread { action(app) }
            working = false
            loading = false
            snapshot = result
            elapsedNow = SystemClock.elapsedRealtime()
            // The selection is discarded after every completed action, including a
            // failed one. Nothing this screen offers may arrive pre-selected, least
            // of all a break-glass capability left over from the previous window.
            draft = MaintenanceDraft()
        }
    }

    LaunchedEffect(Unit) {
        val app = context.applicationContext
        val result = onPolicyThread { loadMaintenance(app) }
        snapshot = result
        elapsedNow = SystemClock.elapsedRealtime()
        loading = false
    }

    // The countdown, and the pass that ends an expired window. Expiry is not a
    // display concern: when the time is up the coordinator restores the base
    // policy and reads it back, and the screen reports what came of that.
    LaunchedEffect(snapshot.window) {
        val current = snapshot.window ?: return@LaunchedEffect
        while (true) {
            elapsedNow = SystemClock.elapsedRealtime()
            if (current.remainingMillis(elapsedNow) <= 0L) {
                perform { app -> closeMaintenance(app, CloseReason.EXPIRED) }
                return@LaunchedEffect
            }
            delay(1_000L)
        }
    }

    fun proceed() {
        val blocker = openBlockerOf(
            draft = draft,
            // Checked here as well as in the state machine so a lapsed session is
            // refused on this screen instead of being carried into a request.
            adminAuthenticated = AdminSession.isUnlocked(),
            deviceOwner = snapshot.deviceOwner,
            windowOpen = snapshot.window != null,
            working = working,
        )
        if (blocker != OpenBlocker.NONE) {
            blocked = blocker
            return
        }
        AdminSession.extend()
        blocked = null
        if (draft.nextStep() != MaintenanceStep.READY) {
            // A confirmation is still owed. Nothing reaches the device until the
            // last one has been passed.
            draft = draft.advanced()
            return
        }
        val request = draft
        perform { app -> openMaintenance(app, request.capabilities, request.durationMillis) }
    }

    fun closeNow() {
        // Deliberately not gated on the administrator session: closing removes
        // privilege from the device, and refusing it to protect a screen would
        // leave a debugging transport open.
        if (!closeActionEnabled(snapshot.window != null, working)) {
            return
        }
        perform { app -> closeMaintenance(app, CloseReason.ADMINISTRATOR_CANCELLED) }
    }

    val window = snapshot.window
    LockdownScreen(
        title = stringResource(R.string.maint_title),
        subtitle = stringResource(R.string.maint_subtitle),
    ) {
        MaintenanceStatusCard(window, elapsedNow)

        if (!snapshot.deviceOwner) {
            Spacer(Modifier.height(16.dp))
            MessageBanner(UiMessage(stringResource(R.string.not_device_owner), isError = true))
        }

        snapshot.result?.let { result ->
            Spacer(Modifier.height(16.dp))
            MessageBanner(maintenanceResultMessage(result))
            if (result.kind.restoreOwed) {
                Spacer(Modifier.height(16.dp))
                RestoreFailedCard(result.failures)
            }
        }

        blocked?.let { blocker ->
            Spacer(Modifier.height(16.dp))
            MessageBanner(UiMessage(stringResource(openBlockerLabel(blocker)), isError = true))
        }

        if (loading) {
            Spacer(Modifier.height(20.dp))
            Text(
                text = stringResource(R.string.maint_loading),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else if (window != null) {
            OpenWindowSection(
                window = window,
                relaxed = snapshot.relaxed,
                residual = snapshot.residual,
                working = working,
                onCloseNow = { closeNow() },
            )
        } else {
            when (draft.step) {
                MaintenanceStep.CONFIRM -> ConfirmSection(
                    draft = draft,
                    working = working,
                    onProceed = { proceed() },
                    onBack = { draft = draft.retreated() },
                )

                MaintenanceStep.CONFIRM_BREAK_GLASS -> BreakGlassSection(
                    working = working,
                    onProceed = { proceed() },
                    onBack = { draft = draft.retreated() },
                )

                // SELECT is the resting state, and it is also where READY lands:
                // the draft is discarded once a request has been made, so a
                // confirmed selection is never left standing to be re-sent.
                else -> SelectSection(
                    draft = draft,
                    working = working,
                    onCapability = { capability, selected ->
                        draft = draft.withCapability(capability, selected)
                        blocked = null
                    },
                    onDuration = { millis ->
                        draft = draft.withDuration(millis)
                        blocked = null
                    },
                    onProceed = { proceed() },
                )
            }
        }

        Spacer(Modifier.height(12.dp))
        SecondaryAction(text = stringResource(R.string.action_back), onClick = onBack)
    }
}

// ------------------------------------------------------------------- the cards

/** What this device is right now: closed, or open with the time that is left. */
@Composable
private fun MaintenanceStatusCard(window: MaintenanceWindow?, elapsedNow: Long) {
    val state = if (window == null) MaintenanceState.CLOSED else MaintenanceState.OPEN
    val facts = buildList {
        add(stringResource(R.string.maint_title) to stringResource(MaintenanceLabels.state(state)))
        if (window != null) {
            add(
                stringResource(R.string.maint_open_capabilities_label) to
                    capabilityNames(window.capabilities())
            )
            add(
                stringResource(R.string.maint_open_remaining_label) to
                    remainingText(window.remainingMillis(elapsedNow))
            )
        }
    }
    PolicyStatusCard(
        tone = when {
            window == null -> StatusTone.VERIFIED
            // A window holding a privileged transport is drawn as loudly as a
            // policy failure, because that is the state nobody may overlook.
            window.breakGlass() -> StatusTone.FAILED
            else -> StatusTone.APPLYING
        },
        headline = stringResource(
            if (window == null) {
                R.string.maint_card_closed_headline
            } else {
                R.string.maint_card_open_headline
            }
        ),
        facts = facts,
        detail = if (window == null) {
            stringResource(R.string.maint_card_closed_detail)
        } else {
            stringResource(
                R.string.maint_expected_close,
                formatClockTime(window.expectedCloseWallClock()),
            )
        },
    )
}

/** The open window: what is open, how long is left, and how to end it now. */
@Composable
private fun OpenWindowSection(
    window: MaintenanceWindow,
    relaxed: List<SystemPolicyControl>,
    residual: List<SystemPolicyControl>,
    working: Boolean,
    onCloseNow: () -> Unit,
) {
    Spacer(Modifier.height(24.dp))
    SectionCard(title = stringResource(R.string.maint_open_capabilities_label)) {
        window.capabilities().forEachIndexed { index, capability ->
            if (index > 0) {
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            }
            Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
                Text(
                    text = stringResource(MaintenanceLabels.title(capability)),
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                if (capability.breakGlass()) {
                    Text(
                        text = stringResource(R.string.maint_break_glass_badge),
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
                Text(
                    text = stringResource(MaintenanceLabels.consequence(capability)),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }

    Spacer(Modifier.height(16.dp))
    Text(
        text = windowLengthText(window.durationMillis()),
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Spacer(Modifier.height(4.dp))
    Text(
        text = stringResource(R.string.maint_expiry_estimate_note),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )

    Spacer(Modifier.height(12.dp))
    Text(
        text = if (relaxed.isEmpty()) {
            stringResource(R.string.maint_open_relaxed_none)
        } else {
            stringResource(R.string.maint_open_relaxed, controlNames(relaxed))
        },
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    if (residual.isNotEmpty()) {
        Spacer(Modifier.height(4.dp))
        Text(
            // Reported, never opened: a capability that is still blocked has to be
            // said out loud, or a technician watches an "open" window fail.
            text = stringResource(R.string.maint_open_residual, controlNames(residual)),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.error,
        )
    }

    Spacer(Modifier.height(28.dp))
    PrimaryAction(
        text = stringResource(
            if (working) R.string.maint_action_closing else R.string.maint_action_close_now
        ),
        onClick = onCloseNow,
        enabled = !working,
    )
}

/** Choosing capabilities and a duration. Nothing here starts selected. */
@Composable
private fun SelectSection(
    draft: MaintenanceDraft,
    working: Boolean,
    onCapability: (MaintenanceCapability, Boolean) -> Unit,
    onDuration: (Long) -> Unit,
    onProceed: () -> Unit,
) {
    Spacer(Modifier.height(24.dp))
    SectionCard(title = stringResource(R.string.maint_section_capabilities)) {
        standardCapabilities().forEachIndexed { index, capability ->
            if (index > 0) {
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            }
            CapabilityRow(
                capability = capability,
                selected = capability in draft.capabilities,
                enabled = !working,
                onSelect = { onCapability(capability, it) },
            )
        }
    }
    Spacer(Modifier.height(8.dp))
    Text(
        text = stringResource(R.string.maint_capabilities_note),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )

    // The break-glass capability lives in its own card with its own warning, so
    // it cannot be picked up as one more line in a list of ordinary features.
    Spacer(Modifier.height(24.dp))
    SectionCard(title = stringResource(R.string.maint_section_break_glass)) {
        Text(
            text = stringResource(R.string.maint_break_glass_note),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
        )
        breakGlassCapabilities().forEach { capability ->
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            CapabilityRow(
                capability = capability,
                selected = capability in draft.capabilities,
                enabled = !working,
                onSelect = { onCapability(capability, it) },
            )
        }
    }

    Spacer(Modifier.height(24.dp))
    SectionCard(title = stringResource(R.string.maint_section_duration)) {
        offeredDurations().forEachIndexed { index, millis ->
            if (index > 0) {
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            }
            DurationRow(
                millis = millis,
                selected = millis == draft.durationMillis,
                enabled = !working,
                onSelect = { onDuration(millis) },
            )
        }
    }
    Spacer(Modifier.height(8.dp))
    Text(
        text = stringResource(R.string.maint_expiry_estimate_note),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )

    Spacer(Modifier.height(28.dp))
    PrimaryAction(
        text = stringResource(
            if (working) R.string.maint_action_working else R.string.maint_action_review
        ),
        onClick = onProceed,
        enabled = !working,
    )
}

/** What is about to be opened, for how long, and until roughly when. */
@Composable
private fun ConfirmSection(
    draft: MaintenanceDraft,
    working: Boolean,
    onProceed: () -> Unit,
    onBack: () -> Unit,
) {
    Spacer(Modifier.height(24.dp))
    Text(
        text = stringResource(R.string.maint_confirm_title),
        style = MaterialTheme.typography.titleMedium,
        color = MaterialTheme.colorScheme.onSurface,
        modifier = Modifier.semantics { heading() },
    )
    Spacer(Modifier.height(8.dp))
    Text(
        text = stringResource(R.string.maint_confirm_subtitle),
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )

    Spacer(Modifier.height(16.dp))
    SectionCard(title = stringResource(R.string.maint_section_capabilities)) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = stringResource(
                    R.string.maint_confirm_capabilities,
                    capabilityNames(draft.capabilities),
                ),
                style = MaterialTheme.typography.bodyMedium,
            )
            Spacer(Modifier.height(8.dp))
            Text(
                text = stringResource(
                    R.string.maint_confirm_duration,
                    durationText(draft.durationMillis),
                ),
                style = MaterialTheme.typography.bodyMedium,
            )
            Spacer(Modifier.height(8.dp))
            Text(
                text = stringResource(
                    R.string.maint_expected_close,
                    formatClockTime(
                        previewCloseWallClock(System.currentTimeMillis(), draft.durationMillis)
                    ),
                ),
                style = MaterialTheme.typography.bodyMedium,
            )
            Spacer(Modifier.height(8.dp))
            Text(
                text = stringResource(R.string.maint_expiry_estimate_note),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }

    Spacer(Modifier.height(16.dp))
    Text(
        text = stringResource(R.string.maint_confirm_note),
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )

    Spacer(Modifier.height(28.dp))
    PrimaryAction(
        text = stringResource(
            when {
                working -> R.string.maint_action_working
                // The break-glass warning is still owed, so this button is not
                // allowed to be the one that opens anything.
                draft.breakGlass -> R.string.maint_action_continue
                else -> R.string.maint_action_open
            }
        ),
        onClick = onProceed,
        enabled = !working,
    )
    Spacer(Modifier.height(12.dp))
    SecondaryAction(text = stringResource(R.string.action_cancel), onClick = onBack)
}

/** The separate break-glass step: what the transport is, and what to do about it. */
@Composable
private fun BreakGlassSection(
    working: Boolean,
    onProceed: () -> Unit,
    onBack: () -> Unit,
) {
    Spacer(Modifier.height(24.dp))
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
                    text = stringResource(R.string.maint_break_glass_title),
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.semantics { heading() },
                )
            }
            Spacer(Modifier.height(12.dp))
            Text(
                text = stringResource(R.string.maint_break_glass_subtitle),
                style = MaterialTheme.typography.bodyMedium,
            )
            Spacer(Modifier.height(12.dp))
            Text(
                text = stringResource(R.string.maint_break_glass_warning),
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold,
            )
            Spacer(Modifier.height(12.dp))
            Text(
                text = stringResource(R.string.maint_break_glass_not_left_open),
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }

    Spacer(Modifier.height(28.dp))
    PrimaryAction(
        text = stringResource(
            if (working) R.string.maint_action_working else R.string.maint_break_glass_confirm
        ),
        onClick = onProceed,
        enabled = !working,
    )
    Spacer(Modifier.height(12.dp))
    SecondaryAction(text = stringResource(R.string.action_cancel), onClick = onBack)
}

/** The standing error state for a restore this device did not confirm. */
@Composable
private fun RestoreFailedCard(failures: List<String>) {
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
            Text(
                text = stringResource(R.string.maint_restore_failed_headline),
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.semantics { heading() },
            )
            Spacer(Modifier.height(12.dp))
            Text(
                text = stringResource(R.string.maint_restore_failed_recovery),
                style = MaterialTheme.typography.bodyMedium,
            )
            failures.forEach { failure ->
                Spacer(Modifier.height(8.dp))
                Text(
                    // Control summaries are Latin identifiers inside a localized
                    // sentence, so each one is isolated for bidirectional text.
                    text = stringResource(R.string.maint_failure_line, failure.bidiIsolated()),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}

// ------------------------------------------------------------------- the rows

@Composable
private fun CapabilityRow(
    capability: MaintenanceCapability,
    selected: Boolean,
    enabled: Boolean,
    onSelect: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 64.dp)
            .toggleable(
                value = selected,
                enabled = enabled,
                role = Role.Checkbox,
                onValueChange = onSelect,
            )
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // `weight` keeps the text wrapping instead of pushing the box past the
        // trailing edge; both are resolved against the layout direction, so the
        // box sits on the trailing side in Hebrew as well as in English.
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = stringResource(MaintenanceLabels.title(capability)),
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
            if (capability.breakGlass()) {
                Text(
                    text = stringResource(R.string.maint_break_glass_badge),
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            Text(
                text = stringResource(MaintenanceLabels.consequence(capability)),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Spacer(Modifier.size(16.dp))
        // The row owns the toggle semantics, so the box itself is decorative.
        Checkbox(checked = selected, onCheckedChange = null, enabled = enabled)
    }
}

@Composable
private fun DurationRow(
    millis: Long,
    selected: Boolean,
    enabled: Boolean,
    onSelect: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .selectable(
                selected = selected,
                enabled = enabled,
                role = Role.RadioButton,
                onClick = onSelect,
            )
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = durationText(millis),
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.weight(1f),
        )
        Spacer(Modifier.size(16.dp))
        RadioButton(selected = selected, onClick = null, enabled = enabled)
    }
}

// ---------------------------------------------------------------- the wording

/**
 * One offered duration, in the engine's own words.
 *
 * The minute count is passed for the fallback string only; the named durations
 * ignore it, which is what keeps a length chosen elsewhere readable instead of
 * blank.
 */
@Composable
private fun durationText(millis: Long): String = stringResource(
    MaintenanceLabels.duration(millis),
    MaintenanceLabels.durationMinutes(millis),
)

/** The remaining-time line, floored so it never claims time the window lacks. */
@Composable
private fun remainingText(remainingMillis: Long): String {
    val remaining = remainingTimeOf(remainingMillis)
    return when (remaining.shape) {
        RemainingShape.EXPIRED -> stringResource(R.string.maint_open_remaining_expired)
        RemainingShape.UNDER_ONE_MINUTE ->
            stringResource(R.string.maint_open_remaining_under_minute)

        RemainingShape.MINUTES ->
            stringResource(R.string.maint_open_remaining_minutes, remaining.minutes.toInt())

        RemainingShape.HOURS_AND_MINUTES -> stringResource(
            R.string.maint_open_remaining_hours,
            remaining.hours.toInt(),
            remaining.minutes.toInt(),
        )
    }
}

@Composable
private fun windowLengthText(durationMillis: Long): String {
    val parts = durationPartsOf(durationMillis)
    return if (parts.showsHours) {
        stringResource(
            R.string.maint_open_length_hours,
            parts.hours.toInt(),
            parts.minutes.toInt(),
        )
    } else {
        stringResource(R.string.maint_open_length_minutes, parts.minutes.toInt())
    }
}

/** One localized sentence per outcome, error-toned when the outcome is one. */
@Composable
private fun maintenanceResultMessage(result: MaintenanceResultView): UiMessage {
    val detail = if (result.failures.isEmpty()) {
        stringResource(R.string.error_unknown).bidiIsolated()
    } else {
        result.failures.joinToString(separator = " · ").bidiIsolated()
    }
    val text = when (result.kind) {
        MaintenanceResultKind.OPENED -> stringResource(R.string.maint_result_opened)
        MaintenanceResultKind.OPEN_REFUSED -> stringResource(
            R.string.maint_result_open_refused,
            stringResource(MaintenanceLabels.refusal(result.reason)),
        )

        MaintenanceResultKind.OPEN_FAILED_RESTORED ->
            stringResource(R.string.maint_result_open_failed_restored, detail)

        MaintenanceResultKind.OPEN_FAILED_RESTORE_FAILED ->
            stringResource(R.string.maint_result_open_failed_restore_failed, detail)

        MaintenanceResultKind.CLOSED_RESTORE_VERIFIED ->
            stringResource(R.string.maint_result_closed_verified)

        MaintenanceResultKind.CLOSE_RESTORE_FAILED ->
            stringResource(R.string.maint_result_close_failed, detail)

        MaintenanceResultKind.STILL_OPEN -> stringResource(R.string.maint_result_still_open)
        MaintenanceResultKind.NOT_OPEN -> stringResource(R.string.maint_result_not_open)
    }
    return UiMessage(text, isError = result.kind.isError)
}

@StringRes
private fun openBlockerLabel(blocker: OpenBlocker): Int = when (blocker) {
    OpenBlocker.SESSION_EXPIRED -> R.string.maint_blocked_session
    OpenBlocker.NOT_DEVICE_OWNER -> R.string.maint_blocked_not_device_owner
    OpenBlocker.ALREADY_OPEN -> R.string.maint_blocked_already_open
    OpenBlocker.NO_CAPABILITY -> R.string.maint_blocked_no_capability
    OpenBlocker.INVALID_DURATION -> R.string.maint_blocked_invalid_duration
    OpenBlocker.WORKING -> R.string.maint_action_working
    OpenBlocker.NONE -> R.string.maint_action_review
}

/** Capability titles in enum order, which is the order the audit line uses. */
@Composable
private fun capabilityNames(capabilities: Set<MaintenanceCapability>): String =
    MaintenanceCapability.values()
        .filter { it in capabilities }
        // The resources are resolved through the inline `map` and joined
        // afterwards: `joinToString` keeps its transform as a stored function
        // value, which is not a composable context.
        .map { stringResource(MaintenanceLabels.title(it)) }
        .joinToString(separator = ", ")

/** System policy control titles, for the relaxed and residual-blocker lines. */
@Composable
private fun controlNames(controls: List<SystemPolicyControl>): String =
    controls
        .map { stringResource(SystemPolicyLabels.title(it)) }
        .joinToString(separator = ", ")

/**
 * A clock time in the display locale and the 12/24-hour setting of the device.
 *
 * Isolated because a Latin time string inside a Hebrew sentence would otherwise
 * drag its punctuation to the wrong side.
 */
@Composable
private fun formatClockTime(millis: Long): String {
    val context = LocalContext.current
    return DateFormat.getTimeFormat(context).format(Date(millis)).bidiIsolated()
}

/**
 * Runs one device pass on the same single policy thread every other writer of
 * these restrictions uses, and suspends until it returns.
 *
 * Dispatchers.IO was wrong here, not merely untidy: a console pass on an IO
 * thread could interleave with a reconciliation pass on the policy thread, each
 * holding a different lock, each reading back the other's half-applied writes as
 * its own verified result. One thread for all DevicePolicyManager work is the
 * invariant; this is the console honouring it.
 */
private suspend fun <T> onPolicyThread(block: () -> T): T =
    suspendCancellableCoroutine { continuation ->
        PolicyReconciliationCoordinator.runOnPolicyThread {
            try {
                continuation.resume(block())
            } catch (throwable: Throwable) {
                continuation.resumeWithException(throwable)
            }
        }
    }

// ------------------------------------------------------------ the device work

/**
 * What the screen knows after one device pass.
 *
 * [window] is populated only from an outcome the coordinator reported as open, so
 * this type cannot carry an optimistic window.
 */
private class MaintenanceSnapshot(
    val window: MaintenanceWindow?,
    val relaxed: List<SystemPolicyControl>,
    val residual: List<SystemPolicyControl>,
    val deviceOwner: Boolean,
    val result: MaintenanceResultView?,
) {
    companion object {
        /** Before the first read: assume nothing, claim nothing. */
        fun unknown() = MaintenanceSnapshot(null, emptyList(), emptyList(), true, null)

        fun notDeviceOwner() = MaintenanceSnapshot(null, emptyList(), emptyList(), false, null)
    }
}

/** One outcome in the terms the banner states, holding no resource identifiers. */
private class MaintenanceResultView(
    val kind: MaintenanceResultKind,
    val reason: String?,
    val failures: List<String>,
)

/**
 * The coordinator for this device, or `null` when this build is not the device
 * owner and therefore cannot relax or restore anything.
 */
private fun maintenanceCoordinatorOf(context: Context): MaintenanceCoordinator? =
    MaintenanceGuard.coordinatorFor(context)

/**
 * The liveness pass the screen opens with.
 *
 * It is not a read. An expired window, a window that survived a restart, and a
 * stored record that could not be parsed all have to end in a restore that is
 * read back, and this is where that happens — before an administrator is offered
 * anything else.
 */
private fun loadMaintenance(context: Context): MaintenanceSnapshot {
    val outcome = refreshOnce(context) ?: return MaintenanceSnapshot.notDeviceOwner()
    return snapshotOf(context, outcome, reportUnchanged = false)
}

/**
 * The guard's liveness pass, not a private copy of it.
 *
 * This function once re-implemented the guard's body and drifted immediately:
 * it lacked the protection-paused stand-down, so opening this screen on a
 * paused device with a leftover owed-restore flag re-asserted the full base
 * restriction set onto a device the console showed as paused. Delegating is
 * the fix that stays fixed — a rule added to [MaintenanceGuard.refresh] cannot
 * miss the console path, because the console path is the same code.
 */
private fun refreshOnce(context: Context): MaintenanceOutcome? =
    MaintenanceGuard.refresh(context)

/**
 * Opens a window.
 *
 * A liveness pass runs first. The state machine refuses to open on top of an
 * existing window, and a window that has lapsed has to be closed, restored and
 * verified on its own audit line before a new one is granted.
 */
private fun openMaintenance(
    context: Context,
    capabilities: Set<MaintenanceCapability>,
    durationMillis: Long,
): MaintenanceSnapshot {
    val coordinator =
        maintenanceCoordinatorOf(context) ?: return MaintenanceSnapshot.notDeviceOwner()
    val refreshed = refreshOnce(context) ?: return MaintenanceSnapshot.notDeviceOwner()
    if (refreshed.restoreOwed()) {
        // A restore is still owed. Opening now would stack a new window on a
        // device whose previous relaxations were never proved to be gone.
        return snapshotOf(context, refreshed, reportUnchanged = true)
    }
    val requested = if (capabilities.isEmpty()) {
        // Handed to the state machine rather than fixed here: an empty request is
        // its refusal to make, and the console reports the refusal it gives.
        EnumSet.noneOf(MaintenanceCapability::class.java)
    } else {
        EnumSet.copyOf(capabilities)
    }
    val request = OpenRequest(
        requested,
        durationMillis,
        AdminSession.isUnlocked(),
        AllowedAppsStore.isProtectionEnabled(context),
    )
    // Through the guard: it marks the intent to relax before the first
    // device call, so a crash between relaxing and recording still leaves a
    // restore owed.
    val outcome = MaintenanceGuard.open(context, coordinator, openWindowAfter(refreshed), request)
    return snapshotOf(context, outcome, reportUnchanged = true)
}

/** Ends the window by hand, or because it ran out, and reads the restore back. */
private fun closeMaintenance(context: Context, reason: CloseReason): MaintenanceSnapshot {
    val coordinator =
        maintenanceCoordinatorOf(context) ?: return MaintenanceSnapshot.notDeviceOwner()
    val current = MaintenanceStore.readWindow(context)
    val outcome = if (reason == CloseReason.ADMINISTRATOR_CANCELLED) {
        MaintenanceGuard.cancel(context, coordinator, current)
    } else {
        // Expiry is the state machine's call, not this screen's: the guard's
        // pass re-reads the clocks and closes only if they say the window is
        // over — and it carries the paused stand-down the screen must not skip.
        refreshOnce(context) ?: return MaintenanceSnapshot.notDeviceOwner()
    }
    return snapshotOf(context, outcome, reportUnchanged = true)
}

/**
 * Persists exactly what the outcome hands back, and records the audit line.
 *
 * The entries carry the coordinator's own summary — phase, verified status,
 * capability keys, control keys and a duration in milliseconds — and nothing
 * else. No PIN, no recovery code, no kiosk URL.
 */
private fun record(context: Context, outcome: MaintenanceOutcome): MaintenanceOutcome =
    MaintenanceGuard.record(context, outcome)

/**
 * Turns an outcome into what the screen shows.
 *
 * The relaxed and residual-blocker lists are recomputed with the same pure
 * function the coordinator used, so a window read back from storage after a
 * process restart describes itself as accurately as one opened a moment ago.
 */
private fun snapshotOf(
    context: Context,
    outcome: MaintenanceOutcome,
    reportUnchanged: Boolean,
): MaintenanceSnapshot {
    val window = openWindowAfter(outcome)
    val plan = window?.let {
        MaintenancePlan.forWindow(
            SystemPolicyStore.effectiveProfile(context),
            SystemPolicyStore.explicitChoices(context),
            it,
        )
    }
    val kind = maintenanceResultKindOf(outcome)
    // Opening the screen on a device where nothing happened is not a result worth
    // announcing; every deliberate action is.
    val quiet = !reportUnchanged &&
        (kind == MaintenanceResultKind.STILL_OPEN || kind == MaintenanceResultKind.NOT_OPEN)
    return MaintenanceSnapshot(
        window = window,
        relaxed = plan?.relaxed()?.toList().orEmpty(),
        residual = plan?.residualBlockers()?.toList().orEmpty(),
        deviceOwner = true,
        result = if (quiet) {
            null
        } else {
            MaintenanceResultView(kind, outcome.reason(), failureLinesOf(outcome))
        },
    )
}
