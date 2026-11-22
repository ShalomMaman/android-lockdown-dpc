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
import androidx.compose.foundation.selection.toggleable
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
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import com.example.lockdowndpc.R
import com.example.lockdowndpc.maintenance.MaintenancePlan
import com.example.lockdowndpc.maintenance.MaintenanceStore
import com.example.lockdowndpc.policy.AllowedAppsStore
import com.example.lockdowndpc.policy.AuditEvent
import com.example.lockdowndpc.policy.AuditLog
import com.example.lockdowndpc.policy.BuiltInBlockExemptions
import com.example.lockdowndpc.policy.BuiltInExemptionsController
import com.example.lockdowndpc.policy.PackageIdentity
import com.example.lockdowndpc.policy.HomeFilterController
import com.example.lockdowndpc.policy.HomeFilterPolicy
import com.example.lockdowndpc.policy.LockdownPolicyController
import com.example.lockdowndpc.policy.PlayStoreCompatibility
import com.example.lockdowndpc.policy.PlayStoreCompatibilityStore
import com.example.lockdowndpc.policy.PolicyReconciliationCoordinator
import com.example.lockdowndpc.policy.ScheduleAlarm
import com.example.lockdowndpc.policy.ScheduleChange
import com.example.lockdowndpc.policy.ScheduleClock
import com.example.lockdowndpc.policy.ScheduleController
import com.example.lockdowndpc.policy.ScheduleSettings
import com.example.lockdowndpc.policy.ScheduleStore
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
    val resources = LocalResources.current
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
    val homeFilterEnabled = remember(revision) { HomeFilterController.isEnabled(context) }
    val playCompatibilityRequested =
        remember(revision) { PlayStoreCompatibilityStore.isEnabled(context) }
    val playCompatibilityState = remember(revision) { playCompatibilityStateOf(context) }
    val exemptionsView = remember(revision) { loadExemptionsView(context) }
    // A background pass can change what Android reports; re-read on return.
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { revision++ }
    var pendingExemption by remember { mutableStateOf<PendingExemption?>(null) }
    val schedule = remember(revision) { ScheduleStore.read(context) }
    val scheduleExact = remember(revision) { ScheduleAlarm.exactPermitted(context) }
    val scheduleClockLocked = remember(revision) { ScheduleClock.locked(context) }
    var pendingSchedule by remember { mutableStateOf<Boolean?>(null) }

    fun requireSession(): Boolean {
        if (AdminSession.isUnlocked()) {
            AdminSession.extend()
            return true
        }
        message = UiMessage(resources.getString(R.string.system_policy_error_auth), isError = true)
        return false
    }

    fun commit(change: PendingChange) {
        if (!requireSession()) {
            return
        }
        if (!SystemPolicyStore.setRequested(context, change.control, change.requested)) {
            message = UiMessage(resources.getString(R.string.policy_settings_save_failed), isError = true)
            return
        }
        // The previous verdict describes a policy that is no longer the one being
        // asked for, so it stops being evidence the instant the choice changes.
        SystemPolicyStore.invalidateVerification(context, change.control)
        AuditLog.append(
            context,
            AuditEvent.SYSTEM_POLICY_CHANGED,
            resources.getString(
                R.string.audit_system_policy_changed,
                "${change.control.storageKey()}=${change.requested}".bidiIsolated(),
            ),
        )
        revision++
        message = UiMessage(
            resources.getString(
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
            AuditEvent.PLAY_COMPATIBILITY_CHANGED,
            resources.getString(
                R.string.audit_play_compatibility_changed,
                "play_store_compatibility=$requested".bidiIsolated(),
            ),
        )
        revision++
        message = UiMessage(
            resources.getString(
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
                    resources.getString(R.string.not_device_owner),
                    isError = true,
                )

                !result.applied() -> {
                    // Policy detail mixes prose with Latin restriction keys, so it
                    // is isolated before being embedded in a localized sentence.
                    val detail = result.errors().firstOrNull()
                        ?: resources.getString(R.string.error_unknown)
                    UiMessage(
                        resources.getString(
                            R.string.system_policy_applied_failed,
                            detail.bidiIsolated(),
                        ),
                        isError = true,
                    )
                }

                else -> {
                    AuditLog.append(
                        context,
                        AuditEvent.SYSTEM_POLICY_APPLIED,
                        resources.getString(R.string.audit_system_policy_applied),
                    )
                    UiMessage(
                        resources.getString(R.string.system_policy_applied_ok),
                        isError = false,
                    )
                }
            }
        }
    }

    /**
     * Submits a change to the built-in block exemptions at the policy boundary.
     *
     * The policy controller checks authorization again before saving. The
     * console refreshes the live Android state after the protection pass.
     */
    fun submitExemption(
        trigger: String,
        clearApprovals: Boolean = false,
        operation: (BuiltInBlockExemptions.Settings) -> BuiltInBlockExemptions.Settings = { it },
    ) {
        if (working) {
            return
        }
        if (AdminSession.isUnlocked()) {
            AdminSession.extend()
        }
        working = true
        message = null
        coroutineScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                try {
                    Result.success(
                        if (clearApprovals) {
                            BuiltInExemptionsController.clearApprovals(context.applicationContext)
                        } else {
                            BuiltInExemptionsController.change(
                                context.applicationContext,
                                { settings -> operation(settings) },
                                trigger,
                            )
                        }
                    )
                } catch (exception: SecurityException) {
                    Result.failure<BuiltInExemptionsController.Outcome>(exception)
                } catch (exception: IllegalArgumentException) {
                    Result.failure<BuiltInExemptionsController.Outcome>(exception)
                } catch (exception: IllegalStateException) {
                    Result.failure<BuiltInExemptionsController.Outcome>(exception)
                }
            }
            working = false
            revision++
            val changed = outcome.getOrNull()
            val result = changed?.result()
            message = when {
                outcome.exceptionOrNull() is SecurityException -> UiMessage(
                    resources.getString(R.string.system_policy_error_auth),
                    isError = true,
                )
                outcome.isFailure ||
                    changed?.status() == BuiltInExemptionsController.Status.NOT_SAVED -> UiMessage(
                    resources.getString(R.string.system_policy_exempt_change_refused),
                    isError = true,
                )
                changed?.status() == BuiltInExemptionsController.Status.CONTAINMENT_REFUSED -> UiMessage(
                    resources.getString(R.string.system_policy_exempt_containment_refused),
                    isError = true,
                )
                result != null && !result.applied() -> UiMessage(
                    resources.getString(
                        if (changed?.status() == BuiltInExemptionsController.Status.AUDIT_NOT_SAVED) {
                            R.string.system_policy_exempt_failed_and_audit_not_saved
                        } else {
                            R.string.system_policy_applied_failed
                        },
                        (result.errors().firstOrNull()
                            ?: resources.getString(R.string.error_unknown)).bidiIsolated(),
                    ),
                    isError = true,
                )
                changed?.status() == BuiltInExemptionsController.Status.FILTER_NOT_READY -> UiMessage(
                    resources.getString(R.string.system_policy_exempt_filter_not_ready),
                    isError = true,
                )
                changed?.status() == BuiltInExemptionsController.Status.AUDIT_NOT_SAVED -> UiMessage(
                    resources.getString(R.string.system_policy_exempt_audit_not_saved),
                    isError = true,
                )
                changed?.status() == BuiltInExemptionsController.Status.PAUSED_REFUSED -> UiMessage(
                    resources.getString(R.string.system_policy_exempt_paused_refused),
                    isError = true,
                )
                changed?.status() == BuiltInExemptionsController.Status.ACTIVE_ADMIN_REFUSED -> UiMessage(
                    resources.getString(R.string.system_policy_exempt_active_admin_refused),
                    isError = true,
                )
                changed?.status() == BuiltInExemptionsController.Status.ADMINS_UNREADABLE -> UiMessage(
                    resources.getString(R.string.system_policy_exempt_admins_unreadable),
                    isError = true,
                )
                result == null -> null
                else -> UiMessage(
                    resources.getString(R.string.system_policy_applied_ok),
                    isError = false,
                )
            }
        }
    }

    /**
     * Turns night and work hours on or off at the policy boundary, which
     * checks the administrator session again before a loosening is saved and
     * then runs the enforcing pass.
     */
    fun submitSchedule(requested: Boolean) {
        if (working || !requireSession()) {
            return
        }
        working = true
        message = null
        coroutineScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                try {
                    Result.success(ScheduleController.setEnabled(context.applicationContext, requested))
                } catch (exception: RuntimeException) {
                    // SecurityException included: shown as an expired session below.
                    Result.failure<ScheduleController.Result>(exception)
                }
            }
            working = false
            revision++
            val result = outcome.getOrElse { failure ->
                // The stored schedule is re-read on the next render, so the
                // row shows what is actually in force.
                message = if (failure is SecurityException) {
                    UiMessage(resources.getString(R.string.system_policy_error_auth), isError = true)
                } else {
                    UiMessage(
                        resources.getString(
                            R.string.system_policy_applied_failed,
                            failure.javaClass.simpleName.bidiIsolated(),
                        ),
                        isError = true,
                    )
                }
                return@launch
            }
            val pass = result.pass()
            message = when (result.outcome().status()) {
                ScheduleChange.Status.SESSION_REQUIRED -> UiMessage(
                    resources.getString(R.string.system_policy_error_auth),
                    isError = true,
                )
                ScheduleChange.Status.NOT_SAVED -> UiMessage(
                    resources.getString(R.string.system_policy_schedule_not_saved),
                    isError = true,
                )
                ScheduleChange.Status.CLOCK_UNLOCKED -> UiMessage(
                    resources.getString(R.string.system_policy_schedule_clock_unconfirmed),
                    isError = true,
                )
                ScheduleChange.Status.UNCHANGED -> null
                else -> when {
                    pass == null -> UiMessage(
                        resources.getString(R.string.system_policy_paused_note),
                        isError = false,
                    )
                    !pass.applied() -> UiMessage(
                        resources.getString(
                            R.string.system_policy_applied_failed,
                            (pass.errors().firstOrNull()
                                ?: resources.getString(R.string.error_unknown)).bidiIsolated(),
                        ),
                        isError = true,
                    )
                    else -> UiMessage(
                        resources.getString(R.string.system_policy_applied_ok),
                        isError = false,
                    )
                }
            }
        }
    }

    /** Pins the application to the signer it has right now, then submits. */
    fun approveSocial(candidate: ExemptionCandidate) {
        val signer = PackageIdentity.currentSignerSha256IncludingHidden(
            context.packageManager,
            candidate.packageName,
        )
        if (signer.isEmpty()) {
            message = UiMessage(
                resources.getString(R.string.system_policy_exempt_social_signer_unreadable),
                isError = true,
            )
            return
        }
        submitExemption("approve:${candidate.packageName}") { settings ->
            settings.withSocial(candidate.packageName, signer)
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
                            lockedByHomeFilter = homeFilterEnabled &&
                                control in HomeFilterPolicy.REQUIRED_CONTROLS,
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

        Spacer(Modifier.height(20.dp))
        SectionCard(title = stringResource(R.string.system_policy_section_schedule)) {
            key(revision) {
                ScheduleRow(
                    settings = schedule,
                    exactAlarms = scheduleExact,
                    clockLocked = scheduleClockLocked,
                    enabled = !working,
                    onToggle = { requested -> pendingSchedule = requested },
                )
            }
        }

        Spacer(Modifier.height(20.dp))
        key(revision) {
            BuiltInExemptionsSection(
                view = exemptionsView,
                enabled = !working,
                onRequestChrome = { pendingExemption = PendingExemption.Chrome },
                onRemoveChrome = {
                    submitExemption("remove:chrome") { settings -> settings.withChrome(false) }
                },
                onRequestSocial = { candidate ->
                    pendingExemption = PendingExemption.Social(candidate)
                },
                onRemoveSocial = { candidate ->
                    submitExemption("remove:${candidate.packageName}") { settings ->
                        settings.withoutSocial(candidate.packageName)
                    }
                },
                onClearApprovals = { submitExemption("clear-approvals", clearApprovals = true) },
            )
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

    pendingExemption?.let { change ->
        ExemptionConfirmDialog(
            pending = change,
            onConfirm = {
                pendingExemption = null
                when (change) {
                    PendingExemption.Chrome -> submitExemption("approve:chrome") { settings ->
                        settings.withChrome(true)
                    }
                    is PendingExemption.Social -> approveSocial(change.candidate)
                }
            },
            onDismiss = { pendingExemption = null },
        )
    }

    pendingSchedule?.let { requested ->
        ScheduleConfirmDialog(
            requested = requested,
            onConfirm = {
                pendingSchedule = null
                submitSchedule(requested)
            },
            onDismiss = { pendingSchedule = null },
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

/**
 * Night and work hours: one switch for both windows, the state on file, and
 * what the windows do. An unreadable record reads as on, because the device
 * enforces both default windows for it. While a schedule is on, the
 * exact-alarm state is stated as it is, with no promised delay. On Android
 * 8.0/8.1 an unlocked clock is stated as the reason the schedule cannot be
 * turned on yet.
 */
@Composable
private fun ScheduleRow(
    settings: ScheduleSettings,
    exactAlarms: Boolean,
    clockLocked: Boolean,
    enabled: Boolean,
    onToggle: (Boolean) -> Unit,
) {
    // On while any window restricts: one enabled window is still a schedule
    // in force, and the fail-closed windows of an unreadable record too.
    val on = settings.unreadable() || settings.enforcing()
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 64.dp)
            // The row owns the switch semantics, so TalkBack reads the title
            // and status together with the state.
            .toggleable(
                value = on,
                enabled = enabled,
                role = Role.Switch,
                onValueChange = onToggle,
            )
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = stringResource(R.string.system_policy_schedule_row),
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                text = stringResource(
                    R.string.system_policy_status_line,
                    stringResource(
                        when {
                            settings.unreadable() -> R.string.system_policy_schedule_state_unreadable
                            on -> R.string.system_policy_schedule_state_on
                            else -> R.string.system_policy_schedule_state_off
                        }
                    ),
                ),
                style = MaterialTheme.typography.bodySmall,
                color = if (settings.unreadable()) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
            )
        }
        Spacer(Modifier.size(16.dp))
        // Decorative: the row above is the toggle.
        Switch(
            checked = on,
            onCheckedChange = null,
            enabled = enabled,
        )
    }
    Text(
        text = stringResource(R.string.system_policy_schedule_body),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
    )
    if (on) {
        Text(
            text = stringResource(
                if (exactAlarms) {
                    R.string.system_policy_schedule_exact
                } else {
                    R.string.system_policy_schedule_inexact
                }
            ),
            style = MaterialTheme.typography.bodySmall,
            color = if (exactAlarms) {
                MaterialTheme.colorScheme.onSurfaceVariant
            } else {
                MaterialTheme.colorScheme.error
            },
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
        )
    }
    if (!clockLocked) {
        Text(
            text = stringResource(R.string.system_policy_schedule_clock_needed),
            style = MaterialTheme.typography.bodySmall,
            color = if (on) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
        )
    }
}

/** What turning the windows on or off does, stated before anything is written. */
@Composable
private fun ScheduleConfirmDialog(
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
                        R.string.system_policy_schedule_confirm_enable_title
                    } else {
                        R.string.system_policy_schedule_confirm_disable_title
                    }
                )
            )
        },
        text = {
            Text(
                stringResource(
                    if (requested) {
                        R.string.system_policy_schedule_confirm_enable_body
                    } else {
                        R.string.system_policy_schedule_confirm_disable_body
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
    lockedByHomeFilter: Boolean,
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
            if (lockedByPlayCompatibility || lockedByHomeFilter) {
                Text(
                    text = stringResource(
                        if (lockedByHomeFilter) R.string.home_filter_control_required
                        else R.string.system_policy_play_compat_locked_control,
                    ),
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
            enabled = enabled && !lockedByPlayCompatibility && !lockedByHomeFilter,
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
