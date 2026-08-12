package com.example.lockdowndpc.ui

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.graphics.Color
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.History
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.Language
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.LockOpen
import androidx.compose.material.icons.rounded.Pause
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material.icons.rounded.SystemUpdateAlt
import androidx.compose.material.icons.rounded.VpnKey
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.compose.runtime.CompositionLocalProvider
import com.example.lockdowndpc.R
import com.example.lockdowndpc.policy.AllowedAppsStore
import com.example.lockdowndpc.policy.AuditLog
import com.example.lockdowndpc.policy.LockdownPolicyController
import com.example.lockdowndpc.security.AdminPinStore
import com.example.lockdowndpc.security.AdminSession
import com.example.lockdowndpc.ui.theme.LockdownTheme
import com.example.lockdowndpc.updates.SecureUpdateManager
import com.example.lockdowndpc.updates.UpdateConfig
import com.example.lockdowndpc.updates.UpdatePhase
import com.example.lockdowndpc.updates.UpdateScheduler
import com.example.lockdowndpc.updates.UpdateSnapshot
import com.example.lockdowndpc.updates.UpdateStateStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Administrator console. The screen sequence, the three minute admin session and
 * the FLAG_SECURE rules are the same as the programmatic View implementation this
 * replaced; only the presentation moved to Compose.
 *
 * The base class is `AppCompatActivity` purely for localization: below API 33 that
 * is what applies the persisted display language to the activity resources. See
 * [AppLocales].
 */
class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        UpdateScheduler.schedule(applicationContext)
        // Start fail-closed: on release builds the window is protected before
        // Compose can draw its first frame. Public/admin screens explicitly
        // clear the flag after their state has been resolved.
        if (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE == 0) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
        // The console is always light, even when the system is in dark mode, so
        // the bar styles are pinned instead of following the system setting.
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.light(Color.TRANSPARENT, SYSTEM_BAR_DARK_SCRIM),
            navigationBarStyle = SystemBarStyle.light(Color.TRANSPARENT, SYSTEM_BAR_DARK_SCRIM),
        )
        setContent {
            LockdownTheme {
                AdminConsole(
                    onSecureScreen = ::setSecureScreen,
                    onOpenAppList = {
                        startActivity(Intent(this, AllowedAppsActivity::class.java))
                    },
                )
            }
        }
    }

    /**
     * Release builds keep the PIN, lockout and recovery screens out of
     * screenshots and the recents thumbnail. Debug builds deliberately leave the
     * flag untouched so visual QA can capture them.
     */
    private fun setSecureScreen(secure: Boolean) {
        if (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
            return
        }
        if (secure) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }
}

private enum class ConsoleScreen(val secure: Boolean) {
    ENROLLMENT(false),
    PIN_SETUP(true),
    LOCKED(true),
    ADMIN(false),
    RECOVERY(true),
}

private data class ConsoleStatus(
    val deviceOwner: Boolean,
    val policyState: AllowedAppsStore.PolicyState,
    val policyError: String,
    val allowlistConfigured: Boolean,
    val protectionEnabled: Boolean,
    val mode: AllowedAppsStore.ProtectionMode,
)

private fun isDeviceOwner(context: Context): Boolean {
    val dpm = context.getSystemService(DevicePolicyManager::class.java)
    return dpm != null && dpm.isDeviceOwnerApp(context.packageName)
}

private fun readStatus(context: Context) = ConsoleStatus(
    deviceOwner = isDeviceOwner(context),
    policyState = AllowedAppsStore.getPolicyState(context),
    policyError = AllowedAppsStore.getPolicyError(context).orEmpty(),
    allowlistConfigured = AllowedAppsStore.isAllowlistConfigured(context),
    protectionEnabled = AllowedAppsStore.isProtectionEnabled(context),
    mode = AllowedAppsStore.getProtectionMode(context),
)

private fun initialScreen(context: Context): ConsoleScreen {
    if (!isDeviceOwner(context)) {
        return ConsoleScreen.ENROLLMENT
    }
    if (!AdminPinStore.hasPin(context)) {
        return ConsoleScreen.PIN_SETUP
    }
    // Reaching the locked screen always drops the admin session, including on
    // activity recreation. That was the behaviour of the shipped build.
    AdminSession.lock()
    return ConsoleScreen.LOCKED
}

/**
 * The retry guidance is a plural: English needs one/other and Hebrew additionally
 * needs the dual form (`שנייה אחת` / `שתי שניות` / `%d שניות`), which a single
 * format string cannot express. `getQuantityString` takes an `Int`, so the rounded
 * delay is clamped rather than truncated.
 */
private fun lockoutText(context: Context, remainingMillis: Long): String {
    val delay = lockoutDelayOf(remainingMillis)
    val template = when (delay.unit) {
        LockoutUnit.SECONDS -> R.plurals.lockout_seconds
        LockoutUnit.MINUTES -> R.plurals.lockout_minutes
    }
    val amount = delay.amount.coerceIn(1L, Int.MAX_VALUE.toLong()).toInt()
    return context.resources.getQuantityString(template, amount, amount)
}

@Composable
private fun AdminConsole(
    onSecureScreen: (Boolean) -> Unit,
    onOpenAppList: () -> Unit,
) {
    val context = LocalContext.current
    var screen by remember { mutableStateOf(initialScreen(context)) }
    var replacingPin by remember { mutableStateOf(false) }
    var recoveryCode by remember { mutableStateOf("") }
    var message by remember { mutableStateOf<UiMessage?>(null) }
    var modePickerVisible by remember { mutableStateOf(false) }
    var languagePickerVisible by remember { mutableStateOf(false) }
    var auditLogVisible by remember { mutableStateOf(false) }
    var policyOperationInProgress by remember { mutableStateOf(false) }
    var updateOperationInProgress by remember { mutableStateOf(false) }
    var updateSnapshot by remember { mutableStateOf(UpdateStateStore.read(context)) }
    var statusRevision by remember { mutableIntStateOf(0) }
    val coroutineScope = rememberCoroutineScope()
    val status = remember(screen, statusRevision) { readStatus(context) }

    fun showLocked() {
        AdminSession.lock()
        message = null
        replacingPin = false
        screen = ConsoleScreen.LOCKED
    }

    fun requireSession(): Boolean {
        if (AdminSession.isUnlocked()) {
            return true
        }
        showLocked()
        return false
    }

    fun showAdmin() {
        if (!AdminSession.isUnlocked()) {
            showLocked()
            return
        }
        AdminSession.extend()
        message = null
        statusRevision++
        screen = ConsoleScreen.ADMIN
    }

    fun showRecovery(code: String) {
        if (!AdminSession.isUnlocked()) {
            showLocked()
            return
        }
        recoveryCode = code
        message = null
        screen = ConsoleScreen.RECOVERY
    }

    fun savePin(first: String, second: String) {
        if (replacingPin && !requireSession()) {
            return
        }
        if (!AdminPinStore.isValidPin(first)) {
            message = UiMessage(context.getString(R.string.pin_error_format), isError = true)
            return
        }
        if (first != second) {
            message = UiMessage(context.getString(R.string.pin_error_mismatch), isError = true)
            return
        }
        try {
            AdminPinStore.setNewPin(context, first)
            val code = AdminPinStore.rotateRecoveryCode(context)
            AuditLog.append(
                context,
                context.getString(
                    if (replacingPin) R.string.audit_pin_replaced else R.string.audit_pin_set
                ),
            )
            AdminSession.unlock()
            statusRevision++
            showRecovery(code)
        } catch (exception: RuntimeException) {
            message = UiMessage(context.getString(R.string.pin_error_save), isError = true)
        }
    }

    fun unlockWith(pin: String) {
        val result = AdminPinStore.verify(context, pin)
        when (result.status()) {
            AdminPinStore.Status.SUCCESS -> {
                AdminSession.unlock()
                if (result.usedRecoveryCode()) {
                    replacingPin = true
                    message = null
                    screen = ConsoleScreen.PIN_SETUP
                } else {
                    showAdmin()
                }
            }

            AdminPinStore.Status.INVALID ->
                message = UiMessage(context.getString(R.string.pin_error_invalid), isError = true)

            AdminPinStore.Status.LOCKED ->
                message = UiMessage(lockoutText(context, result.remainingMillis()), isError = true)

            AdminPinStore.Status.NOT_CONFIGURED -> {
                replacingPin = false
                message = null
                screen = ConsoleScreen.PIN_SETUP
            }

            AdminPinStore.Status.ERROR ->
                message = UiMessage(context.getString(R.string.pin_error_verify), isError = true)

            else -> Unit
        }
    }

    fun applyProtection() {
        if (policyOperationInProgress || !requireSession()) {
            return
        }
        AdminSession.extend()
        if (!AllowedAppsStore.isAllowlistConfigured(context)) {
            message = UiMessage(context.getString(R.string.admin_error_allowlist), isError = true)
            onOpenAppList()
            return
        }
        policyOperationInProgress = true
        message = null
        coroutineScope.launch {
            val result = withContext(Dispatchers.IO) {
                LockdownPolicyController.apply(context.applicationContext)
            }
            policyOperationInProgress = false
            statusRevision++
            if (!result.deviceOwner()) {
                message = UiMessage(context.getString(R.string.not_device_owner), isError = true)
            } else if (!result.applied()) {
                // Policy details are produced by the policy layer and mix prose
                // with Latin class and package names, so each one is isolated
                // before it is embedded in a localized sentence.
                val detail = result.errors().firstOrNull() ?: context.getString(R.string.error_unknown)
                showAdmin()
                message = UiMessage(
                    context.getString(R.string.policy_failed, detail.bidiIsolated()),
                    isError = true,
                )
            } else {
                AuditLog.append(context, context.getString(R.string.audit_apply))
                showAdmin()
                val blocked = result.blockedPackages()
                message = UiMessage(
                    context.resources.getQuantityString(R.plurals.policy_applied, blocked, blocked),
                    isError = false,
                )
            }
        }
    }

    fun pauseProtection() {
        if (policyOperationInProgress || !requireSession()) {
            return
        }
        AdminSession.extend()
        policyOperationInProgress = true
        message = null
        coroutineScope.launch {
            val result = withContext(Dispatchers.IO) {
                LockdownPolicyController.pause(context.applicationContext)
            }
            policyOperationInProgress = false
            statusRevision++
            if (!result.deviceOwner()) {
                message = UiMessage(context.getString(R.string.not_device_owner), isError = true)
            } else if (!result.applied()) {
                val detail = result.errors().firstOrNull() ?: context.getString(R.string.error_unknown)
                showAdmin()
                message = UiMessage(
                    context.getString(R.string.admin_pause_failed, detail.bidiIsolated()),
                    isError = true,
                )
            } else {
                AuditLog.append(context, context.getString(R.string.audit_pause))
                showAdmin()
                message = UiMessage(context.getString(R.string.admin_pause_ok), isError = false)
            }
        }
    }

    fun rotateRecoveryCode() {
        if (!requireSession()) {
            return
        }
        try {
            AuditLog.append(context, context.getString(R.string.audit_recovery))
            showRecovery(AdminPinStore.rotateRecoveryCode(context))
        } catch (exception: RuntimeException) {
            message = UiMessage(context.getString(R.string.admin_error_recovery), isError = true)
        }
    }

    fun checkForUpdates() {
        if (updateOperationInProgress || !requireSession()) {
            return
        }
        AdminSession.extend()
        updateOperationInProgress = true
        coroutineScope.launch {
            withContext(Dispatchers.IO) {
                SecureUpdateManager.checkNow(context.applicationContext)
            }
            updateSnapshot = UpdateStateStore.read(context)
            updateOperationInProgress = false
        }
    }

    LaunchedEffect(screen) { onSecureScreen(screen.secure) }

    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        when {
            screen == ConsoleScreen.ADMIN && !AdminSession.isUnlocked() -> showLocked()
            screen == ConsoleScreen.ADMIN -> {
                statusRevision++
                updateSnapshot = UpdateStateStore.read(context)
            }
            screen == ConsoleScreen.RECOVERY && !AdminSession.isUnlocked() -> showLocked()
            screen == ConsoleScreen.ENROLLMENT && isDeviceOwner(context) -> {
                message = null
                replacingPin = false
                screen = initialScreen(context)
            }

            else -> Unit
        }
    }

    when (screen) {
        ConsoleScreen.ENROLLMENT -> EnrollmentScreen()

        ConsoleScreen.PIN_SETUP -> PinSetupScreen(
            replacing = replacingPin,
            message = message,
            onSave = ::savePin,
            onCancel = { if (requireSession()) showAdmin() },
        )

        ConsoleScreen.LOCKED -> LockedScreen(
            status = status,
            message = message,
            onUnlock = ::unlockWith,
        )

        ConsoleScreen.ADMIN -> AdminScreen(
            status = status,
            policyOperationInProgress = policyOperationInProgress,
            updateOperationInProgress = updateOperationInProgress,
            updateSnapshot = updateSnapshot,
            message = message,
            onApply = ::applyProtection,
            onPause = ::pauseProtection,
            onPickMode = { if (requireSession()) modePickerVisible = true },
            onChooseApps = {
                if (requireSession()) {
                    AdminSession.extend()
                    onOpenAppList()
                }
            },
            onChangePin = {
                if (requireSession()) {
                    replacingPin = true
                    message = null
                    screen = ConsoleScreen.PIN_SETUP
                }
            },
            onNewRecoveryCode = ::rotateRecoveryCode,
            onOpenAuditLog = { if (requireSession()) auditLogVisible = true },
            onCheckUpdate = ::checkForUpdates,
            onPickLanguage = { if (requireSession()) languagePickerVisible = true },
            onLock = { showLocked() },
        )

        ConsoleScreen.RECOVERY -> RecoveryScreen(
            code = recoveryCode,
            onAcknowledge = { if (requireSession()) showAdmin() },
        )
    }

    if (modePickerVisible) {
        ModePickerDialog(
            current = status.mode,
            onDismiss = { modePickerVisible = false },
            onSave = { chosen ->
                modePickerVisible = false
                AllowedAppsStore.setProtectionMode(context, chosen)
                AuditLog.append(
                    context,
                    context.getString(
                        if (chosen == AllowedAppsStore.ProtectionMode.ALLOW_SELECTED) {
                            R.string.audit_mode_allow
                        } else {
                            R.string.audit_mode_block
                        }
                    ),
                )
                showAdmin()
            },
        )
    }

    if (languagePickerVisible) {
        LanguagePickerDialog(
            current = AppLocales.current(),
            onDismiss = { languagePickerVisible = false },
            onSave = { chosen ->
                languagePickerVisible = false
                // Android recreates this activity to apply the new resources, and
                // `initialScreen` drops the admin session on every recreation. That
                // is the shipped fail-closed behaviour, so the picker says so
                // instead of the console quietly holding the session open.
                AppLocales.apply(chosen)
            },
        )
    }

    if (auditLogVisible) {
        AuditLogDialog(onDismiss = { auditLogVisible = false })
    }
}

@Composable
private fun EnrollmentScreen() {
    LockdownScreen(
        title = stringResource(R.string.enrollment_title),
        subtitle = stringResource(R.string.enrollment_subtitle),
    ) {
        Card(
            shape = MaterialTheme.shapes.large,
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.primaryContainer,
                contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
            ),
            elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Row(modifier = Modifier.padding(20.dp)) {
                Icon(
                    imageVector = Icons.Rounded.Info,
                    contentDescription = null,
                    modifier = Modifier.size(24.dp),
                )
                Spacer(Modifier.size(14.dp))
                Text(
                    text = stringResource(R.string.enrollment_note),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }
}

@Composable
private fun PinSetupScreen(
    replacing: Boolean,
    message: UiMessage?,
    onSave: (String, String) -> Unit,
    onCancel: () -> Unit,
) {
    var first by remember { mutableStateOf("") }
    var second by remember { mutableStateOf("") }

    LockdownScreen(
        title = stringResource(
            if (replacing) R.string.pin_setup_title_replace else R.string.pin_setup_title
        ),
        subtitle = stringResource(R.string.pin_setup_subtitle),
    ) {
        PinField(
            value = first,
            onValueChange = { first = it },
            label = stringResource(R.string.pin_setup_field_new),
        )
        Spacer(Modifier.height(12.dp))
        PinField(
            value = second,
            onValueChange = { second = it },
            label = stringResource(R.string.pin_setup_field_confirm),
            imeAction = ImeAction.Done,
            onImeAction = { onSave(first, second) },
        )
        if (message != null) {
            Spacer(Modifier.height(16.dp))
            MessageBanner(message)
        }
        Spacer(Modifier.height(24.dp))
        PrimaryAction(
            text = stringResource(
                if (replacing) R.string.pin_setup_save_replace else R.string.pin_setup_save
            ),
            icon = Icons.Rounded.Key,
            onClick = { onSave(first, second) },
        )
        if (replacing) {
            Spacer(Modifier.height(12.dp))
            SecondaryAction(text = stringResource(R.string.action_cancel), onClick = onCancel)
        }
    }
}

@Composable
private fun LockedScreen(
    status: ConsoleStatus,
    message: UiMessage?,
    onUnlock: (String) -> Unit,
) {
    var pin by remember { mutableStateOf("") }

    fun submit() {
        val entered = pin
        pin = ""
        onUnlock(entered)
    }

    LockdownScreen(
        title = stringResource(R.string.locked_title),
        subtitle = stringResource(R.string.locked_subtitle),
    ) {
        PolicyStatusCard(
            tone = statusTone(status.policyState),
            headline = stringResource(statusHeadline(status.policyState)),
            facts = statusFacts(status),
            detail = statusDetail(status),
        )
        Spacer(Modifier.height(24.dp))
        PinField(
            value = pin,
            onValueChange = { pin = it },
            label = stringResource(R.string.locked_field_pin),
            imeAction = ImeAction.Done,
            onImeAction = ::submit,
        )
        if (message != null) {
            Spacer(Modifier.height(16.dp))
            MessageBanner(message)
        }
        Spacer(Modifier.height(24.dp))
        PrimaryAction(
            text = stringResource(R.string.locked_unlock),
            icon = Icons.Rounded.LockOpen,
            onClick = ::submit,
        )
    }
}

@Composable
private fun AdminScreen(
    status: ConsoleStatus,
    policyOperationInProgress: Boolean,
    updateOperationInProgress: Boolean,
    updateSnapshot: UpdateSnapshot,
    message: UiMessage?,
    onApply: () -> Unit,
    onPause: () -> Unit,
    onPickMode: () -> Unit,
    onChooseApps: () -> Unit,
    onChangePin: () -> Unit,
    onNewRecoveryCode: () -> Unit,
    onOpenAuditLog: () -> Unit,
    onCheckUpdate: () -> Unit,
    onPickLanguage: () -> Unit,
    onLock: () -> Unit,
) {
    val allowSelected = status.mode == AllowedAppsStore.ProtectionMode.ALLOW_SELECTED

    LockdownScreen(
        title = stringResource(R.string.app_name),
        subtitle = stringResource(
            if (allowSelected) R.string.admin_subtitle_allow else R.string.admin_subtitle_block
        ),
    ) {
        PolicyStatusCard(
            tone = statusTone(status.policyState),
            headline = stringResource(statusHeadline(status.policyState)),
            facts = statusFacts(status),
            detail = statusDetail(status),
        )
        if (message != null) {
            Spacer(Modifier.height(16.dp))
            MessageBanner(message)
        }

        Spacer(Modifier.height(24.dp))
        PrimaryAction(
            text = stringResource(
                when {
                    policyOperationInProgress -> R.string.admin_policy_working
                    status.protectionEnabled -> R.string.admin_apply_refresh
                    else -> R.string.admin_apply
                }
            ),
            icon = if (status.protectionEnabled) Icons.Rounded.Refresh else Icons.Rounded.Shield,
            enabled = !policyOperationInProgress,
            onClick = onApply,
        )

        Spacer(Modifier.height(28.dp))
        SectionCard(title = stringResource(R.string.admin_section_protection)) {
            ActionRow(
                icon = Icons.Rounded.Tune,
                title = stringResource(R.string.admin_mode_row),
                supporting = stringResource(
                    if (allowSelected) R.string.mode_label_allow else R.string.mode_label_block
                ),
                onClick = onPickMode,
            )
            ActionRow(
                icon = Icons.Rounded.Apps,
                title = stringResource(
                    if (allowSelected) R.string.admin_choose_allow else R.string.admin_choose_block
                ),
                supporting = stringResource(R.string.admin_choose_supporting),
                onClick = onChooseApps,
                showDivider = true,
            )
            if (status.protectionEnabled) {
                ActionRow(
                    icon = Icons.Rounded.Pause,
                    title = stringResource(R.string.admin_pause),
                    supporting = stringResource(R.string.admin_pause_supporting),
                    onClick = onPause,
                    showDivider = true,
                )
            }
        }

        Spacer(Modifier.height(20.dp))
        SectionCard(title = stringResource(R.string.admin_section_access)) {
            ActionRow(
                icon = Icons.Rounded.Key,
                title = stringResource(R.string.admin_change_pin),
                onClick = onChangePin,
            )
            ActionRow(
                icon = Icons.Rounded.VpnKey,
                title = stringResource(R.string.admin_new_recovery),
                supporting = stringResource(R.string.admin_new_recovery_supporting),
                onClick = onNewRecoveryCode,
                showDivider = true,
            )
        }

        Spacer(Modifier.height(20.dp))
        SectionCard(title = stringResource(R.string.admin_section_updates)) {
            ActionRow(
                icon = Icons.Rounded.SystemUpdateAlt,
                title = stringResource(
                    when {
                        !UpdateConfig.isConfigured -> R.string.update_disabled_title
                        updateOperationInProgress -> R.string.update_checking_title
                        updateSnapshot.phase == UpdatePhase.FAILED -> R.string.update_failed_title
                        updateSnapshot.phase == UpdatePhase.INSTALLING -> R.string.update_installing_title
                        else -> R.string.update_check_title
                    }
                ),
                // An update message carries version identifiers and verification
                // failures, so it is isolated rather than left to inherit the
                // direction of the surrounding row.
                supporting = updateSnapshot.message.takeIf { it.isNotBlank() }?.bidiIsolated()
                    ?: stringResource(
                        if (UpdateConfig.isConfigured) {
                            R.string.update_ready_supporting
                        } else {
                            R.string.update_disabled_supporting
                        }
                    ),
                enabled = UpdateConfig.isConfigured && !updateOperationInProgress,
                onClick = onCheckUpdate,
            )
        }

        Spacer(Modifier.height(20.dp))
        SectionCard(title = stringResource(R.string.admin_section_display)) {
            ActionRow(
                // A globe is not a directional glyph, so it is never mirrored.
                icon = Icons.Rounded.Language,
                title = stringResource(R.string.language_row_title),
                supporting = stringResource(AppLocales.labelOf(AppLocales.current())),
                onClick = onPickLanguage,
            )
        }

        // Kiosk integration point: the kiosk agent's controls belong in a
        // SectionCard added here, between "Display" and "Records and monitoring",
        // built from ActionRow entries with keys named `admin_kiosk_*` in
        // res/values/strings.xml and res/values-iw/strings.xml. See the branch
        // notes for the rationale.

        Spacer(Modifier.height(20.dp))
        SectionCard(title = stringResource(R.string.admin_section_records)) {
            ActionRow(
                icon = Icons.Rounded.History,
                title = stringResource(R.string.admin_audit),
                onClick = onOpenAuditLog,
            )
            ActionRow(
                icon = Icons.Rounded.Lock,
                title = stringResource(R.string.admin_lock),
                onClick = onLock,
                showDivider = true,
            )
        }

        Spacer(Modifier.height(24.dp))
        Text(
            text = stringResource(
                if (allowSelected) R.string.admin_help_allow else R.string.admin_help_block
            ),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun RecoveryScreen(code: String, onAcknowledge: () -> Unit) {
    LockdownScreen(
        title = stringResource(R.string.recovery_title),
        subtitle = stringResource(R.string.recovery_subtitle),
    ) {
        val description = stringResource(R.string.recovery_code_description, code)
        Card(
            shape = MaterialTheme.shapes.large,
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.primaryContainer,
                contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
            ),
            elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            // The code is Latin digits and separators. The direction is overridden
            // for this card only, so the groups keep their order when the rest of
            // the page is right-to-left; in English this is already the direction.
            CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                SelectionContainer {
                    Text(
                        text = code,
                        style = MaterialTheme.typography.headlineMedium,
                        fontSize = 30.sp,
                        textAlign = TextAlign.Center,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 28.dp)
                            .semantics { contentDescription = description },
                    )
                }
            }
        }

        Spacer(Modifier.height(16.dp))
        Row(verticalAlignment = Alignment.Top) {
            Icon(
                imageVector = Icons.Rounded.Warning,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.error,
                modifier = Modifier.size(20.dp),
            )
            Spacer(Modifier.size(12.dp))
            Text(
                text = stringResource(R.string.recovery_warning),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.error,
            )
        }

        Spacer(Modifier.height(28.dp))
        PrimaryAction(
            text = stringResource(R.string.recovery_ack),
            onClick = onAcknowledge,
        )
    }
}

@Composable
private fun ModePickerDialog(
    current: AllowedAppsStore.ProtectionMode,
    onDismiss: () -> Unit,
    onSave: (AllowedAppsStore.ProtectionMode) -> Unit,
) {
    var selected by remember { mutableStateOf(current) }
    val options = listOf(
        AllowedAppsStore.ProtectionMode.BLOCK_SELECTED to R.string.mode_option_block,
        AllowedAppsStore.ProtectionMode.ALLOW_SELECTED to R.string.mode_option_allow,
    )

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.mode_dialog_title)) },
        text = {
            Column {
                options.forEach { (mode, label) ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 52.dp)
                            .selectable(
                                selected = selected == mode,
                                role = Role.RadioButton,
                                onClick = { selected = mode },
                            )
                            .padding(vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(selected = selected == mode, onClick = null)
                        Spacer(Modifier.size(12.dp))
                        Text(
                            text = stringResource(label),
                            style = MaterialTheme.typography.bodyLarge,
                        )
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onSave(selected) }) {
                Text(stringResource(R.string.action_save))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) }
        },
    )
}

/**
 * Radio picker for the display language. The two language names are autonyms, so
 * an operator can always recognise their own language even when the console is
 * currently showing one they cannot read.
 */
@Composable
private fun LanguagePickerDialog(
    current: LanguageChoice,
    onDismiss: () -> Unit,
    onSave: (LanguageChoice) -> Unit,
) {
    var selected by remember { mutableStateOf(current) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.language_dialog_title)) },
        text = {
            Column {
                LanguageChoice.entries.forEach { choice ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 52.dp)
                            .selectable(
                                selected = selected == choice,
                                role = Role.RadioButton,
                                onClick = { selected = choice },
                            )
                            .padding(vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(selected = selected == choice, onClick = null)
                        Spacer(Modifier.size(12.dp))
                        Text(
                            // A language name is written in its own script, so it
                            // is isolated and lets the bidi algorithm resolve its
                            // direction from its own first strong character.
                            text = stringResource(AppLocales.labelOf(choice)).bidiIsolated(),
                            style = MaterialTheme.typography.bodyLarge,
                        )
                    }
                }
                Spacer(Modifier.height(12.dp))
                Text(
                    text = stringResource(R.string.language_dialog_note),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        confirmButton = {
            TextButton(onClick = { onSave(selected) }) {
                Text(stringResource(R.string.action_save))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) }
        },
    )
}

@Composable
private fun AuditLogDialog(onDismiss: () -> Unit) {
    val context = LocalContext.current
    // Entries were recorded in whichever language was active at the time, so each
    // line is isolated on its own instead of inheriting the direction of the first.
    val entries = remember { bidiIsolatedLines(AuditLog.formatted(context).orEmpty()) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.audit_dialog_title)) },
        text = {
            Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                Text(text = entries, style = MaterialTheme.typography.bodyMedium)
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_close)) }
        },
    )
}

private fun statusTone(state: AllowedAppsStore.PolicyState): StatusTone = when (state) {
    AllowedAppsStore.PolicyState.ACTIVE -> StatusTone.VERIFIED
    AllowedAppsStore.PolicyState.APPLYING -> StatusTone.APPLYING
    AllowedAppsStore.PolicyState.FAILED -> StatusTone.FAILED
    else -> StatusTone.INACTIVE
}

private fun statusHeadline(state: AllowedAppsStore.PolicyState): Int = when (state) {
    AllowedAppsStore.PolicyState.ACTIVE -> R.string.status_headline_active
    AllowedAppsStore.PolicyState.APPLYING -> R.string.status_headline_applying
    AllowedAppsStore.PolicyState.FAILED -> R.string.status_headline_failed
    else -> R.string.status_headline_inactive
}

@Composable
private fun statusDetail(status: ConsoleStatus): String? =
    if (status.policyState == AllowedAppsStore.PolicyState.FAILED && status.policyError.isNotBlank()) {
        // The stored error comes from the policy layer and can hold restriction
        // names, package names and exception class names, so it is isolated before
        // it is embedded in the localized sentence.
        stringResource(R.string.status_detail, status.policyError.bidiIsolated())
    } else {
        null
    }

@Composable
private fun statusFacts(status: ConsoleStatus): List<Pair<String, String>> = listOf(
    stringResource(R.string.status_label_admin) to
        stringResource(if (status.deviceOwner) R.string.active else R.string.not_configured),
    stringResource(R.string.status_label_apps) to
        stringResource(
            if (status.allowlistConfigured) R.string.configured else R.string.configuration_required
        ),
)
