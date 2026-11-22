package com.example.lockdowndpc.ui

import android.content.pm.ApplicationInfo
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.SystemBarStyle
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import com.example.lockdowndpc.R
import com.example.lockdowndpc.policy.AdminAuthority
import com.example.lockdowndpc.policy.BuiltInBlockExemptions
import com.example.lockdowndpc.policy.HomeFilterCertificate
import com.example.lockdowndpc.policy.HomeFilterController
import com.example.lockdowndpc.policy.HomeFilterPolicy
import com.example.lockdowndpc.policy.HomeFilterProbe
import com.example.lockdowndpc.security.AdminSession
import com.example.lockdowndpc.ui.theme.LockdownTheme
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException

class HomeFilterActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!AdminSession.isUnlocked()) {
            finish()
            return
        }
        if (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE == 0) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.light(Color.TRANSPARENT, SYSTEM_BAR_DARK_SCRIM),
            navigationBarStyle = SystemBarStyle.light(Color.TRANSPARENT, SYSTEM_BAR_DARK_SCRIM),
        )
        setTitle(R.string.home_filter_title)
        setContent { LockdownTheme { HomeFilterScreen(onBack = ::finish) } }
    }

    override fun onResume() {
        super.onResume()
        if (!AdminSession.isUnlocked()) finish()
    }
}

private enum class HomeFilterAction(val title: Int, val guidance: Int) {
    ENABLE(R.string.home_filter_enable, R.string.home_filter_confirm_enable),
    DISABLE(R.string.home_filter_disable, R.string.home_filter_confirm_disable),
    INSTALL_CA(R.string.home_filter_install_ca, R.string.home_filter_confirm_ca),
    REMOVE_CA(R.string.home_filter_remove_ca, R.string.home_filter_confirm_remove_ca),
}

@Composable
private fun HomeFilterScreen(onBack: () -> Unit) {
    val context = LocalContext.current.applicationContext
    val scope = rememberCoroutineScope()
    var snapshot by remember { mutableStateOf<HomeFilterController.Snapshot?>(null) }
    var revision by remember { mutableIntStateOf(0) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<Int?>(null) }
    var vpn by remember { mutableStateOf(HomeFilterPolicy.DEFAULT_VPN_PACKAGE) }
    var pac by remember { mutableStateOf("") }
    var signerPin by remember { mutableStateOf("") }
    var tailnetId by remember { mutableStateOf("") }
    var loginUrl by remember { mutableStateOf(HomeFilterPolicy.DEFAULT_LOGIN_URL) }
    var exitNodeId by remember { mutableStateOf("") }
    var organization by remember { mutableStateOf("") }
    var canaryUrl by remember { mutableStateOf("") }
    var canaryBody by remember { mutableStateOf("") }
    var probe by remember { mutableStateOf(HomeFilterPolicy.ProbeState.NOT_RUN) }
    var selectedCa by remember { mutableStateOf<String?>(null) }
    var confirm by remember { mutableStateOf<HomeFilterAction?>(null) }
    var pendingConfig by remember { mutableStateOf<HomeFilterPolicy.Config?>(null) }
    val supported = HomeFilterPolicy.supportedOn(Build.VERSION.SDK_INT)

    fun authorize(): Boolean {
        if (!AdminSession.isUnlocked()) {
            onBack()
            return false
        }
        AdminSession.extend()
        return true
    }

    fun applyPolicy(operation: (AdminAuthority) -> HomeFilterController.Snapshot) {
        if (busy || !authorize()) return
        val authority = AdminAuthority.localSession(context) ?: return
        busy = true
        probe = HomeFilterPolicy.ProbeState.NOT_RUN
        error = null
        scope.launch {
            try {
                snapshot = withContext(Dispatchers.IO) { operation(authority) }
                selectedCa = null
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (refused: HomeFilterController.FilterTeardownRefusedException) {
                error = when (refused.verdict()) {
                    BuiltInBlockExemptions.TeardownVerdict.APPROVAL_UNREADABLE ->
                        R.string.home_filter_chrome_approval_unreadable
                    BuiltInBlockExemptions.TeardownVerdict.CHROME_NOT_CONTAINED ->
                        R.string.home_filter_chrome_not_contained
                    else -> R.string.home_filter_chrome_approval_blocks_change
                }
            } catch (_: HomeFilterController.CorruptConfigurationException) {
                snapshot = null
                error = R.string.home_filter_corrupt_settings
            } catch (_: UnsupportedOperationException) {
                error = R.string.home_filter_requires_android_10
            } catch (_: Exception) {
                error = R.string.home_filter_operation_failed
            } finally {
                busy = false
                revision++
            }
        }
    }

    val certificatePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri != null && authorize()) {
            busy = true
            error = null
            selectedCa = null
            scope.launch {
                try {
                    selectedCa = withContext(Dispatchers.IO) {
                        context.contentResolver.openInputStream(uri)?.use(HomeFilterCertificate::read)
                            ?: throw IOException("No certificate stream")
                    }
                    if (snapshot?.settings()?.enabled() == true) {
                        confirm = HomeFilterAction.INSTALL_CA
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Exception) {
                    error = R.string.home_filter_invalid_ca
                } finally {
                    busy = false
                }
            }
        }
    }

    fun chooseCertificate() {
        if (!authorize()) return
        try {
            certificatePicker.launch(arrayOf("*/*"))
        } catch (_: RuntimeException) {
            error = R.string.home_filter_picker_unavailable
        }
    }

    DisposableEffect(context) {
        val detach = HomeFilterController.watch(context) { revision++ }
        onDispose { detach.run() }
    }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { revision++ }
    LaunchedEffect(revision, busy) {
        if (!busy && AdminSession.isUnlocked()) {
            probe = HomeFilterPolicy.ProbeState.NOT_RUN
            try {
                val android = withContext(Dispatchers.IO) { HomeFilterController.read(context) }
                snapshot = android
                val canary = android.settings().config()?.canary()
                if (canary != null && android.report().androidSettingsConfirmed(android.settings())) {
                    val result = withContext(Dispatchers.IO) { HomeFilterProbe.check(canary) }
                    val fresh = withContext(Dispatchers.IO) { HomeFilterController.read(context) }
                    snapshot = fresh
                    if (fresh.settings() == android.settings()) probe = result
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: HomeFilterController.CorruptConfigurationException) {
                snapshot = null
                error = R.string.home_filter_corrupt_settings
            } catch (_: Exception) {
                snapshot = null
                error = R.string.home_filter_operation_failed
            }
        }
    }
    LaunchedEffect(Unit) {
        while (AdminSession.isUnlocked()) delay(1000)
        onBack()
    }

    val current = snapshot
    LockdownScreen(
        title = stringResource(R.string.home_filter_title),
        subtitle = stringResource(R.string.home_filter_description),
    ) {
        if (current != null) {
            HomeFilterStatus(current, busy, probe)
            Spacer(Modifier.height(16.dp))
        }
        error?.let { Text(stringResource(it), color = MaterialTheme.colorScheme.error) }
        if (!supported) {
            Text(stringResource(R.string.home_filter_requires_android_10), color = MaterialTheme.colorScheme.error)
        }
        if (current != null && !current.settings().configured() && supported) {
            HomeFilterField(vpn, { vpn = it }, R.string.home_filter_vpn_package, busy, KeyboardType.Ascii)
            HomeFilterField(signerPin, { signerPin = it }, R.string.home_filter_signer_pin, busy, KeyboardType.Ascii)
            HomeFilterField(tailnetId, { tailnetId = it }, R.string.home_filter_tailnet_id, busy, KeyboardType.Ascii)
            HomeFilterField(loginUrl, { loginUrl = it }, R.string.home_filter_login_url, busy, KeyboardType.Uri)
            HomeFilterField(exitNodeId, { exitNodeId = it }, R.string.home_filter_exit_node, busy, KeyboardType.Ascii)
            HomeFilterField(organization, { organization = it }, R.string.home_filter_organization, busy)
            HomeFilterField(pac, { pac = it }, R.string.home_filter_pac_url, busy, KeyboardType.Uri)
            HomeFilterField(canaryUrl, { canaryUrl = it }, R.string.home_filter_canary_url, busy, KeyboardType.Uri)
            HomeFilterField(canaryBody, { canaryBody = it }, R.string.home_filter_canary_body, busy)
            TextButton(onClick = ::chooseCertificate, enabled = !busy) {
                Text(stringResource(R.string.home_filter_choose_ca))
            }
            if (selectedCa != null) {
                Text(stringResource(R.string.home_filter_ca_selected))
                TextButton(onClick = { selectedCa = null }, enabled = !busy) {
                    Text(stringResource(R.string.home_filter_clear_selection))
                }
            }
            PrimaryAction(
                text = stringResource(R.string.home_filter_enable),
                onClick = {
                    try {
                        val routing = HomeFilterPolicy.Routing(tailnetId, loginUrl, exitNodeId, organization)
                        val canary = if (canaryUrl.isBlank() && canaryBody.isBlank()) null
                            else HomeFilterPolicy.Canary(canaryUrl, canaryBody)
                        pendingConfig = HomeFilterPolicy.Config(vpn, pac, signerPin, routing, canary)
                        error = null
                        confirm = HomeFilterAction.ENABLE
                    } catch (_: IllegalArgumentException) {
                        error = R.string.home_filter_invalid_settings
                    }
                },
                enabled = !busy,
            )
        } else if (current?.settings()?.configured() == true) {
            val settings = current.settings()
            if (settings.enabled() && settings.config().routing() == null) {
                Text(stringResource(R.string.home_filter_routing_missing))
            }
            PrimaryAction(
                text = stringResource(R.string.home_filter_retry),
                onClick = { applyPolicy { HomeFilterController.retry(context, it) } },
                enabled = !busy,
            )
            if (settings.enabled()) {
                if (settings.ca() == null) {
                    TextButton(onClick = ::chooseCertificate, enabled = !busy) {
                        Text(stringResource(R.string.home_filter_choose_ca))
                    }
                } else if (!settings.removeCa()) {
                    TextButton(
                        onClick = { confirm = HomeFilterAction.REMOVE_CA },
                        enabled = !busy,
                    ) { Text(stringResource(R.string.home_filter_remove_ca)) }
                }
                TextButton(onClick = { confirm = HomeFilterAction.DISABLE }, enabled = !busy) {
                    Text(stringResource(R.string.home_filter_disable))
                }
            }
        }
        TextButton(onClick = onBack) { Text(stringResource(R.string.action_back)) }
    }

    confirm?.let { action ->
        AlertDialog(
            onDismissRequest = { confirm = null },
            title = { Text(stringResource(action.title)) },
            text = { Text(stringResource(action.guidance)) },
            confirmButton = {
                TextButton(onClick = {
                    confirm = null
                    val ca = selectedCa
                    when (action) {
                        HomeFilterAction.ENABLE -> {
                            pendingConfig?.let { config ->
                                applyPolicy { HomeFilterController.enable(context, it, config, ca) }
                            }
                            pendingConfig = null
                        }
                        HomeFilterAction.DISABLE ->
                            applyPolicy { HomeFilterController.disable(context, it) }
                        HomeFilterAction.INSTALL_CA -> if (ca != null) {
                            applyPolicy { HomeFilterController.installCa(context, it, ca) }
                        }
                        HomeFilterAction.REMOVE_CA ->
                            applyPolicy { HomeFilterController.removeCa(context, it) }
                    }
                }) { Text(stringResource(action.title)) }
            },
            dismissButton = {
                TextButton(onClick = { confirm = null }) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
        )
    }
}

@Composable
private fun HomeFilterField(
    value: String,
    onValueChange: (String) -> Unit,
    label: Int,
    busy: Boolean,
    keyboardType: KeyboardType = KeyboardType.Text,
) {
    val typography = MaterialTheme.typography.bodyLarge
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(stringResource(label)) },
        textStyle = if (keyboardType == KeyboardType.Text) typography
            else typography.copy(textDirection = TextDirection.Ltr),
        singleLine = true,
        enabled = !busy,
        modifier = Modifier.fillMaxWidth(),
        keyboardOptions = KeyboardOptions(keyboardType = keyboardType),
    )
}

@Composable
private fun HomeFilterStatus(
    snapshot: HomeFilterController.Snapshot,
    busy: Boolean,
    probe: HomeFilterPolicy.ProbeState,
) {
    val settings = snapshot.settings()
    val report = snapshot.report()
    val status = report.status(settings, probe)
    val headline = if (busy) R.string.home_filter_checking else when (status) {
        HomeFilterPolicy.Status.ANDROID_SETTINGS_CONFIRMED, HomeFilterPolicy.Status.PROBE_PENDING ->
            R.string.home_filter_confirmed
        HomeFilterPolicy.Status.FILTER_ACTIVE -> R.string.home_filter_active
        HomeFilterPolicy.Status.SETTINGS_UNCONFIRMED, HomeFilterPolicy.Status.PROBE_FAILED ->
            R.string.home_filter_inactive
        HomeFilterPolicy.Status.REMOVAL_PENDING -> R.string.home_filter_removal_pending
        HomeFilterPolicy.Status.OFF -> R.string.home_filter_off
    }
    val tone = when {
        busy -> StatusTone.APPLYING
        status == HomeFilterPolicy.Status.FILTER_ACTIVE ||
            status == HomeFilterPolicy.Status.ANDROID_SETTINGS_CONFIRMED -> StatusTone.VERIFIED
        status == HomeFilterPolicy.Status.PROBE_PENDING -> StatusTone.APPLYING
        settings.configured() -> StatusTone.FAILED
        else -> StatusTone.INACTIVE
    }
    val config = settings.config()
    val facts = if (config == null || busy) emptyList() else listOf(
        stringResource(R.string.home_filter_vpn_package) to config.vpnPackage().bidiIsolated(),
        stringResource(R.string.home_filter_pac_url) to config.pacUrl().bidiIsolated(),
        stringResource(R.string.home_filter_vpn_status) to stringResource(homeFilterState(report.vpn())),
        stringResource(R.string.home_filter_proxy_status) to stringResource(homeFilterState(report.proxy())),
        stringResource(R.string.home_filter_private_dns) to stringResource(homeFilterState(report.privateDns())),
        stringResource(
            if (settings.removeCa()) R.string.home_filter_ca_removal_status
            else R.string.home_filter_ca_status,
        ) to stringResource(homeFilterState(report.ca())),
        stringResource(
            if (settings.enabled()) R.string.home_filter_restrictions
            else R.string.home_filter_restrictions_removal,
        ) to stringResource(homeFilterState(report.restrictions())),
    ) + if (config.canary() != null && settings.enabled()) {
        val probeLabel = when (status) {
            HomeFilterPolicy.Status.FILTER_ACTIVE -> R.string.home_filter_probe_passed
            HomeFilterPolicy.Status.PROBE_FAILED -> R.string.home_filter_probe_failed
            HomeFilterPolicy.Status.PROBE_PENDING -> R.string.home_filter_probe_checking
            else -> R.string.home_filter_probe_not_run
        }
        listOf(stringResource(R.string.home_filter_probe_status) to stringResource(probeLabel))
    } else emptyList()
    PolicyStatusCard(tone, stringResource(headline), facts)
}

private fun homeFilterState(state: HomeFilterPolicy.State): Int = when (state) {
    HomeFilterPolicy.State.CONFIRMED -> R.string.home_filter_readback_confirmed
    HomeFilterPolicy.State.UNCONFIRMED -> R.string.home_filter_readback_unconfirmed
    HomeFilterPolicy.State.NOT_REQUESTED -> R.string.home_filter_readback_not_requested
    HomeFilterPolicy.State.MISSING_VPN -> R.string.home_filter_vpn_missing
    HomeFilterPolicy.State.HIDDEN_VPN -> R.string.home_filter_vpn_hidden
    HomeFilterPolicy.State.UNTRUSTED_VPN -> R.string.home_filter_vpn_untrusted
    HomeFilterPolicy.State.REFUSED -> R.string.home_filter_readback_refused
}
