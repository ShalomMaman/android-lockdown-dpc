package com.example.lockdowndpc.ui

import android.content.pm.ApplicationInfo
import android.graphics.Color
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
import com.example.lockdowndpc.policy.HomeFilterCertificate
import com.example.lockdowndpc.policy.HomeFilterController
import com.example.lockdowndpc.policy.HomeFilterPolicy
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
    var selectedCa by remember { mutableStateOf<String?>(null) }
    var confirm by remember { mutableStateOf<HomeFilterAction?>(null) }

    fun authorize(): Boolean {
        if (!AdminSession.isUnlocked()) {
            onBack()
            return false
        }
        AdminSession.extend()
        return true
    }

    fun applyPolicy(operation: () -> HomeFilterController.Snapshot) {
        if (busy || !authorize()) return
        busy = true
        error = null
        scope.launch {
            try {
                snapshot = withContext(Dispatchers.IO) { operation() }
                selectedCa = null
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                error = R.string.home_filter_operation_failed
            } finally {
                busy = false
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
    LaunchedEffect(revision) {
        if (AdminSession.isUnlocked()) {
            try {
                snapshot = withContext(Dispatchers.IO) { HomeFilterController.read(context) }
            } catch (cancelled: CancellationException) {
                throw cancelled
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
            HomeFilterStatus(current, busy)
            Spacer(Modifier.height(16.dp))
        }
        error?.let { Text(stringResource(it), color = MaterialTheme.colorScheme.error) }
        if (current != null && !current.settings().configured()) {
            val ltrText = MaterialTheme.typography.bodyLarge.copy(textDirection = TextDirection.Ltr)
            OutlinedTextField(
                value = vpn,
                onValueChange = { vpn = it },
                label = { Text(stringResource(R.string.home_filter_vpn_package)) },
                textStyle = ltrText,
                singleLine = true,
                enabled = !busy,
                modifier = Modifier.fillMaxWidth(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
            )
            OutlinedTextField(
                value = pac,
                onValueChange = { pac = it },
                label = { Text(stringResource(R.string.home_filter_pac_url)) },
                textStyle = ltrText,
                singleLine = true,
                enabled = !busy,
                modifier = Modifier.fillMaxWidth(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
            )
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
                        HomeFilterPolicy.Config(vpn, pac)
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
            PrimaryAction(
                text = stringResource(R.string.home_filter_retry),
                onClick = { applyPolicy { HomeFilterController.retry(context) } },
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
                            val config = HomeFilterPolicy.Config(vpn, pac)
                            applyPolicy { HomeFilterController.enable(context, config, ca) }
                        }
                        HomeFilterAction.DISABLE ->
                            applyPolicy { HomeFilterController.disable(context) }
                        HomeFilterAction.INSTALL_CA -> if (ca != null) {
                            applyPolicy { HomeFilterController.installCa(context, ca) }
                        }
                        HomeFilterAction.REMOVE_CA ->
                            applyPolicy { HomeFilterController.removeCa(context) }
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
private fun HomeFilterStatus(snapshot: HomeFilterController.Snapshot, busy: Boolean) {
    val settings = snapshot.settings()
    val report = snapshot.report()
    val active = !busy && report.active(settings)
    val headline = when {
        busy -> R.string.home_filter_checking
        active -> R.string.home_filter_confirmed
        settings.enabled() -> R.string.home_filter_inactive
        settings.configured() -> R.string.home_filter_removal_pending
        else -> R.string.home_filter_off
    }
    val tone = when {
        busy -> StatusTone.APPLYING
        active -> StatusTone.VERIFIED
        settings.configured() -> StatusTone.FAILED
        else -> StatusTone.INACTIVE
    }
    val config = settings.config()
    val facts = if (config == null || busy) emptyList() else listOf(
        stringResource(R.string.home_filter_vpn_package) to config.vpnPackage().bidiIsolated(),
        stringResource(R.string.home_filter_pac_url) to config.pacUrl().bidiIsolated(),
        stringResource(R.string.home_filter_vpn_status) to stringResource(homeFilterState(report.vpn())),
        stringResource(R.string.home_filter_proxy_status) to stringResource(homeFilterState(report.proxy())),
        stringResource(
            if (settings.removeCa()) R.string.home_filter_ca_removal_status
            else R.string.home_filter_ca_status,
        ) to stringResource(homeFilterState(report.ca())),
        stringResource(
            if (settings.enabled()) R.string.home_filter_restrictions
            else R.string.home_filter_restrictions_removal,
        ) to stringResource(homeFilterState(report.restrictions())),
    )
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
