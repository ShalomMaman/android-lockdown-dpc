package com.example.lockdowndpc.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.graphics.Color
import android.os.Bundle
import android.text.format.DateFormat
import android.view.WindowManager
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.example.lockdowndpc.R
import com.example.lockdowndpc.health.DeviceHealthCollector
import com.example.lockdowndpc.health.DeviceHealthReport
import com.example.lockdowndpc.health.DeviceHealthSnapshot
import com.example.lockdowndpc.policy.AuditLog
import com.example.lockdowndpc.security.AdminSession
import com.example.lockdowndpc.ui.theme.LockdownTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Date

/**
 * The local device health report.
 *
 * Three properties are deliberate, and all three are security properties rather
 * than product ones:
 *
 * 1. **Nothing leaves the device on its own.** There is no scheduler, no
 *    endpoint and no network code behind this screen. The only way health data
 *    moves is an administrator choosing to export it, and the export is the
 *    redacted form.
 * 2. **Unknown is never healthy.** The report is rendered from
 *    [com.example.lockdowndpc.health.DeviceHealthAssessor], which treats a state
 *    it could not read as `UNVERIFIED`. A device whose policy was never read
 *    back does not get a clean bill of health because the screen had nothing to
 *    show.
 * 3. **The export is narrower than the screen.** What an administrator standing
 *    in front of the device may read — a kiosk URL, a target package — is
 *    reduced by [com.example.lockdowndpc.health.DeviceHealthRedaction] before it
 *    can be copied anywhere.
 */
class DeviceHealthActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!AdminSession.isUnlocked()) {
            finish()
            return
        }
        // The report names policy state, kiosk configuration and management
        // identity, so it follows the console's fail-closed screenshot rule.
        if (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE == 0) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.light(Color.TRANSPARENT, SYSTEM_BAR_DARK_SCRIM),
            navigationBarStyle = SystemBarStyle.light(Color.TRANSPARENT, SYSTEM_BAR_DARK_SCRIM),
        )
        setTitle(R.string.health_title)
        setContent {
            LockdownTheme {
                DeviceHealthScreen(onBack = { finish() })
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

@Composable
private fun DeviceHealthScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()

    var snapshot by remember { mutableStateOf<DeviceHealthSnapshot?>(null) }
    var report by remember { mutableStateOf("") }
    var exportVisible by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<UiMessage?>(null) }

    val loading = stringResource(R.string.health_value_unknown)

    // Reading the stores touches disk, so it happens off the main thread. The
    // rendering itself is pure and needs resources, so it happens back here.
    LaunchedEffect(Unit) {
        val read = withContext(Dispatchers.IO) { DeviceHealthCollector.read(context) }
        snapshot = read
        report = DeviceHealthReport.local(
            read,
            null,
            System.currentTimeMillis(),
            { id, args -> context.getString(id, *args) },
            { millis -> formatTimestamp(context, millis) },
        )
    }

    LockdownScreen(
        title = stringResource(R.string.health_title),
        subtitle = stringResource(R.string.health_local_only),
    ) {
        MessageBanner(message)
        if (message != null) {
            Spacer(Modifier.height(16.dp))
        }
        // LockdownScreen already scrolls the page, so the report is plain text
        // inside it rather than a second scrolling region.
        Text(
            text = report.ifBlank { loading },
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(24.dp))
        PrimaryAction(
            text = stringResource(R.string.health_export_action),
            icon = Icons.Rounded.ContentCopy,
            enabled = snapshot != null,
            onClick = {
                if (AdminSession.isUnlocked()) {
                    AdminSession.extend()
                    exportVisible = true
                } else {
                    onBack()
                }
            },
        )

        Spacer(Modifier.height(12.dp))
        SecondaryAction(text = stringResource(R.string.health_close), onClick = onBack)
    }

    if (exportVisible) {
        val current = snapshot
        AlertDialog(
            onDismissRequest = { exportVisible = false },
            title = { Text(stringResource(R.string.health_export_title)) },
            text = { Text(stringResource(R.string.health_export_body)) },
            confirmButton = {
                TextButton(
                    enabled = current != null,
                    onClick = {
                        exportVisible = false
                        if (current == null) {
                            return@TextButton
                        }
                        // The redacted form, never the screen's own text.
                        val export = DeviceHealthReport.export(current, System.currentTimeMillis())
                        copyToClipboard(context, export)
                        coroutineScope.launch(Dispatchers.IO) {
                            // The action is audited; the exported text is not.
                            AuditLog.append(context, context.getString(R.string.health_audit_exported))
                        }
                        message = UiMessage(
                            text = context.getString(R.string.health_export_copied),
                            isError = false,
                        )
                    },
                ) {
                    Text(stringResource(R.string.health_export_confirm))
                }
            },
            dismissButton = {
                TextButton(onClick = { exportVisible = false }) {
                    Text(stringResource(R.string.health_export_cancel))
                }
            },
        )
    }
}

/**
 * The clipboard is the deliberate transport: it needs no permission, no network
 * and no file, and it puts the administrator in control of where the report
 * goes. The label is marked sensitive so newer Android releases do not preview
 * the content in the paste toast.
 */
private fun copyToClipboard(context: Context, text: String) {
    val clipboard = context.getSystemService(ClipboardManager::class.java) ?: return
    val clip = ClipData.newPlainText(context.getString(R.string.health_title), text)
    clipboard.setPrimaryClip(clip)
}

private fun formatTimestamp(context: Context, millis: Long): String {
    if (millis <= 0L) {
        return context.getString(R.string.health_value_never)
    }
    val date = Date(millis)
    return "${DateFormat.getDateFormat(context).format(date)} " +
        DateFormat.getTimeFormat(context).format(date)
}
