package com.example.lockdowndpc.ui

import android.content.ClipData
import android.content.ClipboardManager
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.lockdowndpc.R
import com.example.lockdowndpc.policy.RemotePolicyProjection
import com.example.lockdowndpc.policy.RemotePolicyRuntime
import com.example.lockdowndpc.remote.RemoteReanchor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
internal fun RemoteConsole(onSecureScreen: (Boolean) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val haptics = rememberHaptics()
    var status by remember { mutableStateOf(RemoteReanchor.Status()) }
    var showingRecovery by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val policyRefusal by RemotePolicyRuntime.policyRefusals.collectAsStateWithLifecycle()

    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        if (!busy) scope.launch {
            val latest = withContext(Dispatchers.IO) { RemotePolicyRuntime.reanchorStatus(context) }
            if (!busy) {
                if (latest.reason != status.reason) showingRecovery = RemoteReanchor.supports(latest.reason)
                status = latest
            }
        }
    }
    SideEffect { onSecureScreen(showingRecovery) }

    if (!showingRecovery) {
        LockdownScreen(
            title = stringResource(R.string.app_name),
            subtitle = stringResource(when {
                status.awaitingPolicy -> R.string.remote_reanchor_waiting_policy
                status.reason != null -> reanchorReason(status.reason?.code)
                else -> R.string.remote_policy_unavailable
            }),
        ) {
            val refusalMessage = when (policyRefusal) {
                RemotePolicyProjection.LOCALE_UNSUPPORTED -> R.string.remote_policy_locale_unsupported
                RemotePolicyProjection.FILTER_CLEANUP_LIMIT -> R.string.remote_policy_filter_cleanup_limit
                else -> null
            }
            if (refusalMessage != null) {
                MessageBanner(UiMessage(stringResource(refusalMessage), isError = true))
                Spacer(Modifier.height(12.dp))
            }
            if (RemoteReanchor.supports(status.reason)) {
                PrimaryAction(stringResource(R.string.remote_reanchor_title), onClick = {
                    haptics.tick()
                    error = null
                    showingRecovery = true
                    scope.launch {
                        val latest = withContext(Dispatchers.IO) { RemotePolicyRuntime.reanchorStatus(context) }
                        if (!busy && showingRecovery) status = latest
                    }
                })
            }
        }
        return
    }

    BackHandler { if (!busy) showingRecovery = false }
    val focus = LocalFocusManager.current
    val nonce = status.nonce
    var envelope by remember(nonce) { mutableStateOf("") }
    var root by remember(nonce) { mutableStateOf("") }
    LockdownScreen(
        title = stringResource(R.string.remote_reanchor_title),
        subtitle = stringResource(reanchorReason(status.reason?.code)),
        modifier = Modifier.imePadding(),
    ) {
        if (nonce != null) {
            val nonceLabel = stringResource(R.string.remote_reanchor_nonce)
            val ltr = LocalTextStyle.current.copy(textDirection = TextDirection.Ltr, textAlign = TextAlign.Left)
            Text(stringResource(R.string.remote_reanchor_instructions))
            Spacer(Modifier.height(12.dp))
            Text(nonceLabel)
            Text(nonce, modifier = Modifier.fillMaxWidth(), style = ltr)
            ConsoleTextAction(stringResource(R.string.remote_reanchor_copy), enabled = !busy, onClick = {
                val copied = runCatching {
                    requireNotNull(context.getSystemService(ClipboardManager::class.java))
                        .setPrimaryClip(ClipData.newPlainText(nonceLabel, nonce))
                }.isSuccess
                error = if (copied) null else "re-anchor-copy-failed"
                haptics.result(!copied)
            })
            if (status.needsRootFingerprint) {
                OutlinedTextField(
                    value = root,
                    onValueChange = { root = it.take(100) },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text(stringResource(R.string.remote_reanchor_root)) },
                    textStyle = ltr,
                    singleLine = true,
                    enabled = !busy,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
                )
                Spacer(Modifier.height(12.dp))
            }
            OutlinedTextField(
                value = envelope,
                onValueChange = {
                    envelope = it.take(RemoteReanchor.MAX_ENVELOPE_BYTES + 1)
                    error = null
                },
                modifier = Modifier.fillMaxWidth(),
                label = { Text(stringResource(R.string.remote_reanchor_document)) },
                textStyle = ltr,
                minLines = 3,
                maxLines = 6,
                enabled = !busy,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
            )
            Spacer(Modifier.height(16.dp))
            PrimaryAction(
                stringResource(R.string.remote_reanchor_submit),
                enabled = envelope.isNotBlank() && (!status.needsRootFingerprint || root.isNotBlank()),
                loading = busy,
                onClick = {
                    haptics.tick()
                    focus.clearFocus()
                    error = null
                    busy = true
                    scope.launch {
                        val (failure, refreshed) = withContext(Dispatchers.IO) {
                            val failure = RemotePolicyRuntime.reanchor(context, envelope.trim().toByteArray(), root.trim())
                            failure to RemotePolicyRuntime.reanchorStatus(context)
                        }
                        status = refreshed
                        busy = false
                        error = failure?.code
                        haptics.result(failure != null)
                        if (failure == null) showingRecovery = false
                    }
                },
            )
            Spacer(Modifier.height(12.dp))
        }
        val code = error ?: status.error?.code
        if (code != null) {
            MessageBanner(UiMessage(stringResource(reanchorError(code)), isError = true))
            Spacer(Modifier.height(12.dp))
        }
        SecondaryAction(stringResource(R.string.remote_reanchor_back), enabled = !busy,
            onClick = {
                haptics.tick()
                showingRecovery = false
            })
    }
}

private fun reanchorReason(code: String?) = when (code) {
    "journal-lost" -> R.string.remote_policy_journal_lost
    "journal-guard-missing" -> R.string.remote_reanchor_guard_missing
    "journal-guard-unreadable" -> R.string.remote_reanchor_guard_unreadable
    "journal-guard-mismatch" -> R.string.remote_reanchor_guard_mismatch
    "journal-guard-reenrolment-needed" -> R.string.remote_policy_reenrolment_needed
    else -> R.string.remote_policy_guard_blocked
}

private fun reanchorError(code: String) = when (code) {
    "re-anchor-pin-unavailable" -> R.string.remote_reanchor_reset_required
    "re-anchor-nonce-invalid" -> R.string.remote_reanchor_nonce_invalid
    "re-anchor-copy-failed" -> R.string.remote_reanchor_copy_failed
    "re-anchor-clock-unavailable" -> R.string.remote_reanchor_clock_unavailable
    "re-anchor-root-mismatch", "doc-signature-invalid" -> R.string.remote_reanchor_root_invalid
    "re-anchor-binding-mismatch" -> R.string.remote_reanchor_binding_invalid
    "re-anchor-floor-rollback" -> R.string.remote_reanchor_floors_invalid
    "journal-write-failed" -> R.string.remote_reanchor_write_failed
    else -> R.string.remote_reanchor_document_invalid
}
