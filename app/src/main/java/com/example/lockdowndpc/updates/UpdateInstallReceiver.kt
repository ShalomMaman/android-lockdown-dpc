package com.example.lockdowndpc.updates

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import com.example.lockdowndpc.policy.AuditLog

class UpdateInstallReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != SecureUpdateManager.ACTION_INSTALL_RESULT) return
        val status = intent.getIntExtra(
            PackageInstaller.EXTRA_STATUS,
            PackageInstaller.STATUS_FAILURE,
        )
        val sessionId = intent.getIntExtra(PackageInstaller.EXTRA_SESSION_ID, -1)
        val snapshot = UpdateStateStore.read(context)
        if (sessionId < 0 || sessionId != snapshot.candidateSessionId) {
            AuditLog.append(context, "Ignored stale or unknown install result")
            return
        }
        val versionName = snapshot.candidateVersion
        when (status) {
            PackageInstaller.STATUS_SUCCESS -> {
                if (SecureUpdateManager.isInstalledCandidate(context, snapshot)) {
                    UpdateStateStore.recordInstalled(context, versionName)
                    AuditLog.append(context, "Update $versionName installed successfully")
                } else {
                    val message = "installed-version-did-not-match-candidate"
                    UpdateStateStore.recordFailure(context, message)
                    AuditLog.append(context, message)
                }
            }
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                abandonPendingSession(context, intent)
                val message = "update-install-requires-user-action"
                UpdateStateStore.recordFailure(context, message)
                AuditLog.append(context, message)
            }
            else -> {
                val message = "update-install-failed:$status"
                UpdateStateStore.recordFailure(context, message)
                AuditLog.append(context, message)
            }
        }
        SecureUpdateManager.clearCachedUpdate(context)
    }

    private fun abandonPendingSession(context: Context, intent: Intent) {
        val sessionId = intent.getIntExtra(PackageInstaller.EXTRA_SESSION_ID, -1)
        if (sessionId < 0) return
        try {
            context.packageManager.packageInstaller.abandonSession(sessionId)
        } catch (_: SecurityException) {
            // The platform may already have finalized or removed the session.
        } catch (_: IllegalStateException) {
            // Treat an already-finalized session as safely closed.
        } catch (_: IllegalArgumentException) {
            // The session identifier is no longer known to PackageInstaller.
        }
    }
}
