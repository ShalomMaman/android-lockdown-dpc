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
            AuditLog.append(context, "התעלמות מתוצאת התקנה ישנה או לא מזוהה")
            return
        }
        val versionName = snapshot.candidateVersion
        when (status) {
            PackageInstaller.STATUS_SUCCESS -> {
                if (SecureUpdateManager.isInstalledCandidate(context, snapshot)) {
                    UpdateStateStore.recordInstalled(context, versionName)
                    AuditLog.append(context, "עדכון $versionName הותקן בהצלחה")
                } else {
                    val message = "Android דיווח הצלחה אך הגרסה המותקנת לא תאמה למועמד"
                    UpdateStateStore.recordFailure(context, message)
                    AuditLog.append(context, message)
                }
            }
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                abandonPendingSession(context, intent)
                val message = "Android דרש אישור משתמש לעדכון; ההתקנה נעצרה"
                UpdateStateStore.recordFailure(context, message)
                AuditLog.append(context, message)
            }
            else -> {
                val message = "התקנת העדכון נכשלה (קוד $status)"
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
