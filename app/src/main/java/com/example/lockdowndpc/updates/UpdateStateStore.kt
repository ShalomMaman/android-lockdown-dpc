package com.example.lockdowndpc.updates

import android.content.Context
import com.example.lockdowndpc.R

enum class UpdatePhase {
    DISABLED,
    IDLE,
    CHECKING,
    DOWNLOADING,
    INSTALLING,
    UP_TO_DATE,
    INSTALLED,
    FAILED,
}

data class UpdateSnapshot(
    val phase: UpdatePhase,
    val message: String,
    val candidateVersion: String,
    val candidateVersionCode: Long,
    val candidateSessionId: Int,
    val lastCheckedAt: Long,
)

object UpdateStateStore {
    private const val PREFS = "secure_updates"
    private const val KEY_PHASE = "phase"
    private const val KEY_MESSAGE = "message"
    private const val KEY_CANDIDATE = "candidate_version"
    private const val KEY_CANDIDATE_CODE = "candidate_version_code"
    private const val KEY_CANDIDATE_SESSION = "candidate_session_id"
    private const val KEY_LAST_CHECKED = "last_checked_at"
    private const val KEY_HIGHEST_AUTHORIZED_VERSION = "highest_authorized_version"

    @JvmStatic
    fun read(context: Context): UpdateSnapshot {
        val preferences = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val fallback = if (UpdateConfig.isConfigured) UpdatePhase.IDLE else UpdatePhase.DISABLED
        val phase = try {
            UpdatePhase.valueOf(preferences.getString(KEY_PHASE, fallback.name) ?: fallback.name)
        } catch (_: IllegalArgumentException) {
            fallback
        }
        return UpdateSnapshot(
            phase = if (!UpdateConfig.isConfigured) UpdatePhase.DISABLED else phase,
            message = preferences.getString(KEY_MESSAGE, "").orEmpty(),
            candidateVersion = preferences.getString(KEY_CANDIDATE, "").orEmpty(),
            candidateVersionCode = preferences.getLong(KEY_CANDIDATE_CODE, -1L),
            candidateSessionId = preferences.getInt(KEY_CANDIDATE_SESSION, -1),
            lastCheckedAt = preferences.getLong(KEY_LAST_CHECKED, 0L),
        )
    }

    fun recordChecking(context: Context) = write(
        context,
        UpdatePhase.CHECKING,
        context.getString(R.string.update_state_checking),
    )

    fun recordRetryPending(context: Context) = write(
        context,
        UpdatePhase.IDLE,
        context.getString(R.string.update_state_retry),
    )

    fun recordDownloading(context: Context, versionName: String) = write(
        context,
        UpdatePhase.DOWNLOADING,
        context.getString(R.string.update_state_downloading, versionName),
        versionName,
    )

    fun recordInstalling(
        context: Context,
        versionName: String,
        versionCode: Long,
        sessionId: Int,
    ) = write(
        context,
        UpdatePhase.INSTALLING,
        context.getString(R.string.update_state_installing, versionName),
        versionName,
        versionCode,
        sessionId,
        checked = true,
    )

    fun recordUpToDate(context: Context, currentVersion: String) = write(
        context,
        UpdatePhase.UP_TO_DATE,
        context.getString(R.string.update_state_current, currentVersion),
        checked = true,
    )

    fun recordInstalled(context: Context, versionName: String) = write(
        context,
        UpdatePhase.INSTALLED,
        context.getString(R.string.update_state_installed, versionName),
        checked = true,
    )

    fun recordFailure(context: Context, reason: String) = write(
        context,
        UpdatePhase.FAILED,
        reason,
        checked = true,
    )

    fun highestAuthorizedVersion(context: Context): Long =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getLong(KEY_HIGHEST_AUTHORIZED_VERSION, -1L)

    fun recordAuthorizedVersion(context: Context, versionCode: Long) {
        val preferences = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (versionCode > preferences.getLong(KEY_HIGHEST_AUTHORIZED_VERSION, -1L)) {
            preferences.edit().putLong(KEY_HIGHEST_AUTHORIZED_VERSION, versionCode).commit()
        }
    }

    private fun write(
        context: Context,
        phase: UpdatePhase,
        message: String,
        candidateVersion: String = "",
        candidateVersionCode: Long = -1L,
        candidateSessionId: Int = -1,
        checked: Boolean = false,
    ) {
        val editor = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_PHASE, phase.name)
            .putString(KEY_MESSAGE, message)
            .putString(KEY_CANDIDATE, candidateVersion)
            .putLong(KEY_CANDIDATE_CODE, candidateVersionCode)
            .putInt(KEY_CANDIDATE_SESSION, candidateSessionId)
        if (checked) {
            editor.putLong(KEY_LAST_CHECKED, System.currentTimeMillis())
        }
        editor.commit()
    }
}
