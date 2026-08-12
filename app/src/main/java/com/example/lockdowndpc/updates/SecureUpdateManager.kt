package com.example.lockdowndpc.updates

import android.app.PendingIntent
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import android.os.SystemClock
import com.example.lockdowndpc.policy.AuditLog
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.URL
import java.net.URI
import java.security.MessageDigest
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.HttpsURLConnection

enum class UpdateCheckResult { DISABLED, BUSY, UP_TO_DATE, INSTALLING, FAILED }

object SecureUpdateManager {
    const val ACTION_INSTALL_RESULT = "com.example.lockdowndpc.action.UPDATE_INSTALL_RESULT"
    private const val UPDATE_DIRECTORY = "secure-updates"
    private const val UPDATE_FILE = "device-guard-update.apk"
    private const val CONNECT_TIMEOUT_MS = 15_000
    private const val READ_TIMEOUT_MS = 30_000
    private const val MAX_HTTPS_REDIRECTS = 3
    private const val MANIFEST_DEADLINE_MS = 60_000L
    private const val APK_DEADLINE_MS = 10L * 60L * 1_000L
    private val operationLock = ReentrantLock()

    fun checkNow(context: Context): UpdateCheckResult = checkNow(context) { false }

    internal fun checkNow(
        context: Context,
        isCancelled: () -> Boolean,
    ): UpdateCheckResult {
        val appContext = context.applicationContext
        if (!UpdateConfig.isConfigured) {
            return UpdateCheckResult.DISABLED
        }
        if (!operationLock.tryLock()) {
            return UpdateCheckResult.BUSY
        }
        return try {
            performCheck(appContext, isCancelled)
        } catch (_: UpdateCancelledException) {
            clearCachedUpdate(appContext)
            UpdateStateStore.recordRetryPending(appContext)
            UpdateCheckResult.FAILED
        } catch (exception: Exception) {
            clearCachedUpdate(appContext)
            val reason = "update-check-failed:${exception.javaClass.simpleName}"
            UpdateStateStore.recordFailure(appContext, reason)
            AuditLog.append(appContext, reason)
            UpdateCheckResult.FAILED
        } finally {
            operationLock.unlock()
        }
    }

    /** Reconciles success even if process replacement prevented callback delivery. */
    @JvmStatic
    fun onPackageReplaced(context: Context) {
        val appContext = context.applicationContext
        val snapshot = UpdateStateStore.read(appContext)
        val currentVersion = try {
            currentPackageInfo(appContext).versionName.orEmpty()
        } catch (_: PackageManager.NameNotFoundException) {
            ""
        }
        if (snapshot.phase == UpdatePhase.INSTALLING && isInstalledCandidate(appContext, snapshot)) {
            UpdateStateStore.recordInstalled(appContext, currentVersion)
            AuditLog.append(appContext, "Update $currentVersion installed successfully")
        }
        clearCachedUpdate(appContext)
    }

    internal fun isInstalledCandidate(context: Context, snapshot: UpdateSnapshot): Boolean {
        if (snapshot.candidateVersion.isBlank() || snapshot.candidateVersionCode <= 0L) return false
        val current = try {
            currentPackageInfo(context)
        } catch (_: PackageManager.NameNotFoundException) {
            return false
        }
        return current.versionName.orEmpty() == snapshot.candidateVersion &&
            versionCodeOf(current) == snapshot.candidateVersionCode
    }

    private fun performCheck(context: Context, isCancelled: () -> Boolean): UpdateCheckResult {
        val dpm = context.getSystemService(DevicePolicyManager::class.java)
        if (dpm == null || !dpm.isDeviceOwnerApp(context.packageName)) {
            UpdateStateStore.recordFailure(context, "automatic-update-requires-device-owner")
            return UpdateCheckResult.FAILED
        }

        UpdateStateStore.recordChecking(context)
        val envelope = fetchBytes(
            UpdateConfig.manifestUrl,
            MAX_MANIFEST_BYTES,
            deadlineElapsed = SystemClock.elapsedRealtime() + MANIFEST_DEADLINE_MS,
            isCancelled = isCancelled,
        )
        val authorized = UpdateEnvelopeVerifier.verify(
            envelopeBytes = envelope,
            publicKeyBase64 = UpdateConfig.metadataPublicKey,
            expectedPackage = context.packageName,
            nowEpochSeconds = System.currentTimeMillis() / 1_000L,
        )
        val current = currentPackageInfo(context)
        val highestAuthorized = UpdateStateStore.highestAuthorizedVersion(context)
        if (authorized.versionCode < highestAuthorized) {
            throw UpdateVerificationException("manifest-version-rollback")
        }
        if (authorized.versionCode <= versionCodeOf(current)) {
            // The installed APK is already platform-verified; metadata alone
            // never gets to raise the persistent replay floor.
            UpdateStateStore.recordAuthorizedVersion(context, versionCodeOf(current))
            UpdateStateStore.recordUpToDate(context, current.versionName.orEmpty())
            return UpdateCheckResult.UP_TO_DATE
        }

        UpdateStateStore.recordDownloading(context, authorized.versionName)
        val apkDeadline = SystemClock.elapsedRealtime() + APK_DEADLINE_MS
        val apk = downloadAuthorizedApk(
            context,
            authorized,
            deadlineElapsed = apkDeadline,
            isCancelled = isCancelled,
        )
        ensureActive(apkDeadline, isCancelled)
        verifyArchive(context, apk, authorized)
        // Raise the floor only after hash, package, version and APK signer all
        // match the authorized candidate.
        UpdateStateStore.recordAuthorizedVersion(context, authorized.versionCode)
        ensureActive(apkDeadline, isCancelled)
        if (authorized.expiresAtEpochSeconds <= System.currentTimeMillis() / 1_000L) {
            throw UpdateVerificationException("update-manifest-expired-before-install")
        }
        commitSelfUpdate(context, apk, authorized)
        AuditLog.append(context, "Update ${authorized.versionName} verified and sent for install")
        return UpdateCheckResult.INSTALLING
    }

    private fun fetchBytes(
        url: String,
        maxBytes: Int,
        deadlineElapsed: Long,
        isCancelled: () -> Boolean,
    ): ByteArray {
        val connection = openHttps(url, deadlineElapsed, isCancelled)
        try {
            val length = connection.contentLengthLong
            if (length > maxBytes) {
                throw UpdateVerificationException("manifest-too-large")
            }
            connection.inputStream.use { input ->
                val output = java.io.ByteArrayOutputStream(minOf(maxBytes, 8 * 1024))
                val buffer = ByteArray(8 * 1024)
                var total = 0
                while (true) {
                    ensureActive(deadlineElapsed, isCancelled)
                    val read = input.read(buffer)
                    if (read < 0) break
                    total += read
                    if (total > maxBytes) {
                        throw UpdateVerificationException("manifest-too-large")
                    }
                    output.write(buffer, 0, read)
                }
                return output.toByteArray()
            }
        } finally {
            connection.disconnect()
        }
    }

    private fun downloadAuthorizedApk(
        context: Context,
        update: AuthorizedUpdate,
        deadlineElapsed: Long,
        isCancelled: () -> Boolean,
    ): File {
        val directory = File(context.cacheDir, UPDATE_DIRECTORY)
        if (!directory.exists() && !directory.mkdirs()) {
            throw java.io.IOException("Update cache unavailable")
        }
        val partial = File(directory, "$UPDATE_FILE.part")
        val target = File(directory, UPDATE_FILE)
        partial.delete()
        target.delete()

        val digest = MessageDigest.getInstance("SHA-256")
        val connection = openHttps(update.apkUrl, deadlineElapsed, isCancelled)
        try {
            val declaredLength = connection.contentLengthLong
            if (declaredLength >= 0L && declaredLength != update.apkSize) {
                throw UpdateVerificationException("apk-size-mismatch")
            }
            var total = 0L
            connection.inputStream.use { input ->
                FileOutputStream(partial).use { output ->
                    val buffer = ByteArray(16 * 1024)
                    while (true) {
                        ensureActive(deadlineElapsed, isCancelled)
                        val read = input.read(buffer)
                        if (read < 0) break
                        total += read
                        if (total > update.apkSize || total > MAX_APK_BYTES) {
                            throw UpdateVerificationException("apk-too-large")
                        }
                        digest.update(buffer, 0, read)
                        output.write(buffer, 0, read)
                    }
                    output.fd.sync()
                }
            }
            if (total != update.apkSize) {
                throw UpdateVerificationException("apk-download-truncated")
            }
            val expectedDigest = update.apkSha256.hexToBytes()
            if (!MessageDigest.isEqual(digest.digest(), expectedDigest)) {
                throw UpdateVerificationException("apk-sha256-mismatch")
            }
            if (!partial.renameTo(target)) {
                throw java.io.IOException("Unable to finalize update cache")
            }
            return target
        } catch (exception: Exception) {
            partial.delete()
            target.delete()
            throw exception
        } finally {
            connection.disconnect()
        }
    }

    private fun openHttps(
        url: String,
        deadlineElapsed: Long,
        isCancelled: () -> Boolean,
    ): HttpsURLConnection {
        var currentUrl = UpdateEnvelopeVerifier.requireCleanHttpsUrl(url)
        repeat(MAX_HTTPS_REDIRECTS + 1) { redirectCount ->
            ensureActive(deadlineElapsed, isCancelled)
            val connection = URL(currentUrl).openConnection() as HttpsURLConnection
            connection.instanceFollowRedirects = false
            val remaining = (deadlineElapsed - SystemClock.elapsedRealtime())
                .coerceIn(1L, Int.MAX_VALUE.toLong())
            connection.connectTimeout = minOf(CONNECT_TIMEOUT_MS.toLong(), remaining).toInt()
            connection.readTimeout = minOf(READ_TIMEOUT_MS.toLong(), remaining).toInt()
            connection.useCaches = false
            connection.setRequestProperty(
                "Accept",
                "application/json, application/vnd.android.package-archive",
            )
            val status = try {
                connection.responseCode
            } catch (exception: Exception) {
                connection.disconnect()
                throw exception
            }
            when (status) {
                HttpsURLConnection.HTTP_OK -> return connection
                HttpsURLConnection.HTTP_MOVED_PERM,
                HttpsURLConnection.HTTP_MOVED_TEMP,
                HttpsURLConnection.HTTP_SEE_OTHER,
                307,
                308,
                -> {
                    val location = connection.getHeaderField("Location")
                    connection.disconnect()
                    if (redirectCount == MAX_HTTPS_REDIRECTS || location.isNullOrBlank()) {
                        throw java.io.IOException("Too many or invalid HTTPS redirects")
                    }
                    val resolved = try {
                        URI(currentUrl).resolve(location).toString()
                    } catch (_: IllegalArgumentException) {
                        throw UpdateVerificationException("invalid-update-redirect-url")
                    }
                    currentUrl = UpdateEnvelopeVerifier.requireCleanHttpsUrl(resolved)
                }
                else -> {
                    connection.disconnect()
                    throw java.io.IOException("Unexpected HTTP status $status")
                }
            }
        }
        throw java.io.IOException("Unable to open update URL")
    }

    private fun ensureActive(deadlineElapsed: Long, isCancelled: () -> Boolean) {
        if (isCancelled() || SystemClock.elapsedRealtime() >= deadlineElapsed) {
            throw UpdateCancelledException()
        }
    }

    private fun verifyArchive(context: Context, apk: File, update: AuthorizedUpdate) {
        val packageManager = context.packageManager
        val archive = packageInfoForArchive(packageManager, apk)
            ?: throw UpdateVerificationException("android-could-not-read-apk")
        if (archive.packageName != context.packageName || archive.packageName != update.packageName) {
            throw UpdateVerificationException("apk-package-name-mismatch")
        }
        if (versionCodeOf(archive) != update.versionCode) {
            throw UpdateVerificationException("apk-version-code-mismatch")
        }
        if (archive.versionName.orEmpty() != update.versionName) {
            throw UpdateVerificationException("apk-version-name-mismatch")
        }
        val installed = currentPackageInfo(context)
        if (!isSignerAuthorized(installed, archive)) {
            throw UpdateVerificationException("apk-signer-mismatch")
        }
    }

    private fun commitSelfUpdate(context: Context, apk: File, update: AuthorizedUpdate) {
        val installer = context.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
        params.setAppPackageName(context.packageName)
        params.setSize(apk.length())
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            params.setInstallReason(PackageManager.INSTALL_REASON_POLICY)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            params.setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
        }
        val sessionId = installer.createSession(params)
        try {
            installer.openSession(sessionId).use { session ->
                FileInputStream(apk).use { input ->
                    session.openWrite("base.apk", 0L, apk.length()).use { output ->
                        input.copyTo(output, 16 * 1024)
                        session.fsync(output)
                    }
                }
                val callbackIntent = Intent(context, UpdateInstallReceiver::class.java)
                    .setAction(ACTION_INSTALL_RESULT)
                val pendingFlags = PendingIntent.FLAG_UPDATE_CURRENT or
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        PendingIntent.FLAG_MUTABLE
                    } else {
                        0
                    }
                val callback = PendingIntent.getBroadcast(
                    context,
                    sessionId,
                    callbackIntent,
                    pendingFlags,
                )
                UpdateStateStore.recordInstalling(
                    context,
                    update.versionName,
                    update.versionCode,
                    sessionId,
                )
                session.commit(callback.intentSender)
            }
        } catch (exception: Exception) {
            installer.abandonSession(sessionId)
            throw exception
        }
    }

    private fun currentPackageInfo(context: Context): PackageInfo {
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            @Suppress("DEPRECATION")
            PackageManager.GET_SIGNATURES
        }
        return context.packageManager.getPackageInfo(context.packageName, flags)
    }

    private fun packageInfoForArchive(pm: PackageManager, apk: File): PackageInfo? {
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            @Suppress("DEPRECATION")
            PackageManager.GET_SIGNATURES
        }
        @Suppress("DEPRECATION")
        return pm.getPackageArchiveInfo(apk.absolutePath, flags)
    }

    private fun isSignerAuthorized(installed: PackageInfo, archive: PackageInfo): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            @Suppress("DEPRECATION")
            return signatureDigests(installed.signatures) == signatureDigests(archive.signatures)
        }
        val installedSigning = installed.signingInfo
            ?: throw UpdateVerificationException("installed-apk-signing-info-missing")
        val archiveSigning = archive.signingInfo
            ?: throw UpdateVerificationException("new-apk-signing-info-missing")
        if (installedSigning.hasMultipleSigners() || archiveSigning.hasMultipleSigners()) {
            return installedSigning.hasMultipleSigners() &&
                archiveSigning.hasMultipleSigners() &&
                signatureDigests(installedSigning.apkContentsSigners) ==
                signatureDigests(archiveSigning.apkContentsSigners)
        }
        val installedCurrent = signatureDigests(installedSigning.apkContentsSigners)
        val authorizedHistory = signatureDigests(archiveSigning.signingCertificateHistory)
        return installedCurrent.isNotEmpty() && authorizedHistory.containsAll(installedCurrent)
    }

    private fun signatureDigests(signatures: Array<out android.content.pm.Signature>?): Set<String> {
        val presentSignatures = signatures ?: emptyArray()
        if (presentSignatures.isEmpty()) {
            throw UpdateVerificationException("apk-signing-info-missing")
        }
        return presentSignatures.mapTo(linkedSetOf()) { signature ->
            MessageDigest.getInstance("SHA-256")
                .digest(signature.toByteArray())
                .toHex()
        }
    }

    private fun versionCodeOf(info: PackageInfo): Long =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) info.longVersionCode
        else @Suppress("DEPRECATION") info.versionCode.toLong()

    private fun String.hexToBytes(): ByteArray {
        if (length % 2 != 0) throw UpdateVerificationException("invalid-sha256")
        return ByteArray(length / 2) { index ->
            substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { byte -> "%02x".format(byte) }

    fun clearCachedUpdate(context: Context) {
        val directory = File(context.cacheDir, UPDATE_DIRECTORY)
        File(directory, UPDATE_FILE).delete()
        File(directory, "$UPDATE_FILE.part").delete()
    }
}

private class UpdateCancelledException : Exception()
