package com.example.lockdowndpc.policy;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;

import java.security.MessageDigest;
import java.util.Locale;

/**
 * The one definition of "the identity of this installed package" that a risk
 * acceptance is recorded against and later re-checked against.
 *
 * <h2>Why this class exists</h2>
 *
 * <p>A {@link SystemAppRiskAcceptance} only works if the console that records it
 * and the policy engine that re-checks it compute <em>exactly</em> the same two
 * strings. They briefly did not: the console recorded the version as
 * {@code "versionName (versionCode)"} while the engine observed the bare
 * {@code versionName}, and the console hashed the first certificate of the
 * signing <em>history</em> (the oldest, for a rotated key) while the engine
 * collapsed a multi-entry history to the empty string. Either divergence made
 * {@code matches()} unsatisfiable, which silently revoked every opted-in system
 * package on every reconciliation — the failure mode of a comparison whose two
 * sides are written in two places.
 *
 * <p>So both sides call this class, and the format is defined once:
 *
 * <ul>
 *   <li><b>Version</b> is {@code "versionName (longVersionCode)"}. The name
 *       alone is not enough — OEMs ship updates that keep it — and the code
 *       alone is not readable in an audit dialog.</li>
 *   <li><b>Signer</b> is the SHA-256 of the <em>current</em> signing
 *       certificate: {@code apkContentsSigners} on API 28+, which for a rotated
 *       key is the certificate in use now rather than the oldest in the
 *       lineage. A package signed by several certificates at once has no single
 *       identity, so it yields {@code ""} — and an empty digest deliberately
 *       never satisfies {@link SystemAppRiskAcceptance#matches}, so such a
 *       package cannot be risk-accepted at all rather than being accepted on
 *       half its identity.</li>
 * </ul>
 *
 * <p>This is narrower on purpose than the management-trust path.
 * {@code LockdownPolicyController.signingCertificateDigests} collects the whole
 * history so a pinned management certificate keeps matching across a platform
 * -verified rotation; an acceptance is the opposite contract — it exists to
 * <em>detect</em> that the binary changed, so it compares the current
 * certificate only.
 */
public final class PackageIdentity {

    private PackageIdentity() {}

    /** The version string both the console records and the engine observes. */
    public static String versionText(String versionName, long versionCode) {
        return (versionName == null ? "" : versionName) + " (" + versionCode + ")";
    }

    /** {@link #versionText(String, long)} for an already-loaded {@code PackageInfo}. */
    public static String versionText(PackageInfo info) {
        long code = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
                ? info.getLongVersionCode()
                : legacyVersionCode(info);
        return versionText(info.versionName, code);
    }

    /**
     * The SHA-256 of the certificate the package is signed with right now, or
     * {@code ""} when it has no single current signer.
     */
    public static String currentSignerSha256(PackageManager pm, String packageName) {
        try {
            Signature current = null;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                PackageInfo info = pm.getPackageInfo(
                        packageName, PackageManager.GET_SIGNING_CERTIFICATES);
                SigningInfo signingInfo = info.signingInfo;
                if (signingInfo == null || signingInfo.hasMultipleSigners()) {
                    return "";
                }
                Signature[] signers = signingInfo.getApkContentsSigners();
                if (signers == null || signers.length != 1 || signers[0] == null) {
                    return "";
                }
                current = signers[0];
            } else {
                @SuppressWarnings("deprecation")
                PackageInfo info = pm.getPackageInfo(
                        packageName, PackageManager.GET_SIGNATURES);
                @SuppressWarnings("deprecation")
                Signature[] signatures = info.signatures;
                if (signatures == null || signatures.length != 1 || signatures[0] == null) {
                    return "";
                }
                current = signatures[0];
            }
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            return hex(sha256.digest(current.toByteArray()));
        } catch (PackageManager.NameNotFoundException | RuntimeException
                | java.security.NoSuchAlgorithmException exception) {
            // No digest observed. matches() treats an empty digest as never
            // matching, which is the fail-closed direction for an acceptance.
            return "";
        }
    }

    @SuppressWarnings("deprecation")
    private static long legacyVersionCode(PackageInfo info) {
        return info.versionCode;
    }

    private static String hex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            builder.append(String.format(Locale.ROOT, "%02x", value));
        }
        return builder.toString();
    }
}
