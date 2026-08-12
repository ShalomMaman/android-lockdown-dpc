package com.example.lockdowndpc.policy;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class LockdownPackages {
    private LockdownPackages() {}

    /** System browsers, search surfaces and app stores that stay blocked. */
    public static final Set<String> ALWAYS_BLOCKED = immutableSet(
            "com.android.chrome",
            "com.sec.android.app.sbrowser",
            "com.google.android.googlequicksearchbox",
            "com.android.browser",
            "com.mi.globalbrowser",
            "com.heytap.browser",
            "com.oppo.browser",
            "com.vivo.browser",
            "com.huawei.browser",
            "com.android.vending",
            "com.sec.android.app.samsungapps",
            "com.xiaomi.mipicks",
            "com.huawei.appmarket",
            "com.oppo.market",
            "com.bbk.appstore",
            "com.amazon.venezia"
    );

    /** These are blocked by the third-party allowlist unless an administrator approves them. */
    public static final Set<String> KNOWN_BROWSER_AND_SOCIAL = immutableSet(
            "org.mozilla.firefox",
            "com.microsoft.emmx",
            "com.opera.browser",
            "com.opera.mini.native",
            "com.brave.browser",
            "com.duckduckgo.mobile.android",
            "com.vivaldi.browser",
            "com.kiwibrowser.browser",
            "com.UCMobile.intl",
            "com.facebook.katana",
            "com.facebook.lite",
            "com.instagram.android",
            "com.zhiliaoapp.musically",
            "com.ss.android.ugc.trill",
            "com.twitter.android",
            "com.snapchat.android",
            "com.reddit.frontpage",
            "com.pinterest",
            "com.linkedin.android",
            "com.discord",
            "org.telegram.messenger",
            "com.telegram.messenger",
            "com.whatsapp",
            "com.google.android.youtube",
            "com.google.android.apps.youtube.music"
    );

    /**
     * Packages Device Guard must never hide, suspend or take over.
     *
     * <p>Device Guard does not operate a "total system allowlist". Hiding every
     * system package bricks OEM devices in ways that are not recoverable from
     * the console, so the conservative default is: system packages are left
     * alone unless they appear in an explicit catalogue above, and the packages
     * below are protected even then.
     *
     * <p>This set is intentionally free of every package in
     * {@link #ALWAYS_BLOCKED} and {@link #KIOSK_ESCAPE_SURFACES};
     * {@code ManagementPackageTest} pins that so a future addition here cannot
     * silently unblock a store, a browser or an escape surface.
     */
    public static final Set<String> ESSENTIAL_SYSTEM = immutableSet(
            "android",
            "com.android.systemui",
            "com.android.settings",
            "com.android.providers.settings",
            "com.android.permissioncontroller",
            "com.google.android.permissioncontroller",
            "com.android.packageinstaller",
            "com.google.android.packageinstaller",
            "com.android.keychain",
            "com.android.certinstaller",
            "com.android.phone",
            "com.android.server.telecom",
            "com.android.providers.telephony",
            "com.android.emergency",
            "com.android.cellbroadcastreceiver",
            "com.android.inputmethod.latin",
            "com.google.android.inputmethod.latin",
            "com.sec.android.inputmethod",
            "com.google.android.webview",
            "com.android.webview",
            "com.google.android.gms",
            "com.google.android.gsf",
            "com.android.settings.intelligence",
            "com.samsung.android.incallui",
            "com.samsung.android.MtpApplication"
    );

    /**
     * Escape surfaces that must be hidden while a kiosk profile is active.
     *
     * <p>Lock Task already prevents navigating to most of these, but an app that
     * is reachable through a share sheet, an implicit intent or an OEM shortcut
     * is a real exit, so kiosk hides them and verifies the result. Packages in
     * {@link #ESSENTIAL_SYSTEM} always win: recoverability beats containment.
     */
    public static final Set<String> KIOSK_ESCAPE_SURFACES = immutableSet(
            "com.android.documentsui",
            "com.google.android.documentsui",
            "com.google.android.apps.nbu.files",
            "com.sec.android.app.myfiles",
            "com.mi.android.globalFileexplorer",
            "com.android.providers.downloads.ui",
            "com.google.android.apps.docs",
            "com.android.stk",
            "com.google.android.setupwizard",
            "com.android.htmlviewer"
    );

    /** How the policy engine treats a package. */
    public enum PackageClass {
        /** Never hidden, never suspended, never a kiosk target. */
        ESSENTIAL_SYSTEM_PACKAGE,
        /** Management connectivity that must survive policy changes. */
        MANAGEMENT,
        /** Hidden while kiosk is active. */
        KIOSK_ESCAPE_SURFACE,
        /** A system app an administrator explicitly opted into managing. */
        ADMIN_SELECTED_SYSTEM,
        /** Everything else; subject to the ordinary allow/block rules. */
        ORDINARY
    }

    /**
     * The classification seam.
     *
     * @param adminSelectedSystemPackages system packages an administrator has
     *                                    explicitly opted into managing; empty by
     *                                    default so upgrades change nothing
     */
    public static PackageClass classify(
            String packageName,
            Set<String> adminSelectedSystemPackages
    ) {
        if (packageName == null || packageName.isEmpty()) {
            return PackageClass.ORDINARY;
        }
        if (ESSENTIAL_SYSTEM.contains(packageName)) {
            return PackageClass.ESSENTIAL_SYSTEM_PACKAGE;
        }
        if (isManagementPackage(packageName)) {
            return PackageClass.MANAGEMENT;
        }
        if (KIOSK_ESCAPE_SURFACES.contains(packageName)) {
            return PackageClass.KIOSK_ESCAPE_SURFACE;
        }
        if (adminSelectedSystemPackages != null && adminSelectedSystemPackages.contains(packageName)) {
            return PackageClass.ADMIN_SELECTED_SYSTEM;
        }
        return PackageClass.ORDINARY;
    }

    /**
     * A critical management application, as a configuration record rather than a
     * package-name literal scattered through the policy engine.
     *
     * @param packageName               package that must keep working
     * @param approvedCertificateSha256 lower-case hex SHA-256 digests of approved
     *                                  signing certificates; empty means "identity
     *                                  is not proven", which is an explicit gap
     */
    public record ManagementPackage(String packageName, Set<String> approvedCertificateSha256) {
        public ManagementPackage {
            if (packageName == null || packageName.isEmpty()) {
                throw new IllegalArgumentException("A management package needs a package name");
            }
            LinkedHashSet<String> normalized = new LinkedHashSet<>();
            if (approvedCertificateSha256 != null) {
                for (String digest : approvedCertificateSha256) {
                    if (digest != null && !digest.isBlank()) {
                        normalized.add(normalizeDigest(digest));
                    }
                }
            }
            approvedCertificateSha256 = Collections.unmodifiableSet(normalized);
        }

        public boolean hasPinnedCertificate() {
            return !approvedCertificateSha256.isEmpty();
        }

        public ManagementPackage withPins(Set<String> digests) {
            return new ManagementPackage(packageName, digests);
        }
    }

    /**
     * Default management records.
     *
     * <p>Tailscale ships with no pinned certificate so the current pilot keeps
     * behaving exactly as it does today. That is a deliberate, documented proof
     * gap: until an operator configures a digest, the record authenticates a
     * package <em>name</em> and nothing else.
     */
    public static final List<ManagementPackage> MANAGEMENT_DEFAULTS = List.of(
            new ManagementPackage("com.tailscale.ipn", Set.of())
    );

    /** Result of comparing an installed signer against a management record. */
    public enum SignerVerdict {
        /** A digest is configured and the installed signer matches it. */
        MATCH,
        /** A digest is configured and no installed signer matches. Fail closed. */
        MISMATCH,
        /** No digest configured: package-name trust only. */
        UNPINNED,
        /** A digest is configured but the platform reported no signer at all. */
        UNKNOWN_SIGNER
    }

    public static boolean isManagementPackage(String packageName) {
        return managementPackage(packageName) != null;
    }

    public static ManagementPackage managementPackage(String packageName) {
        for (ManagementPackage record : MANAGEMENT_DEFAULTS) {
            if (record.packageName().equals(packageName)) {
                return record;
            }
        }
        return null;
    }

    public static Set<String> managementPackageNames() {
        LinkedHashSet<String> names = new LinkedHashSet<>();
        for (ManagementPackage record : MANAGEMENT_DEFAULTS) {
            names.add(record.packageName());
        }
        return Collections.unmodifiableSet(names);
    }

    /**
     * Merges administrator-configured certificate pins into the defaults.
     * Configuration only ever tightens a record; it cannot add a new management
     * package, because that would be a privilege grant from preferences.
     */
    public static List<ManagementPackage> managementPackages(Map<String, Set<String>> configuredPins) {
        if (configuredPins == null || configuredPins.isEmpty()) {
            return MANAGEMENT_DEFAULTS;
        }
        java.util.ArrayList<ManagementPackage> merged = new java.util.ArrayList<>();
        for (ManagementPackage record : MANAGEMENT_DEFAULTS) {
            Set<String> pins = configuredPins.get(record.packageName());
            merged.add(pins == null || pins.isEmpty() ? record : record.withPins(pins));
        }
        return Collections.unmodifiableList(merged);
    }

    /**
     * Fails closed: once a digest is configured, an unmatched or absent signer is
     * never treated as the management package.
     *
     * @param observedCertificateSha256 digests of the signers the platform reports
     */
    public static SignerVerdict verifySigner(
            ManagementPackage record,
            Set<String> observedCertificateSha256
    ) {
        if (record == null) {
            return SignerVerdict.MISMATCH;
        }
        if (!record.hasPinnedCertificate()) {
            return SignerVerdict.UNPINNED;
        }
        if (observedCertificateSha256 == null || observedCertificateSha256.isEmpty()) {
            return SignerVerdict.UNKNOWN_SIGNER;
        }
        for (String observed : observedCertificateSha256) {
            if (observed != null
                    && !observed.isBlank()
                    && record.approvedCertificateSha256().contains(normalizeDigest(observed))) {
                return SignerVerdict.MATCH;
            }
        }
        return SignerVerdict.MISMATCH;
    }

    /** Only {@link SignerVerdict#MATCH} and {@link SignerVerdict#UNPINNED} grant trust. */
    public static boolean grantsManagementTrust(SignerVerdict verdict) {
        return verdict == SignerVerdict.MATCH || verdict == SignerVerdict.UNPINNED;
    }

    /** Accepts colon-separated or spaced hex digests and lower-cases them. */
    public static String normalizeDigest(String digest) {
        return digest == null
                ? ""
                : digest.replace(":", "").replace(" ", "").trim().toLowerCase(Locale.ROOT);
    }

    private static Set<String> immutableSet(String... values) {
        LinkedHashSet<String> result = new LinkedHashSet<>();
        Collections.addAll(result, values);
        return Collections.unmodifiableSet(result);
    }
}
