package com.example.lockdowndpc.policy;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Pure classification for the searchable application inventory (Issue #18).
 *
 * <p>Free of every Android framework type so it can be covered by plain JVM
 * unit tests. {@code ui/SystemAppInventory.kt} resolves the Android-specific
 * inputs — installed flags, the active input method, the active WebView
 * provider, the stored selections — and passes them in as plain values.
 *
 * <p>This does not replace {@link LockdownPackages#classify}, which stays the
 * seam {@link LockdownPolicyController} enforces against. This class decides
 * only what the console <em>shows</em> and what it lets an administrator
 * touch, and it is deliberately never less conservative than the enforcement
 * seam: every row it reports as {@link Classification#blockable()} is a row
 * the controller would actually act on, and every row the controller pins is
 * reported here as not blockable.
 *
 * <p>The safety tiers come from
 * {@code docs/production-roadmap.md#system-application-safety-model}: a
 * protected core that can never be blocked, packages the policy already has an
 * explicit rule for, a curated set of reviewed manageable system packages,
 * and everything else on an OEM build — visible for diagnosis, but failing
 * closed until an administrator explicitly accepts the identity risk.
 */
public final class SystemAppClassifier {

    private SystemAppClassifier() {}

    public enum Origin { USER, SYSTEM, UPDATED_SYSTEM }

    /** Safety tier from the roadmap's system-application safety model. */
    public enum Tier {
        /** Android, Device Guard, keyboard, WebView, management. Never blockable. */
        PROTECTED_CORE,
        /** A built-in catalogue already rules on this package; the rule is not hand-edited. */
        POLICY_RULED,
        /** A reviewed, non-essential system package an administrator may select directly. */
        KNOWN_MANAGEABLE,
        /** An OEM system package outside every catalogue. Fails closed. */
        UNCLASSIFIED_OEM,
        /** An ordinary third-party application. */
        ORDINARY
    }

    public enum RowState { ALLOWED, BLOCKED, PROTECTED }

    /** The console filters from the roadmap's planned administrator experience. */
    public enum Category { ALL, USER, SYSTEM, STORE, BROWSER, SOCIAL, MANAGEMENT, PROTECTED }

    /** Freshness of a previously recorded {@link SystemAppRiskAcceptance}. */
    public enum RiskAcceptanceStatus {
        /** No acceptance on file; the package fails closed. */
        NONE,
        /** Signer and version still match what the administrator accepted. */
        FRESH,
        /** Signer or version changed since the acceptance; fails closed again. */
        DRIFTED
    }

    /** Why a row is in the state it is in; resolved to display text by the UI layer. */
    public enum ReasonKey {
        PROTECTED_DEVICE_GUARD,
        PROTECTED_ESSENTIAL_SYSTEM,
        PROTECTED_MANAGEMENT_TRANSPORT,
        PROTECTED_ACTIVE_INPUT_METHOD,
        PROTECTED_ACTIVE_WEBVIEW_PROVIDER,
        ALWAYS_BLOCKED_CATALOG,
        KIOSK_ESCAPE_SURFACE,
        KNOWN_BROWSER_OR_SOCIAL_CATALOG,
        KNOWN_MANAGEABLE_SYSTEM,
        UNCLASSIFIED_OEM_NEEDS_RISK_ACCEPTANCE,
        UNCLASSIFIED_OEM_RISK_DRIFTED,
        UNCLASSIFIED_OEM_RISK_ACCEPTED,
        ORDINARY_APP
    }

    /** The device facts a row is classified from; nothing here reaches PackageManager. */
    public record PackageSnapshot(
            String packageName,
            boolean system,
            boolean updatedSystem,
            boolean installed,
            boolean hiddenByPolicy
    ) {
        public PackageSnapshot {
            if (packageName == null || packageName.isEmpty()) {
                throw new IllegalArgumentException("packageName is required");
            }
        }

        public boolean anySystem() {
            return system || updatedSystem;
        }
    }

    /**
     * Packages that are protected on <em>this</em> device, whatever a catalogue
     * says. The active input method and the active WebView provider are runtime
     * facts, not catalogue entries: a device using an OEM keyboard that is absent
     * from {@link LockdownPackages#ESSENTIAL_SYSTEM} must still never be able to
     * block it.
     */
    public record ProtectedContext(
            String ownPackageName,
            Set<String> essentialSystem,
            Set<String> managementPackageNames,
            String activeInputMethodPackage,
            String activeWebViewProviderPackage
    ) {
        public ProtectedContext {
            essentialSystem = essentialSystem == null ? Set.of() : Set.copyOf(essentialSystem);
            managementPackageNames =
                    managementPackageNames == null ? Set.of() : Set.copyOf(managementPackageNames);
            ownPackageName = ownPackageName == null ? "" : ownPackageName;
            activeInputMethodPackage =
                    activeInputMethodPackage == null ? "" : activeInputMethodPackage;
            activeWebViewProviderPackage =
                    activeWebViewProviderPackage == null ? "" : activeWebViewProviderPackage;
        }
    }

    /** The curated catalogues {@link LockdownPackages} already enforces against. */
    public record CatalogContext(
            Set<String> alwaysBlocked,
            Set<String> knownBrowserAndSocial,
            Set<String> kioskEscapeSurfaces
    ) {
        public CatalogContext {
            alwaysBlocked = alwaysBlocked == null ? Set.of() : Set.copyOf(alwaysBlocked);
            knownBrowserAndSocial =
                    knownBrowserAndSocial == null ? Set.of() : Set.copyOf(knownBrowserAndSocial);
            kioskEscapeSurfaces =
                    kioskEscapeSurfaces == null ? Set.of() : Set.copyOf(kioskEscapeSurfaces);
        }

        /** The catalogues as {@link LockdownPolicyController} actually reads them. */
        public static CatalogContext fromLockdownPackages() {
            return new CatalogContext(
                    LockdownPackages.ALWAYS_BLOCKED,
                    LockdownPackages.KNOWN_BROWSER_AND_SOCIAL,
                    LockdownPackages.KIOSK_ESCAPE_SURFACES
            );
        }
    }

    /**
     * @param blockable whether the console may let an administrator toggle this
     *                  row. False for everything the controller decides on its
     *                  own — a protected package, or one a built-in catalogue
     *                  already rules on — so the screen never shows a checkbox
     *                  whose state the policy engine would silently overrule.
     */
    public record Classification(
            Origin origin,
            Tier tier,
            RowState state,
            ReasonKey reasonKey,
            boolean blockable
    ) {}

    public static Origin originOf(PackageSnapshot snapshot) {
        if (snapshot.updatedSystem()) {
            return Origin.UPDATED_SYSTEM;
        }
        return snapshot.system() ? Origin.SYSTEM : Origin.USER;
    }

    /**
     * Whether a stored risk acceptance still applies. Only the signer digest and
     * the version are drift signals; the recorded prior state and firmware build
     * are audit context, not match criteria.
     */
    public static RiskAcceptanceStatus riskStatusOf(
            SystemAppRiskAcceptance stored,
            String observedSignerDigest,
            String observedVersion
    ) {
        if (stored == null) {
            return RiskAcceptanceStatus.NONE;
        }
        return stored.matches(observedSignerDigest, observedVersion)
                ? RiskAcceptanceStatus.FRESH
                : RiskAcceptanceStatus.DRIFTED;
    }

    /**
     * Classifies one row of the inventory.
     *
     * <p>Order matters and is the whole safety argument: the protected checks run
     * before every catalogue, the catalogues run before the manageable tier, and
     * an unrecognised system package is the last case rather than the default.
     *
     * @param effectivelyAllowed whether the package ends up allowed under the
     *                           protection mode and selection currently in force;
     *                           read only when the result is blockable
     * @param riskStatus         freshness of any advanced risk acceptance on file
     */
    public static Classification classify(
            PackageSnapshot snapshot,
            ProtectedContext protectedContext,
            CatalogContext catalog,
            boolean effectivelyAllowed,
            RiskAcceptanceStatus riskStatus
    ) {
        String packageName = snapshot.packageName();
        Origin origin = originOf(snapshot);

        if (packageName.equals(protectedContext.ownPackageName())) {
            return protectedRow(origin, ReasonKey.PROTECTED_DEVICE_GUARD);
        }
        if (protectedContext.essentialSystem().contains(packageName)) {
            return protectedRow(origin, ReasonKey.PROTECTED_ESSENTIAL_SYSTEM);
        }
        if (protectedContext.managementPackageNames().contains(packageName)) {
            return protectedRow(origin, ReasonKey.PROTECTED_MANAGEMENT_TRANSPORT);
        }
        if (packageName.equals(protectedContext.activeInputMethodPackage())) {
            return protectedRow(origin, ReasonKey.PROTECTED_ACTIVE_INPUT_METHOD);
        }
        if (packageName.equals(protectedContext.activeWebViewProviderPackage())) {
            return protectedRow(origin, ReasonKey.PROTECTED_ACTIVE_WEBVIEW_PROVIDER);
        }

        // The controller blocks these unconditionally, so the console reports the
        // rule rather than offering a checkbox it would overrule on the next pass.
        if (catalog.alwaysBlocked().contains(packageName)) {
            return ruledRow(origin, RowState.BLOCKED, ReasonKey.ALWAYS_BLOCKED_CATALOG);
        }
        if (catalog.knownBrowserAndSocial().contains(packageName)) {
            return ruledRow(origin, RowState.BLOCKED, ReasonKey.KNOWN_BROWSER_OR_SOCIAL_CATALOG);
        }
        // Hidden only while a kiosk profile is active; the kiosk profile owns it.
        if (catalog.kioskEscapeSurfaces().contains(packageName)) {
            return ruledRow(origin, RowState.BLOCKED, ReasonKey.KIOSK_ESCAPE_SURFACE);
        }

        if (!snapshot.anySystem()) {
            return new Classification(origin, Tier.ORDINARY,
                    stateOf(effectivelyAllowed), ReasonKey.ORDINARY_APP, true);
        }

        if (KNOWN_MANAGEABLE_SYSTEM.contains(packageName)) {
            return new Classification(origin, Tier.KNOWN_MANAGEABLE,
                    stateOf(effectivelyAllowed), ReasonKey.KNOWN_MANAGEABLE_SYSTEM, true);
        }

        // A system or updated-system package outside every catalogue: an OEM
        // component whose importance cannot be inferred from FLAG_SYSTEM alone.
        return switch (riskStatus) {
            case FRESH -> new Classification(origin, Tier.UNCLASSIFIED_OEM,
                    stateOf(effectivelyAllowed), ReasonKey.UNCLASSIFIED_OEM_RISK_ACCEPTED, true);
            case DRIFTED -> new Classification(origin, Tier.UNCLASSIFIED_OEM, RowState.BLOCKED,
                    ReasonKey.UNCLASSIFIED_OEM_RISK_DRIFTED, false);
            case NONE -> new Classification(origin, Tier.UNCLASSIFIED_OEM, RowState.BLOCKED,
                    ReasonKey.UNCLASSIFIED_OEM_NEEDS_RISK_ACCEPTANCE, false);
        };
    }

    /**
     * Whether selecting this row requires an explicit advanced risk acceptance
     * first. Only an unclassified OEM package does; a reviewed manageable system
     * package and an ordinary application do not.
     */
    public static boolean requiresRiskAcceptance(Classification classification) {
        return classification.tier() == Tier.UNCLASSIFIED_OEM;
    }

    private static Classification protectedRow(Origin origin, ReasonKey reason) {
        return new Classification(origin, Tier.PROTECTED_CORE, RowState.PROTECTED, reason, false);
    }

    private static Classification ruledRow(Origin origin, RowState state, ReasonKey reason) {
        return new Classification(origin, Tier.POLICY_RULED, state, reason, false);
    }

    private static RowState stateOf(boolean effectivelyAllowed) {
        return effectivelyAllowed ? RowState.ALLOWED : RowState.BLOCKED;
    }

    /**
     * Reviewed, non-essential system packages an administrator may select without
     * a per-device risk acceptance.
     *
     * <p>Membership is deliberately narrow: media players, galleries, games
     * portals, store-adjacent extras and assistant front ends. Nothing here
     * carries telephony, input, launcher, settings, permission, installer or
     * update responsibilities, which is what makes hiding one recoverable. A
     * package that is merely <em>probably</em> safe belongs in the unclassified
     * tier instead, where it fails closed until someone accepts the risk on the
     * firmware in front of them.
     *
     * <p>{@code SystemAppClassifierTest} pins this set disjoint from
     * {@link LockdownPackages#ESSENTIAL_SYSTEM}, {@link LockdownPackages#ALWAYS_BLOCKED}
     * and {@link LockdownPackages#KIOSK_ESCAPE_SURFACES}, so an addition here can
     * never quietly unprotect a package another catalogue pins.
     */
    public static final Set<String> KNOWN_MANAGEABLE_SYSTEM = immutableSet(
            "com.google.android.apps.photos",
            "com.google.android.music",
            "com.google.android.videos",
            "com.google.android.apps.magazines",
            "com.google.android.apps.books",
            "com.google.android.apps.tachyon",
            "com.google.android.play.games",
            "com.samsung.android.game.gamehome",
            "com.samsung.android.game.gametools",
            "com.samsung.android.themestore",
            "com.samsung.android.bixby.agent",
            "com.samsung.android.app.tips",
            "com.sec.android.app.music",
            "com.sec.android.app.videoplayer",
            "com.miui.player",
            "com.miui.video",
            "com.miui.gallery",
            "com.xiaomi.glgm",
            "com.heytap.music",
            "com.coloros.video"
    );

    /** "Application stores and installers." */
    public static final Set<String> STORE_PACKAGES = immutableSet(
            "com.android.vending",
            "com.sec.android.app.samsungapps",
            "com.xiaomi.mipicks",
            "com.huawei.appmarket",
            "com.oppo.market",
            "com.bbk.appstore",
            "com.amazon.venezia",
            "com.android.packageinstaller",
            "com.google.android.packageinstaller",
            "com.samsung.android.themestore"
    );

    /** "Browsers and web entry points." */
    public static final Set<String> BROWSER_PACKAGES = immutableSet(
            "com.android.chrome",
            "com.sec.android.app.sbrowser",
            "com.google.android.googlequicksearchbox",
            "com.android.browser",
            "com.mi.globalbrowser",
            "com.heytap.browser",
            "com.oppo.browser",
            "com.vivo.browser",
            "com.huawei.browser",
            "org.mozilla.firefox",
            "com.microsoft.emmx",
            "com.opera.browser",
            "com.opera.mini.native",
            "com.brave.browser",
            "com.duckduckgo.mobile.android",
            "com.vivaldi.browser",
            "com.kiwibrowser.browser",
            "com.UCMobile.intl",
            "com.google.android.webview",
            "com.android.webview",
            "com.android.htmlviewer"
    );

    /** "Social and communication applications." */
    public static final Set<String> SOCIAL_PACKAGES = immutableSet(
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
            "com.google.android.apps.youtube.music",
            "com.google.android.apps.tachyon"
    );

    /**
     * Whether a row belongs in {@code category}.
     *
     * <p>The facets are independent on purpose: a package can be both a system
     * component and a browser, and a protected row can still belong to a content
     * category, so the filters describe the same inventory from different angles
     * rather than partitioning it.
     */
    public static boolean matchesCategory(
            Classification classification,
            PackageSnapshot snapshot,
            ProtectedContext protectedContext,
            Category category
    ) {
        String packageName = snapshot.packageName();
        return switch (category) {
            case ALL -> true;
            case USER -> classification.origin() == Origin.USER;
            case SYSTEM -> snapshot.anySystem();
            case STORE -> STORE_PACKAGES.contains(packageName);
            case BROWSER -> BROWSER_PACKAGES.contains(packageName);
            case SOCIAL -> SOCIAL_PACKAGES.contains(packageName);
            case MANAGEMENT -> protectedContext.managementPackageNames().contains(packageName);
            case PROTECTED -> classification.state() == RowState.PROTECTED;
        };
    }

    private static Set<String> immutableSet(String... values) {
        LinkedHashSet<String> result = new LinkedHashSet<>();
        Collections.addAll(result, values);
        return Collections.unmodifiableSet(result);
    }
}
