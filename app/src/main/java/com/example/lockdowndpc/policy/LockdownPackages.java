package com.example.lockdowndpc.policy;

import java.util.Collections;
import java.util.LinkedHashSet;
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

    private static Set<String> immutableSet(String... values) {
        LinkedHashSet<String> result = new LinkedHashSet<>();
        Collections.addAll(result, values);
        return Collections.unmodifiableSet(result);
    }
}
