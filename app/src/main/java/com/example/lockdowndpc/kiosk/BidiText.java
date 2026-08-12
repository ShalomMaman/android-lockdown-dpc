package com.example.lockdowndpc.kiosk;

/**
 * Unicode bidi isolation for the Java kiosk surface.
 *
 * <p>The Kotlin console has the same two helpers in {@code ui/UiLogic.kt}; they
 * cannot be shared because that file is {@code internal} Kotlin and this package
 * is deliberately free of console coupling. {@code BidiTextParityTest} pins the
 * two implementations to the same code points so they cannot drift.
 */
public final class BidiText {

    /** U+2066 LEFT-TO-RIGHT ISOLATE. */
    public static final char LTR_ISOLATE = '⁦';

    /** U+2068 FIRST STRONG ISOLATE. */
    public static final char FIRST_STRONG_ISOLATE = '⁨';

    /** U+2069 POP DIRECTIONAL ISOLATE. */
    public static final char POP_ISOLATE = '⁩';

    private BidiText() {}

    /**
     * Isolates known left-to-right content — a package name, a URL, a version —
     * so it keeps its own direction and its own punctuation order inside a
     * right-to-left paragraph. The platform equivalent of {@code <span dir="ltr">}.
     */
    public static String ltrIsolated(String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }
        return LTR_ISOLATE + value + POP_ISOLATE;
    }

    /**
     * Isolates content whose language is not known at build time — a third-party
     * application label — without forcing a direction: the bidi algorithm takes
     * the base direction from the first strong character. The platform equivalent
     * of {@code <bdi>}.
     */
    public static String bidiIsolated(String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }
        return FIRST_STRONG_ISOLATE + value + POP_ISOLATE;
    }
}
