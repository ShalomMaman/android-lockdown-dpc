package com.example.lockdowndpc.security;

/**
 * Removes invisible Unicode controls that can make an untrusted application
 * label reorder or conceal the trusted text rendered beside it.
 */
public final class AppLabelSanitizer {

    private AppLabelSanitizer() {}

    /**
     * Strips legacy bidi embeddings/overrides and isolate controls.
     *
     * <p>Device Guard supplies its own balanced isolate around labels at render
     * time. Retaining controls supplied by another application would let that
     * application close or nest that boundary, including through a label saved
     * by an older policy pass.
     */
    public static String sanitize(String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }
        StringBuilder sanitized = new StringBuilder(value.length());
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if ((character >= '\u202A' && character <= '\u202E')
                    || (character >= '\u2066' && character <= '\u2069')) {
                continue;
            }
            sanitized.append(character);
        }
        return sanitized.toString();
    }
}
