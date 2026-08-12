package com.example.lockdowndpc.kiosk;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

/**
 * Normalization and validation of single-site kiosk URLs.
 *
 * <p>Intentionally free of Android APIs ({@code android.net.Uri} is a device
 * stub on the JVM) so every rule here is provable by plain unit tests.
 *
 * <p>The accepted shape is deliberately narrow: an absolute, hierarchical,
 * credential-free HTTPS URL whose host survives IDNA conversion. Everything
 * else — {@code http}, {@code intent}, {@code javascript}, {@code data},
 * {@code blob}, {@code file}, {@code content}, custom app schemes, opaque URIs
 * and dot-segment paths — is rejected rather than repaired.
 */
public final class KioskUrl {

    public static final int HTTPS_DEFAULT_PORT = 443;
    private static final int MAX_LENGTH = 2000;
    private static final String HTTPS = "https";

    private KioskUrl() {}

    /** A URL that passed every rule, split into the parts the kiosk needs. */
    public record Normalized(String scheme, String host, int port, String url) {
        public KioskOrigin origin() {
            return new KioskOrigin(scheme, host, port);
        }
    }

    /** Either a {@link Normalized} URL or a stable machine-readable reason. */
    public record Result(Normalized value, String error) {
        public boolean ok() {
            return value != null;
        }

        static Result ok(Normalized value) {
            return new Result(value, null);
        }

        static Result fail(String error) {
            return new Result(null, error);
        }
    }

    public static Result normalize(String raw) {
        if (raw == null) {
            return Result.fail("missing-url");
        }
        String candidate = raw.trim();
        if (candidate.isEmpty()) {
            return Result.fail("missing-url");
        }
        if (candidate.length() > MAX_LENGTH) {
            return Result.fail("url-too-long");
        }
        for (int index = 0; index < candidate.length(); index++) {
            char character = candidate.charAt(index);
            // Whitespace, C0/C1 controls and backslashes are the usual carriers of
            // parser-confusion tricks such as "https://good\@evil".
            if (character <= 0x20 || character == 0x7f || (character >= 0x80 && character <= 0x9f)) {
                return Result.fail("illegal-character");
            }
            if (character == '\\') {
                return Result.fail("illegal-character");
            }
        }

        URI uri;
        try {
            uri = new URI(candidate);
        } catch (URISyntaxException exception) {
            return Result.fail("unparsable-url");
        }
        if (!uri.isAbsolute()) {
            return Result.fail("relative-url");
        }
        if (uri.isOpaque()) {
            // "https:portal" and every scheme-only form such as "javascript:..".
            return Result.fail("opaque-url");
        }

        String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
        if (!HTTPS.equals(scheme)) {
            return Result.fail("scheme-not-https");
        }
        if (uri.getRawUserInfo() != null) {
            return Result.fail("credentials-in-url");
        }

        String host = uri.getHost();
        if (host == null || host.isEmpty()) {
            // getHost() also returns null for authorities Java refuses to parse,
            // which is exactly the ambiguity a kiosk target must not carry.
            return Result.fail("missing-host");
        }
        String asciiHost = host.toLowerCase(Locale.ROOT);
        if (!asciiHost.startsWith("[")) {
            // ASCII-only by design. Rejecting non-ASCII hosts removes the whole
            // homograph class instead of trying to detect it; an operator with an
            // internationalized domain configures its punycode ("xn--") form.
            for (int index = 0; index < asciiHost.length(); index++) {
                char character = asciiHost.charAt(index);
                boolean legal = (character >= 'a' && character <= 'z')
                        || (character >= '0' && character <= '9')
                        || character == '-' || character == '.';
                if (!legal) {
                    return Result.fail("invalid-host");
                }
            }
            if (asciiHost.indexOf('.') < 0) {
                // A single-label host cannot be pinned to a public origin and is
                // usually a typo such as "https://portal".
                return Result.fail("invalid-host");
            }
        }

        int port = uri.getPort();
        if (port == -1) {
            port = HTTPS_DEFAULT_PORT;
        } else if (port < 1 || port > 65535) {
            return Result.fail("invalid-port");
        }

        String path = uri.getRawPath();
        if (path == null || path.isEmpty()) {
            path = "/";
        }
        if (!path.startsWith("/")) {
            return Result.fail("invalid-path");
        }
        if (hasDotSegment(path)) {
            return Result.fail("relative-path-segment");
        }

        StringBuilder url = new StringBuilder(HTTPS).append("://").append(asciiHost);
        if (port != HTTPS_DEFAULT_PORT) {
            url.append(':').append(port);
        }
        url.append(path);
        if (uri.getRawQuery() != null) {
            url.append('?').append(uri.getRawQuery());
        }
        if (uri.getRawFragment() != null) {
            url.append('#').append(uri.getRawFragment());
        }
        return Result.ok(new Normalized(HTTPS, asciiHost, port, url.toString()));
    }

    /** Lower-cased scheme of {@code raw}, or {@code ""} when it carries none. */
    public static String schemeOf(String raw) {
        if (raw == null) {
            return "";
        }
        String candidate = raw.trim();
        int separator = candidate.indexOf(':');
        if (separator <= 0) {
            return "";
        }
        String scheme = candidate.substring(0, separator);
        for (int index = 0; index < scheme.length(); index++) {
            char character = scheme.charAt(index);
            boolean legal = (character >= 'a' && character <= 'z')
                    || (character >= 'A' && character <= 'Z')
                    || (character >= '0' && character <= '9')
                    || character == '+' || character == '-' || character == '.';
            if (!legal) {
                return "";
            }
        }
        return scheme.toLowerCase(Locale.ROOT);
    }

    private static boolean hasDotSegment(String path) {
        for (String segment : path.split("/", -1)) {
            if (".".equals(segment) || "..".equals(segment)
                    || "%2e".equalsIgnoreCase(segment) || "%2e%2e".equalsIgnoreCase(segment)) {
                return true;
            }
        }
        return false;
    }
}
