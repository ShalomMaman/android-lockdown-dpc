package com.example.lockdowndpc.kiosk;

import java.util.Locale;

/**
 * A web origin as defined by scheme, host and effective port.
 *
 * <p>This is the containment unit for single-site kiosk: navigation is confined
 * to exactly this origin, so {@code https://portal.school.example} does not
 * imply {@code https://mail.school.example} or {@code http://portal.school.example}.
 */
public record KioskOrigin(String scheme, String host, int port) {

    public KioskOrigin {
        if (scheme == null || host == null) {
            throw new IllegalArgumentException("origin requires a scheme and a host");
        }
        scheme = scheme.toLowerCase(Locale.ROOT);
        host = host.toLowerCase(Locale.ROOT);
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("origin requires an effective port");
        }
    }

    /** Serialized form used for storage, logging and operator-facing messages. */
    public String value() {
        if (port == KioskUrl.HTTPS_DEFAULT_PORT && "https".equals(scheme)) {
            return scheme + "://" + host;
        }
        return scheme + "://" + host + ":" + port;
    }

    public boolean matches(KioskUrl.Normalized candidate) {
        return candidate != null
                && scheme.equals(candidate.scheme())
                && host.equals(candidate.host())
                && port == candidate.port();
    }
}
