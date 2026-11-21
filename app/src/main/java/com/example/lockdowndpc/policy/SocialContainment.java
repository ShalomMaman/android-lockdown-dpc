package com.example.lockdowndpc.policy;

import java.util.List;

/**
 * Contains one catalogue social package that has no verified exemption: hidden,
 * or — when Android refuses the hide, as it does for an active device
 * administrator — suspended. When both are refused the package stays
 * launchable, and the pass reports {@link #REFUSED_ERROR} for it.
 */
public final class SocialContainment {

    private SocialContainment() {}

    public static final String REFUSED_ERROR = "CONTAINMENT_REFUSED";

    public enum Result { HIDDEN, SUSPENDED, REFUSED }

    /** One package as Android reports it. Any call may throw. */
    public interface Gateway {
        void hide();

        boolean hidden();

        /** Asks Android to suspend; {@code false} when it refused. */
        boolean suspend();

        boolean suspended();
    }

    public static Result contain(String packageName, Gateway gateway, List<String> errors) {
        try {
            gateway.hide();
            if (gateway.hidden()) {
                return Result.HIDDEN;
            }
        } catch (RuntimeException ignored) {
            // Refused; fall back to suspension below.
        }
        try {
            if (gateway.suspend() && gateway.suspended()) {
                return Result.SUSPENDED;
            }
        } catch (RuntimeException ignored) {
            // Refused too; reported below.
        }
        errors.add(REFUSED_ERROR + ":" + packageName);
        return Result.REFUSED;
    }
}
