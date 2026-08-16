package com.example.lockdowndpc.policy;

import java.util.Objects;
import java.util.function.BooleanSupplier;

/**
 * Repeats a policy read-back while Android propagates an asynchronous state
 * change, without turning an exhausted verification into success.
 */
final class BoundedVerificationRetry {
    private BoundedVerificationRetry() {}

    static boolean verify(
            int maxAttempts,
            BooleanSupplier verification,
            Runnable waitBeforeRetry
    ) {
        if (maxAttempts < 1) {
            throw new IllegalArgumentException("maxAttempts must be positive");
        }
        Objects.requireNonNull(verification, "verification");
        Objects.requireNonNull(waitBeforeRetry, "waitBeforeRetry");

        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            if (verification.getAsBoolean()) {
                return true;
            }
            if (attempt + 1 < maxAttempts) {
                waitBeforeRetry.run();
            }
        }
        return false;
    }
}
