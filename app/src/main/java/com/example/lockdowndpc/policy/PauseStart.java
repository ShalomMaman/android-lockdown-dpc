package com.example.lockdowndpc.policy;

/**
 * The start of a pause, in the one allowed order: the continuation evidence a
 * later pass would use to keep an allowed Chrome visible is removed, durably,
 * before the pause changes anything. If Android does not persist that removal,
 * the pause is refused and nothing changes; otherwise a pass after the pause
 * could treat itself as continuing a verified pass from before it.
 */
final class PauseStart {

    private PauseStart() {}

    static final String REFUSED_ERROR = "pause-refused:continuation-not-invalidated";

    interface Steps {
        /** Removes the continuation evidence; {@code false} when the commit failed. */
        boolean invalidateContinuation();

        void markPauseStarted();
    }

    /** @return whether the pause may proceed */
    static boolean begin(Steps steps) {
        if (!steps.invalidateContinuation()) {
            return false;
        }
        steps.markPauseStarted();
        return true;
    }
}
