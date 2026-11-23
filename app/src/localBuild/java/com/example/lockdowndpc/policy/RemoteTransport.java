package com.example.lockdowndpc.policy;

import android.content.Context;
import android.content.Intent;

/** The local build has no remote transport or provisioning implementation. */
public final class RemoteTransport {
    private RemoteTransport() {}

    public static boolean mark(Context context, Intent request) {
        return false;
    }

    public static boolean store(Context context, Intent request) {
        return false;
    }

    public static void schedule(Context context) {}
}
