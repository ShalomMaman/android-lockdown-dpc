package com.example.lockdowndpc.kiosk;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;

/**
 * The one contract for reaching administration from inside kiosk.
 *
 * <p>Deliberately narrow:
 *
 * <ul>
 *   <li>The intent is always <em>explicit</em> — it names the console component,
 *       so it cannot be broadcast or picked up by another app.</li>
 *   <li>It carries no authority. The console still starts on its locked PIN
 *       screen; {@link #EXTRA_SOURCE} is a provenance hint for the audit log,
 *       never an authorization token.</li>
 *   <li>There is no secret code path and no hardcoded PIN. Leaving kiosk goes
 *       through {@link KioskController#requestExit} which requires an
 *       authenticated administrator session.</li>
 * </ul>
 */
public final class KioskAdminEntry {

    /** Action used only to tell the console it was opened from kiosk. */
    public static final String ACTION_ADMIN_ENTRY =
            "com.example.lockdowndpc.kiosk.action.ADMIN_ENTRY";

    public static final String EXTRA_SOURCE = "com.example.lockdowndpc.kiosk.extra.SOURCE";

    public static final String SOURCE_KIOSK_GESTURE = "kiosk-gesture";

    /**
     * Referenced by name rather than by class literal so the Java kiosk package
     * never has to compile against the Kotlin console (and vice versa).
     */
    private static final String CONSOLE_ACTIVITY = "com.example.lockdowndpc.ui.MainActivity";

    private KioskAdminEntry() {}

    public static Intent consoleIntent(Context context, String source) {
        Intent intent = new Intent(ACTION_ADMIN_ENTRY);
        intent.setComponent(new ComponentName(context.getPackageName(), CONSOLE_ACTIVITY));
        intent.putExtra(EXTRA_SOURCE, source);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
        return intent;
    }
}
