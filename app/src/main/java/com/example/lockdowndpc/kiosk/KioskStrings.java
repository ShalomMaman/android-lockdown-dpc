package com.example.lockdowndpc.kiosk;

/**
 * Operator-facing text for the kiosk host.
 *
 * <p>Held here rather than in {@code res/values/strings.xml} because the kiosk
 * backend landed before its console integration; moving these into the shared
 * resource file is part of the UI wiring step.
 */
final class KioskStrings {

    static final String ERROR_TITLE = "מצב קיוסק אינו זמין";
    static final String ERROR_NOT_CONFIGURED = "לא הוגדרה תצורת קיוסק תקפה במכשיר זה.";
    static final String ERROR_TARGET_UNAVAILABLE =
            "היישום שהוגדר לקיוסק אינו זמין. פנו למנהל המערכת.";
    static final String ERROR_SITE_UNAVAILABLE =
            "לא ניתן לטעון את האתר שהוגדר. בדקו את החיבור לרשת ונסו שוב.";
    static final String ERROR_TLS =
            "החיבור המאובטח לאתר נכשל. הגישה נחסמה מטעמי בטיחות.";
    static final String ERROR_BLOCKED_NAVIGATION =
            "הניווט נחסם: היעד נמצא מחוץ לאתר שהוגדר.";
    static final String ERROR_DOWNLOAD_BLOCKED = "הורדות חסומות במצב קיוסק.";
    static final String RETRY = "נסו שוב";

    private KioskStrings() {}
}
