# מסלול בנייה וחתימה ל־Production

מסלול ה־Production נפרד במכוון מהפיילוט הקיים:

- בנייה רגילה ממשיכה להשתמש בזהות `com.example.lockdowndpc` ובחתימת הפיתוח, ולכן יכולה לעדכן את מכשיר הפיילוט שכבר הוגדר כ־Device Owner.
- בניית Production משתמשת בזהות הזמנית `il.co.shalommaman.deviceguard` ודורשת מפתח חתימה חיצוני. הסודות והמפתח אינם נשמרים בריפוזיטורי.

> לפני מסירת המכשיר הראשון ללקוח יש לאשר סופית את שם החברה ואת ה־application ID. אחרי פרסום או provisioning אין לשנות אותם.

## הכנת מפתח

את קובץ המפתח שומרים בכספת ארגונית ובגיבוי מוצפן, מחוץ לתיקיית הפרויקט. את ארבעת הערכים הבאים מגדירים ב־CI secret store, במשתני סביבה מקומיים או בקובץ `~/.gradle/gradle.properties` שאינו חלק מהריפוזיטורי:

```properties
deviceGuardStoreFile=/absolute/secure/path/device-guard-production.jks
deviceGuardStorePassword=REDACTED
deviceGuardKeyAlias=device-guard-production
deviceGuardKeyPassword=REDACTED
```

לחלופין, משתני הסביבה הנתמכים הם:

```text
DEVICE_GUARD_STORE_FILE
DEVICE_GUARD_STORE_PASSWORD
DEVICE_GUARD_KEY_ALIAS
DEVICE_GUARD_KEY_PASSWORD
```

## בנייה

ה־init script הוא מתג מפורש: בלי `-I` מתקבל APK של הפיילוט; איתו מתקבל APK של Production.

```bash
./gradlew -I gradle/production.init.gradle.kts clean assembleRelease lintRelease test
```

יש לאמת לפני פרסום שה־APK קיבל את הזהות והחתימה הנכונות:

```bash
apkanalyzer manifest application-id app/build/outputs/apk/release/app-release.apk
apksigner verify --print-certs app/build/outputs/apk/release/app-release.apk
```

אין להפיץ APK אם ה־application ID אינו `il.co.shalommaman.deviceguard`, אם החתימה היא תעודת debug, או אם טביעת האצבע אינה תואמת לרישום המאושר של הארגון.

## Provisioning

ה־namespace של הקוד נשאר כרגע `com.example.lockdowndpc` כדי לא לשנות את רכיב הניהול של מכשיר הפיילוט. לכן ב־Production יש להשתמש בשם הרכיב המלא:

```bash
adb shell dpm set-device-owner \
  il.co.shalommaman.deviceguard/com.example.lockdowndpc.admin.LockdownAdminReceiver
```

אותו ערך מלא נדרש גם בשדה `android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME` של QR provisioning.

## אין שדרוג ישיר מהפיילוט

APK של Production הוא אפליקציה אחרת ואינו יכול לעדכן את `com.example.lockdowndpc`. בנוסף, Device Owner קשור לרכיב האדמין הקיים. מעבר של מכשיר פיילוט לזהות Production מחייב תהליך מעבר מתוכנן — בדרך כלל הסרת ניהול/איפוס יצרן ו־provisioning מחדש — ולא התקנת APK מעל הקיים.

מקורות רשמיים: [הגדרת application ID ו־namespace](https://developer.android.com/build/configure-app-module), [חתימת אפליקציות ועדכונים](https://developer.android.com/studio/publish/app-signing), [בניית DPC ו־ComponentName](https://developer.android.com/work/dpc/build-dpc).
