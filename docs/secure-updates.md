# עדכונים מרחוק ללא ADB

האפליקציה כוללת ערוץ עדכון עצמי עבור מכשיר שמוגדר כ־`Device Owner`. הערוץ
מושבת כברירת מחדל ונפתח רק בבנייה שקיבלה גם כתובת HTTPS ל־manifest וגם מפתח
EC ציבורי לאימות המטא־דאטה.

## גבול האמון

שרת הקבצים אינו נחשב מהימן לבדו. לפני התקנה הלקוח דורש את כל התנאים הבאים:

1. ה־manifest חתום ב־ECDSA באמצעות מפתח המטא־דאטה האופליין.
2. שם החבילה זהה לאפליקציה המותקנת וקוד הגרסה גבוה יותר.
3. כתובת ה־APK וכל ההפניות משתמשות ב־HTTPS בלבד.
4. הגודל ו־SHA-256 של הקובץ תואמים ל־manifest החתום.
5. Android מצליח לקרוא את ה־APK, ושם החבילה, הגרסה ותעודת החתימה שלו זהים
   לערכים המאושרים ולאפליקציה המותקנת.
6. רק לאחר כל הבדיקות נפתחת `PackageInstaller.Session` עבור אותה חבילה.

כשל בכל שלב עוצר את ההתקנה ואינו משהה או משנה את מדיניות ההגנה. הבדיקה
מתוזמנת מיד לאחר bootstrap ולאחר מכן פעם ביום באמצעות `JobScheduler`; אין
שירות רשת קבוע בזיכרון. מנהל מורשה יכול להפעיל בדיקה ידנית ממסך הניהול.

## הגדרת בנייה

הערכים נתמכים כ־Gradle properties או כמשתני סביבה:

```text
deviceGuardUpdateManifestUrl / DEVICE_GUARD_UPDATE_MANIFEST_URL
deviceGuardUpdatePublicKey   / DEVICE_GUARD_UPDATE_PUBLIC_KEY
deviceGuardUpdatePublicKeySha256 / DEVICE_GUARD_UPDATE_PUBLIC_KEY_SHA256
```

המפתח הציבורי הוא SubjectPublicKeyInfo של EC בקידוד DER ולאחריו Base64 ללא
שורות. מפתח המטא־דאטה נפרד לחלוטין ממפתח חתימת ה־APK. לדוגמה, ליצירת זוג
P-256 מוצפן מחוץ לריפוזיטורי:

```bash
openssl genpkey -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-256 \
  -aes-256-cbc \
  -out /secure/offline/device-guard-update-ec.pem

openssl pkey \
  -in /secure/offline/device-guard-update-ec.pem \
  -pubout -outform DER \
  | openssl base64 -A
```

יש לשמור את המפתח הפרטי ואת הסיסמה בכספת ארגונית עם גיבוי מוצפן ובקרת גישה.
המפתח הציבורי אינו סוד וניתן להעבירו לבנייה. מסלול Production נכשל אם הגדרות
העדכון או הגדרות חתימת ה־APK חסרות.

## יצירת release

`tools/publish_update.py` בודק את זהות ה־APK ואת תעודת החתימה באמצעות כלי
Android הרשמיים לפני שהוא יוצר manifest. הוא אינו דורס קובץ קיים ללא `--force`.

```bash
./tools/publish_update.py \
  --apk /secure/releases/device-guard.apk \
  --apk-url https://HOST/releases/download/v0.4.2/device-guard.apk \
  --expected-package com.example.lockdowndpc \
  --expected-signer-sha256 CERTIFICATE_SHA256 \
  --private-key /secure/offline/device-guard-update-ec.pem \
  --expected-metadata-key-sha256 APPROVED_PUBLIC_KEY_DER_SHA256 \
  --key-passphrase-env DEVICE_GUARD_UPDATE_KEY_PASSWORD \
  --output /secure/releases/latest.json
```

מעלים את ה־APK לכתובת הגרסה הקבועה ואת `latest.json` לכתובת היציבה שהוטמעה
באפליקציה. פרסום מקצועי חייב להיות אטומי מבחינת הסדר: קודם APK בלתי־משתנה,
אחר כך manifest חתום שמפנה אליו.

ה־manifest כולל זמני הנפקה ותפוגה, ותוקפו מוגבל בצד הלקוח ל־91 ימים. כלי
הפרסום משתמש ב־30 ימים כברירת מחדל. יש לרענן את `latest.json` לפני התפוגה גם
אם לא יצאה גרסת APK חדשה. המכשיר שומר גם את קוד הגרסה החתום הגבוה ביותר שכבר
ראה, ולכן השרת אינו יכול להחזיר אותו ל־manifest ישן יותר לאחר שכבר ראה חדש.

## Bootstrap ו־rollback

לגרסה שכבר מותקנת במכשיר ואין בה updater נדרשת התקנת bootstrap אחת באמצעות
ADB. מאותו רגע העדכונים הרגילים אינם זקוקים למחשב, כל עוד המכשיר מחובר לרשת
וערוץ ה־HTTPS זמין.

Android אינו מאפשר להחליף application ID או תעודת חתימת APK בעדכון רגיל.
מכשיר הפיילוט נשאר ב־`com.example.lockdowndpc` ובחתימת הפיילוט; מכשירי לקוח
חדשים חייבים לעבור provisioning עם זהות ומפתח Production. תיקון או rollback
מופצים כגרסה חדשה עם `versionCode` גבוה יותר, ולא כהורדת גרסה.

ב־Android 9 ומעלה הלקוח מקבל סיבוב תעודה רק כאשר ה־APK החדש כולל signing
lineage מאומת שמכיל את החותם הנוכחי. חבילות עם כמה חותמים דורשות התאמה מדויקת
ואינן יכולות לסובב חתימות. כל סיבוב מפתח עדיין מחייב rehearsal במכשיר בדיקה
לפני פרסום ללקוחות.
