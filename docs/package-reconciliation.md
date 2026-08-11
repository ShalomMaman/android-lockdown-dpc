# Reconciliation לאחר התקנת אפליקציות

ב־Android 8.0 ומעלה רוב שידורי החבילות המרומזים אינם נמסרים ל־receiver שמוצהר רק ב־manifest. לכן `PACKAGE_ADDED` הוסר מה־receiver הסטטי והועבר למקלט דינמי בתוך `LockdownDeviceAdminService`.

Android מחזיק חיבור ל־`DeviceAdminService` של Device Owner כל עוד המשתמש פעיל. אם התהליך נהרג עקב לחץ זיכרון, המערכת קושרת אותו מחדש לאחר backoff. השירות מבצע reconciliation מלא גם ב־`onCreate()`, כך שהפעלה מחדש מתקנת התקנות שאירעו בזמן שהתהליך לא היה זמין.

ההתנהגות לפי מצב המדיניות:

- במצב רשימה לבנה (`ALLOW_SELECTED`), כל אפליקציית צד שלישי חדשה מתווספת למלאי המנוהל ונחסמת כל עוד לא אושרה במפורש.
- במצב רשימה שחורה (`BLOCK_SELECTED`), חבילות חסומות מוכרות נחסמות מחדש, אבל אפליקציה אקראית חדשה מותרת מעצם הגדרת המצב.
- אם הגנה לא התבקשה, השירות אינו מחיל חסימה. הפעלה עתידית מבצעת סריקה מלאה ולא נשענת רק על היסטוריית broadcasts.

הפעולות מסודרות ב־executor יחיד ו־`apply()`/`pause()` מסונכרנות, כדי למנוע החלות מתחרות מאירוע התקנה, boot ומסך הניהול.

## מגבלה שנותרה

`PACKAGE_ADDED` מתקבל לאחר שהחבילה כבר הותקנה. לכן קיימת אפשרות לחלון קצר בין השלמת התקנה לבין הסתרת האפליקציה. כדי להשיג התקנה אטומית לחלוטין יש לשלוט גם במסלול ההתקנה עצמו (למשל managed app distribution), ולא לאפשר ADB או installer חיצוני בזמן הגנה. ההגבלות הקיימות על חנות, מקורות לא מוכרים ושליטה באפליקציות מצמצמות את החלון במסלול המשתמש הרגיל.

מקורות רשמיים: [`DeviceAdminService`](https://developer.android.com/reference/android/app/admin/DeviceAdminService), [חריגים והגבלות על implicit broadcasts](https://developer.android.com/develop/background-work/background-tasks/broadcasts/broadcast-exceptions), [`ACTION_PACKAGE_ADDED`](https://developer.android.com/reference/android/content/Intent#ACTION_PACKAGE_ADDED).
