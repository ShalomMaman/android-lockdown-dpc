package com.example.lockdowndpc.ui;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.admin.DevicePolicyManager;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.graphics.Color;
import android.os.Bundle;
import android.text.InputFilter;
import android.text.InputType;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import com.example.lockdowndpc.R;
import com.example.lockdowndpc.policy.AllowedAppsStore;
import com.example.lockdowndpc.policy.AuditLog;
import com.example.lockdowndpc.policy.LockdownPolicyController;
import com.example.lockdowndpc.security.AdminPinStore;
import com.example.lockdowndpc.security.AdminSession;

public final class MainActivity extends Activity {
    private TextView status;
    private TextView message;
    private Screen screen;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        renderInitialScreen();
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (screen == Screen.ADMIN) {
            if (!AdminSession.isUnlocked()) {
                renderLockedScreen();
            } else {
                updateStatus();
            }
        } else if (screen == Screen.RECOVERY && !AdminSession.isUnlocked()) {
            renderLockedScreen();
        } else if (screen == Screen.ENROLLMENT && isDeviceOwner()) {
            renderInitialScreen();
        }
    }

    private void renderInitialScreen() {
        if (!isDeviceOwner()) {
            renderEnrollmentRequired();
        } else if (!AdminPinStore.hasPin(this)) {
            renderPinSetup(false);
        } else {
            renderLockedScreen();
        }
    }

    private void renderEnrollmentRequired() {
        setSecureScreen(false);
        screen = Screen.ENROLLMENT;
        LinearLayout content = baseContent(
                "נדרשת הפעלת ניהול מלא",
                "האפליקציה הותקנה, אך עדיין אינה יכולה לאכוף חסימות. טכנאי השירות צריך להשלים הרשמה מאובטחת באמצעות QR או USB."
        );
        TextView note = text(
                "לאחר השלמת ההרשמה ניתן יהיה להגדיר קוד מנהל ולבחור את שיטת החסימה.",
                16,
                Color.rgb(80, 88, 101)
        );
        content.addView(note, matchWrap());
        showContent(content);
    }

    private void renderPinSetup(boolean replacingExistingPin) {
        setSecureScreen(true);
        screen = Screen.PIN_SETUP;
        LinearLayout content = baseContent(
                replacingExistingPin ? "שינוי קוד מנהל" : "הגדרת קוד מנהל",
                "יש לבחור קוד בן 6 עד 12 ספרות. הקוד יידרש לשינוי הרשימה או להשהיית ההגנה."
        );

        EditText pin = pinField("קוד מנהל חדש");
        EditText confirmation = pinField("אימות הקוד");
        content.addView(pin, matchWrap());
        addWithTopMargin(content, confirmation, 10);

        message = messageView();
        addWithTopMargin(content, message, 10);

        Button save = button(replacingExistingPin ? "שמירת הקוד החדש" : "שמירת הקוד והמשך");
        save.setOnClickListener(view -> {
            if (replacingExistingPin && !requireAdminSession()) {
                return;
            }
            String first = pin.getText().toString();
            String second = confirmation.getText().toString();
            if (!AdminPinStore.isValidPin(first)) {
                showMessage("הקוד חייב להכיל 6 עד 12 ספרות.", true);
                return;
            }
            if (!first.equals(second)) {
                showMessage("שני הקודים אינם זהים.", true);
                return;
            }
            try {
                AdminPinStore.setNewPin(this, first);
                String recoveryCode = AdminPinStore.rotateRecoveryCode(this);
                AuditLog.append(this, replacingExistingPin
                        ? "קוד המנהל הוחלף"
                        : "קוד המנהל הוגדר");
                pin.setText("");
                confirmation.setText("");
                unlockAdminSession();
                renderRecoveryCode(recoveryCode);
            } catch (RuntimeException exception) {
                showMessage("לא ניתן לשמור את הקוד במכשיר.", true);
            }
        });
        addWithTopMargin(content, save, 14);

        if (replacingExistingPin) {
            Button cancel = button("ביטול");
            cancel.setOnClickListener(view -> {
                if (requireAdminSession()) {
                    renderAdminPanel();
                }
            });
            addWithTopMargin(content, cancel, 8);
        }

        showContent(content);
    }

    private void renderLockedScreen() {
        setSecureScreen(true);
        screen = Screen.LOCKED;
        AdminSession.lock();
        LinearLayout content = baseContent(
                "ניהול ההגנה",
                "הגדרות המכשיר נעולות. יש להזין את קוד המנהל כדי לבצע שינויים."
        );

        status = text("", 17, Color.rgb(25, 30, 38));
        styleStatus(status);
        content.addView(status, matchWrap());

        EditText pin = pinField("קוד מנהל");
        addWithTopMargin(content, pin, 16);

        message = messageView();
        addWithTopMargin(content, message, 8);

        Button unlock = button("כניסה לניהול");
        unlock.setOnClickListener(view -> verifyAndUnlock(pin));
        addWithTopMargin(content, unlock, 12);

        updateStatus();
        showContent(content);
    }

    private void verifyAndUnlock(EditText pin) {
        AdminPinStore.Verification result = AdminPinStore.verify(this, pin.getText().toString());
        pin.setText("");
        switch (result.status()) {
            case SUCCESS -> {
                unlockAdminSession();
                if (result.usedRecoveryCode()) {
                    renderPinSetup(true);
                } else {
                    renderAdminPanel();
                }
            }
            case INVALID -> showMessage("קוד מנהל שגוי.", true);
            case LOCKED -> showMessage(lockoutMessage(result.remainingMillis()), true);
            case NOT_CONFIGURED -> renderPinSetup(false);
            case ERROR -> showMessage("לא ניתן לאמת את הקוד. יש לפנות למנהל המכשיר.", true);
        }
    }

    private void renderAdminPanel() {
        if (!AdminSession.isUnlocked()) {
            renderLockedScreen();
            return;
        }
        setSecureScreen(false);
        screen = Screen.ADMIN;
        extendAdminSession();
        LinearLayout content = baseContent(
                "מגן המכשיר",
                modeDescription()
        );

        status = text("", 17, Color.rgb(25, 30, 38));
        styleStatus(status);
        content.addView(status, matchWrap());

        message = messageView();
        addWithTopMargin(content, message, 10);

        Button mode = button("שיטת החסימה: " + modeLabel());
        mode.setOnClickListener(view -> {
            if (requireAdminSession()) {
                showModePicker();
            }
        });
        addWithTopMargin(content, mode, 14);

        Button choose = button(AllowedAppsStore.getProtectionMode(this)
                == AllowedAppsStore.ProtectionMode.ALLOW_SELECTED
                ? "בחירת אפליקציות מותרות"
                : "בחירת אפליקציות לחסימה");
        choose.setOnClickListener(view -> {
            if (!requireAdminSession()) {
                return;
            }
            extendAdminSession();
            startActivity(new Intent(this, AllowedAppsActivity.class));
        });
        addWithTopMargin(content, choose, 10);

        Button apply = button(AllowedAppsStore.isProtectionEnabled(this)
                ? "שמירה ורענון ההגנה"
                : "הפעלת ההגנה");
        apply.setOnClickListener(view -> applyProtection());
        addWithTopMargin(content, apply, 10);

        if (AllowedAppsStore.isProtectionEnabled(this)) {
            Button pause = button("השהיית ההגנה");
            pause.setOnClickListener(view -> pauseProtection());
            addWithTopMargin(content, pause, 10);
        }

        Button changePin = button("שינוי קוד מנהל");
        changePin.setOnClickListener(view -> {
            if (requireAdminSession()) {
                renderPinSetup(true);
            }
        });
        addWithTopMargin(content, changePin, 10);

        Button recovery = button("יצירת קוד שחזור חדש");
        recovery.setOnClickListener(view -> {
            if (!requireAdminSession()) {
                return;
            }
            try {
                AuditLog.append(this, "נוצר קוד שחזור חדש");
                renderRecoveryCode(AdminPinStore.rotateRecoveryCode(this));
            } catch (RuntimeException exception) {
                showMessage("לא ניתן ליצור קוד שחזור במכשיר.", true);
            }
        });
        addWithTopMargin(content, recovery, 10);

        Button audit = button("יומן פעולות ניהול");
        audit.setOnClickListener(view -> {
            if (!requireAdminSession()) {
                return;
            }
            new AlertDialog.Builder(this)
                    .setTitle("יומן פעולות ניהול")
                    .setMessage(AuditLog.formatted(this))
                    .setPositiveButton("סגירה", null)
                    .show();
        });
        addWithTopMargin(content, audit, 10);

        Button lock = button("נעילת מסך הניהול");
        lock.setOnClickListener(view -> renderLockedScreen());
        addWithTopMargin(content, lock, 10);

        TextView help = text(
                AllowedAppsStore.getProtectionMode(this) == AllowedAppsStore.ProtectionMode.ALLOW_SELECTED
                        ? "Tailscale ורכיבי המערכת החיוניים נשמרים תמיד. אפליקציה חדשה תיחסם עד לאישור מנהל."
                        : "Tailscale ורכיבי המערכת החיוניים נשמרים תמיד. התקנות חדשות דורשות אישור מנהל.",
                14,
                Color.rgb(96, 103, 115)
        );
        help.setPadding(0, dp(24), 0, 0);
        content.addView(help, matchWrap());

        updateStatus();
        showContent(content);
    }

    private void renderRecoveryCode(String recoveryCode) {
        if (!AdminSession.isUnlocked()) {
            renderLockedScreen();
            return;
        }
        setSecureScreen(true);
        screen = Screen.RECOVERY;
        LinearLayout content = baseContent(
                "קוד שחזור חד־פעמי",
                "יש למסור את הקוד רק למנהל האחראי ולשמור אותו במקום בטוח. יצירת קוד חדש מבטלת את הקוד הקודם."
        );

        TextView code = text(recoveryCode, 28, Color.rgb(23, 78, 166));
        code.setTextIsSelectable(true);
        code.setTextDirection(TextView.TEXT_DIRECTION_LTR);
        code.setPadding(dp(16), dp(24), dp(16), dp(24));
        code.setBackgroundColor(Color.rgb(238, 243, 251));
        content.addView(code, matchWrap());

        TextView warning = text(
                "הקוד יוצג רק במסך הזה. לאחר שימוש בו יהיה חובה להגדיר קוד מנהל חדש.",
                15,
                Color.rgb(176, 32, 37)
        );
        addWithTopMargin(content, warning, 14);

        Button recorded = button("רשמתי את הקוד");
        recorded.setOnClickListener(view -> {
            if (requireAdminSession()) {
                renderAdminPanel();
            }
        });
        addWithTopMargin(content, recorded, 16);
        showContent(content);
    }

    private void applyProtection() {
        if (!requireAdminSession()) {
            return;
        }
        extendAdminSession();
        if (!AllowedAppsStore.isAllowlistConfigured(this)) {
            showMessage("לפני ההפעלה יש לבחור ולשמור את רשימת האפליקציות.", true);
            startActivity(new Intent(this, AllowedAppsActivity.class));
            return;
        }
        LockdownPolicyController.PolicyResult result = LockdownPolicyController.apply(this);
        if (!result.deviceOwner()) {
            showMessage(getString(R.string.not_device_owner), true);
            return;
        }
        if (!result.applied()) {
            renderAdminPanel();
            showMessage(getString(
                    R.string.policy_failed,
                    result.errors().isEmpty() ? "שגיאה לא ידועה" : result.errors().get(0)
            ), true);
            return;
        }
        AuditLog.append(this, "מדיניות ההגנה הופעלה או רועננה");
        renderAdminPanel();
        showMessage(getString(R.string.policy_applied, result.blockedPackages()), false);
    }

    private void pauseProtection() {
        if (!requireAdminSession()) {
            return;
        }
        extendAdminSession();
        LockdownPolicyController.PolicyResult result = LockdownPolicyController.pause(this);
        if (!result.deviceOwner()) {
            showMessage(getString(R.string.not_device_owner), true);
            return;
        }
        if (!result.applied()) {
            renderAdminPanel();
            showMessage("השהיית ההגנה לא אומתה: "
                    + (result.errors().isEmpty() ? "שגיאה לא ידועה" : result.errors().get(0)), true);
            return;
        }
        AuditLog.append(this, "מדיניות ההגנה הושהתה");
        renderAdminPanel();
        showMessage("ההגנה הושהתה ואומתה. מסך הניהול נשאר נעול בקוד.", false);
    }

    private void showModePicker() {
        String[] options = {
                "חסום רק אפליקציות שסומנו",
                "אפשר רק אפליקציות שסומנו"
        };
        int selected = AllowedAppsStore.getProtectionMode(this)
                == AllowedAppsStore.ProtectionMode.BLOCK_SELECTED ? 0 : 1;
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("בחירת שיטת חסימה")
                .setSingleChoiceItems(options, selected, null)
                .setPositiveButton("שמירה", (dialogInterface, ignored) -> {
                    AlertDialog current = (AlertDialog) dialogInterface;
                    int checked = current.getListView().getCheckedItemPosition();
                    AllowedAppsStore.setProtectionMode(
                            this,
                            checked == 1
                                    ? AllowedAppsStore.ProtectionMode.ALLOW_SELECTED
                                    : AllowedAppsStore.ProtectionMode.BLOCK_SELECTED
                    );
                    AuditLog.append(this, checked == 1
                            ? "נבחר מצב: רק אפליקציות מותרות"
                            : "נבחר מצב: חסימת אפליקציות מסומנות");
                    renderAdminPanel();
                })
                .setNegativeButton("ביטול", null)
                .create();
        dialog.show();
    }

    private String modeLabel() {
        return AllowedAppsStore.getProtectionMode(this)
                == AllowedAppsStore.ProtectionMode.ALLOW_SELECTED
                ? "רק אפליקציות מותרות"
                : "חסימת אפליקציות מסומנות";
    }

    private String modeDescription() {
        return AllowedAppsStore.getProtectionMode(this)
                == AllowedAppsStore.ProtectionMode.ALLOW_SELECTED
                ? "רק אפליקציות שנבחרו במפורש יהיו זמינות בזמן ההגנה."
                : "האפליקציות שתסומנו ייחסמו בזמן ההגנה; שאר האפליקציות יישארו פעילות.";
    }

    private void updateStatus() {
        if (status == null) {
            return;
        }
        DevicePolicyManager dpm = getSystemService(DevicePolicyManager.class);
        boolean owner = dpm != null && dpm.isDeviceOwnerApp(getPackageName());
        boolean configured = AllowedAppsStore.isAllowlistConfigured(this);
        String policyStatus = switch (AllowedAppsStore.getPolicyState(this)) {
            case ACTIVE -> getString(R.string.policy_state_active);
            case APPLYING -> getString(R.string.policy_state_applying);
            case FAILED -> getString(R.string.policy_state_failed);
            case INACTIVE -> getString(R.string.not_enabled);
        };
        status.setText(getString(
                R.string.status_format_with_allowlist,
                getString(owner ? R.string.active : R.string.not_configured),
                policyStatus,
                getString(configured ? R.string.configured : R.string.configuration_required)
        ));
    }

    private boolean isDeviceOwner() {
        DevicePolicyManager dpm = getSystemService(DevicePolicyManager.class);
        return dpm != null && dpm.isDeviceOwnerApp(getPackageName());
    }

    private void unlockAdminSession() {
        AdminSession.unlock();
    }

    private void extendAdminSession() {
        AdminSession.extend();
    }

    private boolean requireAdminSession() {
        if (AdminSession.isUnlocked()) {
            return true;
        }
        renderLockedScreen();
        return false;
    }

    private String lockoutMessage(long remainingMillis) {
        long seconds = Math.max(1L, (remainingMillis + 999L) / 1_000L);
        if (seconds < 60L) {
            return "יותר מדי ניסיונות. ניתן לנסות שוב בעוד " + seconds + " שניות.";
        }
        long minutes = (seconds + 59L) / 60L;
        return "יותר מדי ניסיונות. ניתן לנסות שוב בעוד " + minutes + " דקות.";
    }

    private LinearLayout baseContent(String titleValue, String subtitleValue) {
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(24), dp(36), dp(24), dp(36));
        content.setLayoutDirection(LinearLayout.LAYOUT_DIRECTION_RTL);

        content.addView(text(titleValue, 30, Color.rgb(23, 78, 166)), matchWrap());
        TextView subtitle = text(subtitleValue, 17, Color.rgb(80, 88, 101));
        subtitle.setPadding(0, dp(10), 0, dp(24));
        content.addView(subtitle, matchWrap());
        return content;
    }

    private EditText pinField(String hint) {
        EditText field = new EditText(this);
        field.setHint(hint);
        field.setTextSize(18);
        field.setSingleLine(true);
        field.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
        field.setFilters(new InputFilter[]{new InputFilter.LengthFilter(12)});
        field.setSaveEnabled(false);
        field.setImportantForAutofill(EditText.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        return field;
    }

    private TextView messageView() {
        TextView view = text("", 15, Color.rgb(25, 105, 55));
        view.setMinHeight(dp(22));
        return view;
    }

    private void showMessage(String value, boolean error) {
        if (message != null) {
            message.setTextColor(error ? Color.rgb(176, 32, 37) : Color.rgb(25, 105, 55));
            message.setText(value);
        }
    }

    private void styleStatus(TextView view) {
        view.setBackgroundColor(Color.rgb(238, 243, 251));
        view.setPadding(dp(16), dp(16), dp(16), dp(16));
    }

    private Button button(String label) {
        Button button = new Button(this);
        button.setText(label);
        button.setTextSize(16);
        return button;
    }

    private void addWithTopMargin(LinearLayout parent, android.view.View view, int topMarginDp) {
        LinearLayout.LayoutParams params = matchWrap();
        params.topMargin = dp(topMarginDp);
        parent.addView(view, params);
    }

    private TextView text(String value, int size, int color) {
        TextView textView = new TextView(this);
        textView.setText(value);
        textView.setTextSize(size);
        textView.setTextColor(color);
        return textView;
    }

    private LinearLayout.LayoutParams matchWrap() {
        return new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
    }

    private void showContent(LinearLayout content) {
        ScrollView scroll = new ScrollView(this);
        scroll.addView(content);
        setContentView(scroll);
    }

    private void setSecureScreen(boolean secure) {
        if ((getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
            return;
        }
        if (secure) {
            getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        } else {
            getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
        }
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private enum Screen {
        PIN_SETUP,
        LOCKED,
        ADMIN,
        RECOVERY,
        ENROLLMENT
    }
}
