package com.example.lockdowndpc.ui;

import android.app.Activity;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.os.Bundle;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import com.example.lockdowndpc.policy.AllowedAppsStore;
import com.example.lockdowndpc.policy.AuditLog;
import com.example.lockdowndpc.policy.LockdownPackages;
import com.example.lockdowndpc.policy.LockdownPolicyController;
import com.example.lockdowndpc.security.AdminSession;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class AllowedAppsActivity extends Activity {
    private final List<AppRow> rows = new ArrayList<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (!AdminSession.isUnlocked()) {
            finish();
            return;
        }
        AllowedAppsStore.ProtectionMode mode = AllowedAppsStore.getProtectionMode(this);
        boolean allowSelected = mode == AllowedAppsStore.ProtectionMode.ALLOW_SELECTED;
        setTitle(allowSelected ? "אפליקציות מותרות" : "אפליקציות חסומות");

        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(20), dp(24), dp(20), dp(24));
        content.setLayoutDirection(LinearLayout.LAYOUT_DIRECTION_RTL);

        TextView title = text(
                allowSelected ? "בחירת אפליקציות מותרות" : "בחירת אפליקציות לחסימה",
                24,
                Color.rgb(25, 30, 38)
        );
        content.addView(title, matchWrap());

        TextView note = text(
                allowSelected
                        ? "אפליקציות מערכת חיוניות נשארות פעילות. אפליקציה חיצונית שלא תיבחר תוסתר."
                        : "יש לסמן את האפליקציות שרוצים לחסום. דפדפנים, חנויות ורשתות חברתיות מוכרות נחסמים תמיד.",
                15,
                Color.rgb(80, 88, 101)
        );
        note.setPadding(0, dp(8), 0, dp(16));
        content.addView(note, matchWrap());

        Set<String> allowed = AllowedAppsStore.getAllowedPackages(this);
        boolean configured = AllowedAppsStore.isAllowlistConfigured(this);
        Set<String> managed = AllowedAppsStore.getManagedPackages(this);
        for (AppEntry app : loadThirdPartyApps(managed)) {
            CheckBox checkBox = new CheckBox(this);
            checkBox.setText(getString(com.example.lockdowndpc.R.string.app_row_format, app.label, app.packageName));
            checkBox.setTextSize(16);
            checkBox.setPadding(0, dp(8), 0, dp(8));
            checkBox.setChecked(configured
                    ? allowed.contains(app.packageName)
                    : allowSelected);
            content.addView(checkBox, matchWrap());
            rows.add(new AppRow(app.packageName, checkBox));
        }

        Button save = new Button(this);
        save.setText("שמירת הרשימה");
        save.setOnClickListener(view -> saveAndClose());
        LinearLayout.LayoutParams saveParams = matchWrap();
        saveParams.topMargin = dp(20);
        content.addView(save, saveParams);

        ScrollView scroll = new ScrollView(this);
        scroll.addView(content);
        setContentView(scroll);
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (!AdminSession.isUnlocked()) {
            finish();
        }
    }

    private List<AppEntry> loadThirdPartyApps(Set<String> managed) {
        PackageManager pm = getPackageManager();
        ArrayList<AppEntry> apps = new ArrayList<>();
        Map<String, ApplicationInfo> applicationInfo = new LinkedHashMap<>();
        List<ApplicationInfo> installed;
        long inventoryFlags = PackageManager.MATCH_UNINSTALLED_PACKAGES
                | PackageManager.MATCH_DISABLED_COMPONENTS;
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            installed = pm.getInstalledApplications(
                    PackageManager.ApplicationInfoFlags.of(inventoryFlags)
            );
        } else {
            //noinspection deprecation
            installed = pm.getInstalledApplications((int) inventoryFlags);
        }
        for (ApplicationInfo info : installed) {
            // MATCH_UNINSTALLED_PACKAGES can also return packages whose APK was
            // removed but data was retained. Keep only applications installed
            // for this user; DPC-hidden applications retain FLAG_INSTALLED.
            if ((info.flags & ApplicationInfo.FLAG_INSTALLED) != 0) {
                applicationInfo.put(info.packageName, info);
            }
        }

        Set<String> candidatePackages = new LinkedHashSet<>(applicationInfo.keySet());
        candidatePackages.addAll(managed);
        for (String packageName : candidatePackages) {
            ApplicationInfo info = applicationInfo.get(packageName);
            if (info == null) {
                info = loadApplicationInfo(pm, packageName);
            }

            boolean system = info != null && (info.flags
                    & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0;
            if (system
                    || packageName.equals(getPackageName())
                    || packageName.equals("com.tailscale.ipn")) {
                continue;
            }
            if (LockdownPackages.ALWAYS_BLOCKED.contains(packageName)
                    || LockdownPackages.KNOWN_BROWSER_AND_SOCIAL.contains(packageName)) {
                continue;
            }

            String label = info != null
                    ? info.loadLabel(pm).toString()
                    : AllowedAppsStore.getRememberedLabel(this, packageName);
            AllowedAppsStore.rememberManagedPackage(this, packageName, label);
            apps.add(new AppEntry(label, packageName));
        }
        apps.sort(Comparator.comparing(app -> app.label.toLowerCase(Locale.getDefault())));
        return apps;
    }

    private ApplicationInfo loadApplicationInfo(PackageManager pm, String packageName) {
        try {
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                return pm.getApplicationInfo(packageName, PackageManager.ApplicationInfoFlags.of(
                        PackageManager.MATCH_DISABLED_COMPONENTS
                                | PackageManager.MATCH_UNINSTALLED_PACKAGES
                ));
            }
            //noinspection deprecation
            return pm.getApplicationInfo(
                    packageName,
                    PackageManager.MATCH_DISABLED_COMPONENTS
                            | PackageManager.MATCH_UNINSTALLED_PACKAGES
            );
        } catch (PackageManager.NameNotFoundException ignored) {
            return null;
        }
    }

    private void saveAndClose() {
        if (!AdminSession.isUnlocked()) {
            finish();
            return;
        }
        HashSet<String> allowed = new HashSet<>();
        HashSet<String> managed = new HashSet<>();
        for (AppRow row : rows) {
            managed.add(row.packageName);
            if (row.checkBox.isChecked()) {
                allowed.add(row.packageName);
            }
        }
        AllowedAppsStore.setAllowedPackages(this, allowed, managed);
        AuditLog.append(this, "רשימת האפליקציות נשמרה");
        if (AllowedAppsStore.isProtectionEnabled(this)) {
            LockdownPolicyController.apply(this);
        }
        AdminSession.extend();
        setResult(RESULT_OK);
        finish();
    }

    private TextView text(String value, int size, int color) {
        TextView textView = new TextView(this);
        textView.setText(value);
        textView.setTextSize(size);
        textView.setTextColor(color);
        return textView;
    }

    private LinearLayout.LayoutParams matchWrap() {
        return new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private record AppEntry(String label, String packageName) {}
    private record AppRow(String packageName, CheckBox checkBox) {}
}
