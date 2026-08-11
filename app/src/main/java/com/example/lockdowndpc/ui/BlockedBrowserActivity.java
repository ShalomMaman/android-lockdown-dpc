package com.example.lockdowndpc.ui;

import android.app.Activity;
import android.graphics.Color;
import android.os.Bundle;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

public final class BlockedBrowserActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setStatusBarColor(Color.WHITE);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER);
        root.setPadding(dp(32), dp(32), dp(32), dp(32));
        root.setLayoutDirection(LinearLayout.LAYOUT_DIRECTION_RTL);

        TextView icon = new TextView(this);
        icon.setText("🛡️");
        icon.setTextSize(56);
        icon.setGravity(Gravity.CENTER);
        root.addView(icon, matchWrap());

        TextView title = new TextView(this);
        title.setText("הגישה לאינטרנט חסומה");
        title.setTextSize(26);
        title.setTextColor(Color.rgb(25, 30, 38));
        title.setGravity(Gravity.CENTER);
        title.setPadding(0, dp(20), 0, dp(8));
        root.addView(title, matchWrap());

        TextView message = new TextView(this);
        message.setText("לא ניתן לפתוח דפדפנים או קישורי אינטרנט במכשיר הזה.");
        message.setTextSize(17);
        message.setTextColor(Color.rgb(80, 88, 101));
        message.setGravity(Gravity.CENTER);
        root.addView(message, matchWrap());

        setContentView(root);
    }

    private ViewGroup.LayoutParams matchWrap() {
        return new ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
