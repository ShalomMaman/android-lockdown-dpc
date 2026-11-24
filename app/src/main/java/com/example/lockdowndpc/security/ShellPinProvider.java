package com.example.lockdowndpc.security;

import android.annotation.SuppressLint;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.Process;

import com.example.lockdowndpc.R;
import com.example.lockdowndpc.policy.AuditEvent;
import com.example.lockdowndpc.policy.AuditLog;

/**
 * Shell-only {@link ContentProvider} that allows setup automation over ADB to
 * set, verify, or replace the local administrator PIN without UI interaction.
 *
 * <p>Only callers running as {@link Process#SHELL_UID} (UID 2000) are accepted;
 * every other UID, including {@code root} (UID 0), is refused on entry.
 */
public final class ShellPinProvider extends ContentProvider {
    static final int SHELL_UID = 2000;

    static final String METHOD_SET_INITIAL = "set-initial";
    static final String METHOD_VERIFY = "verify";
    static final String METHOD_REPLACE = "replace";

    static final String EXTRA_PIN = "pin";
    static final String EXTRA_CURRENT = "current";

    static final String KEY_STATUS = "status";
    static final String KEY_RECOVERY = "recovery";
    static final String KEY_REMAINING_MILLIS = "remainingMillis";
    static final String KEY_CODE = "code";

    static final String STATUS_REFUSED_CALLER = "refused-caller";
    static final String STATUS_PIN_EXISTS = "pin-exists";
    static final String STATUS_INVALID_PIN = "invalid-pin";
    static final String STATUS_OK = "ok";
    static final String STATUS_REFUSED = "refused";
    static final String STATUS_MATCH = "match";
    static final String STATUS_MISMATCH = "mismatch";
    static final String STATUS_LOCKED = "locked";
    static final String STATUS_NOT_CONFIGURED = "not-configured";
    static final String STATUS_ERROR = "error";

    interface PinStore {
        boolean hasPin();

        boolean setInitialPin(String pin);

        AdminPinStore.Verification verify(String pin);

        boolean replacePinAfterVerification(String pin);

        String rotateRecoveryCode();

        default void clearRecoveryGrant() {}

        default void recordAudit(boolean replaced) {}
    }

    record Result(String status, String recovery, Long remainingMillis, String code) {
        static Result statusOnly(String status) {
            return new Result(status, null, null, null);
        }

        static Result ok(String recovery) {
            return new Result(STATUS_OK, recovery, null, null);
        }

        static Result locked(long remainingMillis) {
            return new Result(STATUS_LOCKED, null, remainingMillis, null);
        }

        static Result error(String code) {
            return new Result(STATUS_ERROR, null, null, code);
        }
    }

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    @SuppressLint("InlinedApi")
    public Bundle call(String method, String arg, Bundle extras) {
        if (Binder.getCallingUid() != Process.SHELL_UID) {
            return statusBundle(STATUS_REFUSED_CALLER);
        }
        try {
            Context context = getContext();
            if (context == null) {
                return errorBundle("context-unavailable");
            }
            Context appContext = context.getApplicationContext();
            if (appContext == null) {
                appContext = context;
            }
            String pin = extras == null ? null : extras.getString(EXTRA_PIN);
            String current = extras == null ? null : extras.getString(EXTRA_CURRENT);
            Result result = handleCall(
                    Binder.getCallingUid(),
                    method,
                    current,
                    pin,
                    new AndroidPinStore(appContext)
            );
            return toBundle(result);
        } catch (RuntimeException exception) {
            return errorBundle(safeErrorCode(exception));
        }
    }

    static Result handleCall(
            int callingUid,
            String method,
            String currentPin,
            String pin,
            PinStore store
    ) {
        if (callingUid != SHELL_UID) {
            return Result.statusOnly(STATUS_REFUSED_CALLER);
        }
        if (store == null) {
            return Result.error("store-unavailable");
        }
        if (method == null) {
            return Result.error("unknown-method");
        }
        try {
            return switch (method) {
                case METHOD_SET_INITIAL -> handleSetInitial(pin, store);
                case METHOD_VERIFY -> handleVerify(pin, store);
                case METHOD_REPLACE -> handleReplace(currentPin, pin, store);
                default -> Result.error("unknown-method");
            };
        } catch (RuntimeException exception) {
            return Result.error(safeErrorCode(exception));
        }
    }

    private static Result handleSetInitial(String pin, PinStore store) {
        if (store.hasPin()) {
            return Result.statusOnly(STATUS_PIN_EXISTS);
        }
        if (!AdminPinStore.isValidPin(pin)) {
            return Result.statusOnly(STATUS_INVALID_PIN);
        }
        if (!store.setInitialPin(pin)) {
            return Result.statusOnly(STATUS_REFUSED);
        }
        String recovery = store.rotateRecoveryCode();
        if (recovery == null || recovery.isEmpty()) {
            return Result.error("recovery-code-unavailable");
        }
        store.recordAudit(false);
        return Result.ok(recovery);
    }

    private static Result handleVerify(String pin, PinStore store) {
        return mapVerification(store.verify(pin), store);
    }

    private static Result handleReplace(String currentPin, String newPin, PinStore store) {
        Result verified = mapVerification(store.verify(currentPin), store);
        if (!STATUS_MATCH.equals(verified.status())) {
            return verified;
        }
        if (!AdminPinStore.isValidPin(newPin)) {
            return Result.statusOnly(STATUS_INVALID_PIN);
        }
        if (!store.replacePinAfterVerification(newPin)) {
            return Result.statusOnly(STATUS_REFUSED);
        }
        String recovery = store.rotateRecoveryCode();
        if (recovery == null || recovery.isEmpty()) {
            return Result.error("recovery-code-unavailable");
        }
        store.recordAudit(true);
        return Result.ok(recovery);
    }

    private static Result mapVerification(AdminPinStore.Verification verification, PinStore store) {
        if (verification == null || verification.status() == null) {
            return Result.error("verify-failed");
        }
        return switch (verification.status()) {
            case SUCCESS -> {
                if (verification.recoveryGrant() != null) {
                    store.clearRecoveryGrant();
                    yield Result.statusOnly(STATUS_MISMATCH);
                }
                yield Result.statusOnly(STATUS_MATCH);
            }
            case INVALID -> Result.statusOnly(STATUS_MISMATCH);
            case LOCKED -> Result.locked(verification.remainingMillis());
            case NOT_CONFIGURED -> Result.statusOnly(STATUS_NOT_CONFIGURED);
            case ERROR -> Result.error("verify-failed");
        };
    }

    private static String safeErrorCode(Exception exception) {
        if (exception instanceof SecurityException) {
            String message = exception.getMessage();
            if (message != null && !message.trim().isEmpty()) {
                return message;
            }
        }
        String name = exception.getClass().getSimpleName();
        return name.isEmpty() ? "Exception" : name;
    }

    private static Bundle statusBundle(String status) {
        Bundle bundle = new Bundle();
        bundle.putString(KEY_STATUS, status);
        return bundle;
    }

    private static Bundle errorBundle(String code) {
        Bundle bundle = new Bundle();
        bundle.putString(KEY_STATUS, STATUS_ERROR);
        bundle.putString(KEY_CODE, code);
        return bundle;
    }

    private static Bundle toBundle(Result result) {
        Bundle bundle = new Bundle();
        bundle.putString(KEY_STATUS, result.status());
        if (result.recovery() != null) {
            bundle.putString(KEY_RECOVERY, result.recovery());
        }
        if (result.remainingMillis() != null) {
            bundle.putLong(KEY_REMAINING_MILLIS, result.remainingMillis());
        }
        if (result.code() != null) {
            bundle.putString(KEY_CODE, result.code());
        }
        return bundle;
    }

    @Override
    public Cursor query(
            Uri uri,
            String[] projection,
            String selection,
            String[] selectionArgs,
            String sortOrder
    ) {
        throw new UnsupportedOperationException("ShellPinProvider supports call() only");
    }

    @Override
    public String getType(Uri uri) {
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        throw new UnsupportedOperationException("ShellPinProvider supports call() only");
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException("ShellPinProvider supports call() only");
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException("ShellPinProvider supports call() only");
    }

    private static final class AndroidPinStore implements PinStore {
        private final Context context;

        private AndroidPinStore(Context context) {
            this.context = context;
        }

        @Override
        public boolean hasPin() {
            return AdminPinStore.hasPin(context);
        }

        @Override
        public boolean setInitialPin(String pin) {
            return AdminPinStore.setInitialPin(context, pin);
        }

        @Override
        public AdminPinStore.Verification verify(String pin) {
            return AdminPinStore.verify(context, pin);
        }

        @Override
        public boolean replacePinAfterVerification(String pin) {
            return AdminPinStore.replacePinAfterVerification(context, pin);
        }

        @Override
        public String rotateRecoveryCode() {
            return AdminPinStore.rotateRecoveryCode(context);
        }

        @Override
        public void clearRecoveryGrant() {
            AdminPinStore.clearRecoveryGrant();
        }

        @Override
        public void recordAudit(boolean replaced) {
            try {
                AuditLog.append(
                        context,
                        replaced ? AuditEvent.PIN_REPLACED : AuditEvent.PIN_SET,
                        context.getString(replaced ? R.string.audit_pin_replaced : R.string.audit_pin_set)
                );
            } catch (RuntimeException ignored) {
                // Best-effort audit record; never fail the PIN operation or log credentials.
            }
        }
    }
}
