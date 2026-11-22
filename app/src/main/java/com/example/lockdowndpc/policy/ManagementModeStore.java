package com.example.lockdowndpc.policy;

import android.content.Context;
import android.content.SharedPreferences;

import com.example.lockdowndpc.maintenance.MaintenanceStore;
import com.example.lockdowndpc.security.AdminPinStore;
import com.example.lockdowndpc.security.AdminSession;
import com.example.lockdowndpc.security.DurablePreferences;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.function.BooleanSupplier;

/** The device-protected marker takes precedence over all credential-protected state. */
public final class ManagementModeStore {
    static final String MARKER_PREFS = "remote_intent";
    static final String MARKER_KEY = "remoteIntent";
    static final String MODE_PREFS = "management_mode";
    static final String MODE_KEY = "mode";
    private static final String REANCHOR_KEY = "reanchorStarted";
    static final String MARKER_FILE = "remote-intent";
    private static final int MARKER_VERSION = 1;

    enum Marker { ABSENT, PRESENT, UNREADABLE }

    private static boolean markerWriteFailed;

    private ManagementModeStore() {}

    public static synchronized ManagementMode read(Context context) {
        ManagementMode mode = readMode(context);
        if (mode != ManagementMode.LOCAL_PIN) {
            AdminPinStore.clearRecoveryGrant();
        }
        return mode;
    }

    private static ManagementMode readMode(Context context) {
        Marker marker = readMarker(context);
        if (marker == Marker.UNREADABLE) {
            return ManagementMode.ENROLLING;
        }
        try {
            String record = modePreferences(context).getString(MODE_KEY, null);
            // Existing installations already have durable local PIN state. Migrate
            // only an absent record and only after proving the marker is absent.
            if (marker == Marker.ABSENT && record == null && AdminPinStore.hasPin(context)) {
                // An existing credential is local authority on an upgrade,
                // even when this best-effort migration has to be retried.
                storeLocalMode(context);
                return ManagementMode.LOCAL_PIN;
            }
            return resolve(marker, record);
        } catch (RuntimeException unreadable) {
            return resolve(marker, null);
        }
    }

    static ManagementMode resolve(Marker marker, String record) {
        if (marker == Marker.UNREADABLE) {
            return ManagementMode.ENROLLING;
        }
        if (marker == Marker.PRESENT) {
            return ManagementMode.REMOTE.name().equals(record)
                    ? ManagementMode.REMOTE : ManagementMode.ENROLLING;
        }
        if (ManagementMode.ENROLLING.name().equals(record) || ManagementMode.REMOTE.name().equals(record)) {
            // A remote record with a missing marker is inconsistent. It cannot
            // authorize a fleet policy or return the device to local setup.
            return ManagementMode.ENROLLING;
        }
        return ManagementMode.LOCAL_PIN.name().equals(record)
                ? ManagementMode.LOCAL_PIN : ManagementMode.UNDECIDED;
    }

    /** Called by local provisioning and before the first PIN is stored. */
    public static synchronized boolean selectLocal(Context context) {
        return read(context).usesLocalPolicy() && storeLocalMode(context);
    }

    public static synchronized boolean hasCommittedRemoteIntent(Context context) {
        return readMarker(context) == Marker.PRESENT;
    }

    /** Called once the fleet binding has been stored by the remote journal. */
    static synchronized boolean commitRemote(Context context) {
        return commitManagedMode(context, ManagementMode.REMOTE);
    }

    static synchronized boolean commitReanchorEnrolling(Context context) {
        return commitManagedMode(context, ManagementMode.ENROLLING);
    }

    static synchronized boolean hasPreviouslyBound(Context context) {
        return readMode(context) == ManagementMode.REMOTE
                || modePreferences(context).getBoolean(REANCHOR_KEY, false);
    }

    private static boolean commitManagedMode(Context context, ManagementMode mode) {
        if (!RemoteEnrolmentGate.permits() || readMarker(context) != Marker.PRESENT) {
            return false;
        }
        try {
            SharedPreferences prefs = modePreferences(context);
            boolean reanchor = mode == ManagementMode.ENROLLING;
            if (mode.name().equals(prefs.getAll().get(MODE_KEY))
                    && (!reanchor || prefs.getBoolean(REANCHOR_KEY, false))) {
                return true;
            }
            var update = prefs.edit().putString(MODE_KEY, mode.name());
            if (reanchor) {
                return DurablePreferences.commit(prefs, update.putBoolean(REANCHOR_KEY, true), MODE_KEY, REANCHOR_KEY);
            }
            return DurablePreferences.commit(prefs, update, MODE_KEY);
        } catch (RuntimeException unreadable) {
            return false;
        }
    }

    private static boolean storeLocalMode(Context context) {
        try {
            SharedPreferences prefs = modePreferences(context);
            if (ManagementMode.LOCAL_PIN.name().equals(prefs.getAll().get(MODE_KEY))) {
                return true;
            }
            return DurablePreferences.commit(prefs,
                    prefs.edit().putString(MODE_KEY, ManagementMode.LOCAL_PIN.name()), MODE_KEY);
        } catch (RuntimeException unreadable) {
            return false;
        }
    }

    /** Reserved for gated provisioning; a successful marker is never removed. */
    static synchronized boolean markRemoteIntent(Context context) {
        if (!RemoteEnrolmentGate.permits()) {
            return false;
        }
        AdminSession.lock();
        AdminPinStore.clearRecoveryGrant();
        try {
            File marker = markerFile(context.createDeviceProtectedStorageContext());
            File staged = File.createTempFile(MARKER_FILE, ".pending", marker.getParentFile());
            try {
                publishMarker(marker, staged);
            } finally {
                // On success the rename consumed it. On failure the original
                // marker is still in place and only the staged file is disposable.
                staged.delete();
            }
            markerWriteFailed = false;
        } catch (IOException | RuntimeException failure) {
            markerWriteFailed = true;
            return false;
        }
        // A window that actually reached Android still owes a verified restore.
        return MaintenanceStore.restorePending(context) || MaintenanceStore.clearForRemoteIntent(context);
    }

    static void publishMarker(File marker, File staged) throws IOException {
        try (FileOutputStream output = new FileOutputStream(staged)) {
            output.write(MARKER_VERSION);
            output.getFD().sync();
        }
        Files.move(staged.toPath(), marker.toPath(),
                StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }

    private static Marker readMarker(Context context) {
        if (markerWriteFailed) {
            return Marker.UNREADABLE;
        }
        try {
            Context device = context.createDeviceProtectedStorageContext();
            File marker = markerFile(device);
            if (!Files.notExists(marker.toPath())) {
                try (FileInputStream input = new FileInputStream(marker)) {
                    return input.read() == MARKER_VERSION && input.read() == -1
                            ? Marker.PRESENT : Marker.UNREADABLE;
                }
            }
            // Recognize a marker from the preferences representation as well,
            // including malformed files that Android loads as an empty map.
            File file = new File(device.getDataDir(), "shared_prefs/" + MARKER_PREFS + ".xml");
            SharedPreferences prefs = device.getSharedPreferences(MARKER_PREFS, Context.MODE_PRIVATE);
            return readMarker(prefs, () -> Files.notExists(file.toPath())
                    && Files.notExists(new File(file.getPath() + ".bak").toPath()));
        } catch (IOException | RuntimeException unreadable) {
            return Marker.UNREADABLE;
        }
    }

    static Marker readMarker(SharedPreferences prefs, BooleanSupplier filesAbsent) {
        try {
            if (prefs.getBoolean(MARKER_KEY, false)) {
                return Marker.PRESENT;
            }
            // Android may load malformed XML as an empty preferences map.
            return !prefs.contains(MARKER_KEY) && filesAbsent.getAsBoolean()
                    ? Marker.ABSENT : Marker.UNREADABLE;
        } catch (RuntimeException unreadable) {
            return Marker.UNREADABLE;
        }
    }

    private static File markerFile(Context device) {
        return new File(device.getFilesDir(), MARKER_FILE);
    }

    private static SharedPreferences modePreferences(Context context) {
        return context.getSharedPreferences(MODE_PREFS, Context.MODE_PRIVATE);
    }
}
