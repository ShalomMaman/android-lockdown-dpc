package com.example.lockdowndpc.policy;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.net.ssl.HttpsURLConnection;

/** A bounded check of the home filter's HTTPS response, using Android's normal network path. */
public final class HomeFilterProbe {
    private static final int TIMEOUT_MS = 4000;
    // DNS or TLS may ignore interruption. Bound the number of outstanding probes even then.
    private static final ThreadPoolExecutor WORKER = new ThreadPoolExecutor(
            0, 1, 15, TimeUnit.SECONDS, new SynchronousQueue<>(),
            task -> new Thread(task, "home-filter-probe"));

    private HomeFilterProbe() {}

    /** Call from the UI's IO dispatcher. Never blocks the policy reconciliation thread. */
    public static HomeFilterPolicy.ProbeState check(HomeFilterPolicy.Canary canary) {
        if (canary == null) return HomeFilterPolicy.ProbeState.NOT_RUN;
        Future<Boolean> work;
        try {
            work = WORKER.submit(() -> request(canary));
        } catch (RejectedExecutionException ignored) {
            return HomeFilterPolicy.ProbeState.FAILED;
        }
        try {
            return work.get(TIMEOUT_MS, TimeUnit.MILLISECONDS)
                    ? HomeFilterPolicy.ProbeState.PASSED : HomeFilterPolicy.ProbeState.FAILED;
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        } catch (ExecutionException | TimeoutException ignored) {
            // Report only the outcome. Exceptions can contain configuration or network data.
        }
        work.cancel(true);
        return HomeFilterPolicy.ProbeState.FAILED;
    }

    private static boolean request(HomeFilterPolicy.Canary canary) throws IOException {
        HttpsURLConnection connection = (HttpsURLConnection)
                URI.create(canary.url()).toURL().openConnection();
        try {
            connection.setInstanceFollowRedirects(false);
            connection.setUseCaches(false);
            connection.setRequestProperty("Cache-Control", "no-cache, no-store");
            connection.setConnectTimeout(2000);
            connection.setReadTimeout(2000);
            if (connection.getResponseCode() != HttpURLConnection.HTTP_OK) return false;
            try (InputStream body = connection.getInputStream()) {
                return matches(body, canary.expectedBody());
            }
        } finally {
            connection.disconnect();
        }
    }

    static boolean matches(InputStream body, String expected) throws IOException {
        for (byte value : expected.getBytes(StandardCharsets.UTF_8)) {
            if (body.read() != Byte.toUnsignedInt(value)) return false;
        }
        return body.read() == -1;
    }
}
