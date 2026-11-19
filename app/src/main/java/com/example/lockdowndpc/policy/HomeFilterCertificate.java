package com.example.lockdowndpc.policy;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Reads one bounded public CA certificate. Stores its canonical DER encoding. */
public final class HomeFilterCertificate {
    static final int MAX_BYTES = 64 * 1024;
    private static final Pattern PEM = Pattern.compile(
            "-----BEGIN CERTIFICATE-----\\s++([A-Za-z0-9+/=\\s]++)"
                    + "-----END CERTIFICATE-----");

    private HomeFilterCertificate() {}

    public static String read(InputStream input) throws IOException, CertificateException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int count;
        while ((count = input.read(buffer)) != -1) {
            if (bytes.size() + count > MAX_BYTES) {
                throw new CertificateException("Certificate file too large");
            }
            bytes.write(buffer, 0, count);
        }
        byte[] certificate = bytes.toByteArray();
        if (certificate.length == 0) {
            throw new CertificateException("Empty certificate file");
        }
        if (certificate[0] != 0x30) {
            Matcher pem = PEM.matcher(new String(certificate, StandardCharsets.US_ASCII).trim());
            if (!pem.matches()) {
                throw new CertificateException("Expected a single PEM or DER certificate");
            }
            try {
                certificate = Base64.getDecoder().decode(pem.group(1).replaceAll("\\s", ""));
            } catch (IllegalArgumentException exception) {
                throw new CertificateException("Invalid PEM encoding", exception);
            }
        }
        ByteArrayInputStream der = new ByteArrayInputStream(certificate);
        X509Certificate ca = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(der);
        byte[] canonical = ca.getEncoded();
        boolean[] usage = ca.getKeyUsage();
        if (der.available() != 0 || !Arrays.equals(certificate, canonical)
                || ca.getBasicConstraints() < 0
                || (usage != null && (usage.length <= 5 || !usage[5]))) {
            throw new CertificateException("Expected a single CA certificate");
        }
        return Base64.getEncoder().encodeToString(canonical);
    }
}
