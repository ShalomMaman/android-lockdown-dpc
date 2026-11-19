package com.example.lockdowndpc.policy;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.util.Base64;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class HomeFilterCertificateTest {
    private static final String TEST_CA = """
            -----BEGIN CERTIFICATE-----
            MIIBgjCCASigAwIBAgIUOgNdCfDBnsHvJ4HCpsw9WJ/v07kwCgYIKoZIzj0EAwIw
            HzEdMBsGA1UEAwwURGV2aWNlR3VhcmQtSlZNLXRlc3QwHhcNMjYxMTE5MjAyNzQ5
            WhcNMzYxMTE2MjAyNzQ5WjAfMR0wGwYDVQQDDBREZXZpY2VHdWFyZC1KVk0tdGVz
            dDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHMpTvUHsFhIUaMisGGaZDcE/e7T
            WNXzvrVH/PKfeOtaERdKcK0Ddkyc/7N+if8vFZDdFgprIjPfGCun+quL/qSjQjBA
            MB0GA1UdDgQWBBRQWhrL2pDpZ4Rh8GIE9GMgXa37LzAPBgNVHRMBAf8EBTADAQH/
            MA4GA1UdDwEB/wQEAwICBDAKBggqhkjOPQQDAgNIADBFAiEAohtfKo5tH5zIaP43
            Ww0NXWOyu+iEXQLI48tgEqnSbdECIGHrpgKy1gxY3tugPuAodQ72X2gKwIrKaQOf
            tyMdoQZB
            -----END CERTIFICATE-----
            """;

    @Test
    public void normalizesSinglePemAndDerToTheSameCertificate() throws Exception {
        String encoded = HomeFilterCertificate.read(asInput(TEST_CA));
        ByteArrayInputStream der = new ByteArrayInputStream(Base64.getDecoder().decode(encoded));
        assertEquals(encoded, HomeFilterCertificate.read(der));
    }

    @Test
    public void refusesBundlesExtraMaterialAndOversizedFiles() {
        assertThrows(CertificateException.class,
                () -> HomeFilterCertificate.read(asInput(TEST_CA + TEST_CA)));
        assertThrows(CertificateException.class,
                () -> HomeFilterCertificate.read(asInput(TEST_CA + "unexpected material")));
        assertThrows(CertificateException.class,
                () -> HomeFilterCertificate.read(new ByteArrayInputStream(new byte[65537])));
    }

    @Test(timeout = 2000)
    public void acceptsOuterWhitespaceAndRejectsLongMalformedPem() throws Exception {
        assertEquals(HomeFilterCertificate.read(asInput(TEST_CA)),
                HomeFilterCertificate.read(asInput(" \r\n" + TEST_CA + "\t ")));
        assertThrows(CertificateException.class, () -> HomeFilterCertificate.read(asInput(
                "-----BEGIN CERTIFICATE-----" + " ".repeat(64000) + "missing footer")));
    }

    private static ByteArrayInputStream asInput(String value) {
        return new ByteArrayInputStream(value.getBytes(StandardCharsets.US_ASCII));
    }
}
