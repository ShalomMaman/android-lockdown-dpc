# Signed update publisher

`publish_update.py` creates the compact, signed JSON envelope consumed by the Device Guard updater. It reads package and version metadata from the APK with `aapt2`, calculates SHA-256 and size by streaming the file, and asks OpenSSL to sign only the canonical payload with `SHA256withECDSA`.

The tool requires Python 3, OpenSSL, Android SDK Build Tools (`aapt2` and `apksigner`), and a working Java runtime for `apksigner`. Set `JAVA_HOME` when Java is not available system-wide.

The EC private key must live outside the repository. The tool never copies it into the envelope, prints it, or passes its contents on the command line. Do not generate or store production keys in this directory.

Example using an existing external key:

```bash
./tools/publish_update.py \
  --apk /secure/releases/device-guard.apk \
  --apk-url https://updates.example.test/device-guard.apk \
  --expected-package com.example.lockdowndpc \
  --expected-signer-sha256 25507e47f49cbacc8cad66ee4967b2bae3f22bbd26fbb4587e9326626669014b \
  --private-key /secure/offline/device-guard-update-ec.pem \
  --expected-metadata-key-sha256 APPROVED_PUBLIC_KEY_DER_SHA256 \
  --output /secure/releases/update-envelope.json
```

For an encrypted EC key, put the passphrase in an environment variable and pass only its name:

```bash
# Inject DEVICE_GUARD_UPDATE_KEY_PASSWORD through the operator's secret manager first.
./tools/publish_update.py \
  ... \
  --key-passphrase-env DEVICE_GUARD_UPDATE_KEY_PASSWORD
```

The tool never reads or prints the variable value; it gives OpenSSL the `env:` reference. Without `--key-passphrase-env`, OpenSSL receives an explicit empty passphrase, so an encrypted key fails immediately instead of waiting for an unavailable TTY prompt.

Safety defaults:

- only clean HTTPS APK URLs are accepted;
- APK identity is extracted rather than supplied by the operator;
- the extracted application ID must equal `--expected-package`;
- `apksigner` must report exactly one signing-certificate digest, equal to `--expected-signer-sha256`;
- the public key derived from the metadata private key must match the approved
  `--expected-metadata-key-sha256` used by the production build;
- APKs over the client's 100 MiB limit are rejected;
- envelopes expire after 30 days by default and cannot exceed 90 days;
- existing output is not replaced unless `--force` is explicit;
- output is written atomically and can never target the APK or private key.

The payload is canonical compact JSON with sorted keys. `payload` and its DER ECDSA `signature` are URL-safe Base64 without padding, matching `UpdateEnvelopeVerifier`.
