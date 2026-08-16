# Product screenshot provenance

The PNG files in this directory are direct Android emulator screen captures of
the Device Guard interface. They were captured from the `main` development
build after the Android API 37 launch fix, with the application provisioned as
Device Owner on an Android API 37.1 emulator.

The debuggable build is used only for documentation capture. Release builds set
`FLAG_SECURE` on administrator and recovery surfaces and therefore produce a
blank screen capture by design.

These images demonstrate interface behavior, localization, and layout. They do
not replace the firmware-specific evidence recorded in
[`docs/device-matrix.md`](../../device-matrix.md).

When refreshing the gallery:

1. Capture the exact version named in the public caption.
2. Use a clean test profile containing no personal or customer data.
3. Exclude administrator PINs, recovery codes, accounts, network addresses,
   device identifiers, and management credentials.
4. Visually inspect every final asset before publication.
5. Keep English alternative text accurate and update the README caption if the
   emulator or build provenance changes.
