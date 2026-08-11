# Contributing

Thank you for helping improve Device Guard.

## Before you start

- Use a dedicated test device or emulator. Device Owner provisioning can require a factory reset.
- Never test destructive policy changes on a personal device.
- Do not commit APK-signing keys, metadata-signing keys, PINs, recovery codes, device identifiers, or customer data.
- Open an issue before a large architectural change so the security and migration impact can be discussed first.

## Development workflow

1. Create a focused branch.
2. Keep policy changes fail-closed and preserve recovery paths.
3. Add or update tests for policy-state, update verification, and UI logic.
4. Run:

   ```bash
   ./gradlew test lintRelease assembleRelease
   python3 -m unittest discover -s tools -p 'test_*.py'
   ```

5. Explain security assumptions, Android-version constraints, and physical-device testing in the pull request.

The Android UI is currently Hebrew-first. New user-facing strings must use Android resources and should be written so future English localization remains straightforward.

By submitting a contribution, you agree that it is licensed under Apache License 2.0.
