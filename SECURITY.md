# Security policy

Device Guard is privileged software. A vulnerability can weaken restrictions or disrupt management of a fully managed Android device.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability-reporting feature for this repository. Include affected versions, Android version and vendor, reproduction steps, expected versus observed behavior, and any proposed mitigation.

Do not include real administrator PINs, recovery codes, signing material, customer data, or live device credentials.

## Supported versions

Security fixes target the latest release. Pilot builds are for controlled testing and are not a supported commercial distribution.

## Security boundaries

- The DPC does not claim to survive a recovery reset, bootloader unlock, or firmware replacement.
- Browser and package blocking is not a general-purpose network firewall.
- Kiosk mode contains a cooperative user on a Device Owner-provisioned device. Single-site kiosk is navigation containment, not a network firewall: a page on the allowed origin can still load scripts, images, and data from other hosts. The full boundary is in [`docs/kiosk-mode.md`](docs/kiosk-mode.md).
- Kiosk mode is **not verified on hardware** in `0.5.0`. Its unit tests prove the pure state, URL, origin, and target-eligibility rules; they prove nothing about what Android or a given OEM build actually does with lock task, the HOME preference, or package hiding.
- Leaving kiosk requires an authenticated administrator session. Without the administrator PIN and without a valid recovery code, the only way out of an active kiosk is re-provisioning the device. Operators must keep both recoverable off the device before enabling kiosk.
- The administrator entry gesture on the kiosk surface opens the PIN screen and grants no authority. It is a convenience, not a secret; the security boundary is the PIN.
- The shipped management record for `com.tailscale.ipn` has **no pinned signing certificate**, so it authenticates a package name and nothing else. This is a deliberate pilot-compatibility gap, surfaced in the console and closed by configuring the release certificate's SHA-256 digest.
- The signed update channel authenticates release metadata and APK identity, but depends on Android's package verifier and the configured signing lineage.
- Operators remain responsible for physical security, provisioning, key custody, and recovery procedures.
