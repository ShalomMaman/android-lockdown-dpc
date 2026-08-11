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
- The signed update channel authenticates release metadata and APK identity, but depends on Android's package verifier and the configured signing lineage.
- Operators remain responsible for physical security, provisioning, key custody, and recovery procedures.
