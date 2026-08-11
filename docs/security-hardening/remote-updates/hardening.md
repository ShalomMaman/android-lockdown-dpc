# Security Hardening Review: Device Guard remote updates

## Evidence Basis

I inspected the DPC at revision `482e023` and the Android package-install boundary. The current policy engine is autonomous, but application upgrades still depend on a temporary ADB TCP listener. Android already gives a fully managed device owner a narrower installation capability through `PackageInstaller`, so we can remove the operational dependency without broadening policy authority.

## Constraints

We must support Android 9, preserve the existing package/certificate during the pilot, fail closed on malformed or downgraded releases, avoid embedded server credentials, and keep protection active when update checks fail. The release host is treated as untrusted unless its metadata signature verifies.

## Opportunity Portfolio

| Opportunity | Evidence | Options | Recommendation | Proposal |
| --- | --- | --- | --- | --- |
| Own the remote-update trust boundary | ADB lifecycle, current signing path, and Android Device Owner installer contract (E001–E005) | Manual ADB; signed self-update; Managed Google Play/EMM | Use signed self-update now; retain EMM as the fleet-scale migration | [Secure remote update boundary](proposals/secure-update-boundary.md) |

## Recommendation Summary

We should accept updates only when a small signed envelope authorizes a higher version of this exact package, the downloaded bytes match the authorized SHA-256 and size, and the APK signer matches the installed DPC signer. `PackageInstaller` remains the final platform check. This keeps a compromised file host from authorizing arbitrary code and makes network failure a maintenance event rather than a protection failure.

## Next Decisions

The client and publishing tool can be implemented now. Enabling production polling still requires choosing a release endpoint and supplying the offline metadata public key at build time; publishing an APK publicly or creating cloud infrastructure is intentionally a separate external-state decision.

