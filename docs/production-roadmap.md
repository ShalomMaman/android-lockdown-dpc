# Production roadmap

This document records the product boundary after Pilot 0.5.1 and the planned
work for the next managed-device release. It is intentionally explicit about
what the administrator console can and cannot configure today.

## Execution tracking

The public [Device Guard Production Roadmap](https://github.com/users/ShalomMaman/projects/3)
is the execution source of truth. This document preserves the rationale and
security boundary; the linked Issues own scope, priority and acceptance:

- **Pilot 0.5.2:** [system-application inventory](https://github.com/ShalomMaman/android-lockdown-dpc/issues/18),
  [verified system controls](https://github.com/ShalomMaman/android-lockdown-dpc/issues/20),
  [timed maintenance mode](https://github.com/ShalomMaman/android-lockdown-dpc/issues/26), and
  [management-package identity pins](https://github.com/ShalomMaman/android-lockdown-dpc/issues/27).
- **Pilot 0.5.3:** [real signed self-update drill](https://github.com/ShalomMaman/android-lockdown-dpc/issues/19),
  [physical kiosk validation](https://github.com/ShalomMaman/android-lockdown-dpc/issues/22),
  [Android/OEM matrix](https://github.com/ShalomMaman/android-lockdown-dpc/issues/23), and
  [repeatable Device Owner provisioning](https://github.com/ShalomMaman/android-lockdown-dpc/issues/28).
- **1.0:** [final production identity and signing](https://github.com/ShalomMaman/android-lockdown-dpc/issues/25)
  and [privacy-preserving fleet health](https://github.com/ShalomMaman/android-lockdown-dpc/issues/24).

## What Pilot 0.5.1 does today

The application picker is a **third-party application picker**. It enumerates
installed and previously managed packages, then deliberately removes:

- Android system and updated-system applications;
- Device Guard itself;
- configured management transports such as Tailscale;
- packages in the built-in browser, store and social-media catalogues.

Known browsers, stores and social applications can still be blocked by policy,
but some are classified by a built-in package catalogue rather than presented
as administrator-selectable rows. This is why Google Play, Chrome and other
system applications may be absent from the list even while protection blocks
them.

The policy backend already has an `ADMIN_SELECTED_SYSTEM` classification and a
storage API for explicitly opted-in system packages. Pilot 0.5.1 ships no
administrator screen that writes this setting. Therefore the presence of that
backend classification must not be described as user-facing system-app
selection.

| Capability | Pilot 0.5.1 status |
| --- | --- |
| Select ordinary installed applications | Available |
| Remember and display DPC-hidden third-party applications | Available |
| Block known stores, browsers and social applications | Available through built-in catalogues |
| Browse and select arbitrary system applications | **Not available** |
| Change the protected essential-system catalogue in the console | **Not available** |
| Disable developer options and ADB | **Not enabled; ADB remains pilot break-glass access** |
| Signed application self-update | Available and verified on the pilot device |
| Single-app and single-site kiosk | Implemented, but still requires dedicated-device hardware validation |

## Planned administrator experience

The next policy-management iteration should provide one searchable inventory
with explicit filters:

- All applications
- User-installed applications
- System applications
- Browsers and web entry points
- Application stores and installers
- Social and communication applications
- Management applications
- Protected Android components

Every row should show the application label, package name, system/user origin,
current installation and visibility state, and the reason for any enforced
classification. The administrator should be able to distinguish a manual choice
from a built-in rule.

The policy state for a package should be represented as one of:

1. **Allowed** — available under the selected policy profile.
2. **Blocked** — hidden and verified by the Device Owner.
3. **Protected** — required for Android, recovery, WebView or management and not
   eligible for blocking.

For known policy categories, the console should also provide group controls such
as “block all application stores” or “block known browsers”. A group control
must remain inspectable: the administrator can see exactly which installed
packages it affects.

## System-application safety model

Displaying every system package is useful; allowing every system package to be
blocked is unsafe. OEM firmware contains launchers, settings providers,
telephony shims, keyboards, permission controllers and update components whose
importance cannot be inferred from `FLAG_SYSTEM` alone.

The system inventory should use three safety tiers:

- **Protected core** — Device Guard, System UI, package/permission installers,
  settings providers, active input method, WebView provider, Google Play
  services where required, and verified management transports. These cannot be
  blocked from the normal console.
- **Known manageable system app** — reviewed packages such as stores, browsers,
  file managers and vendor applications for which the policy has an explicit
  rule.
- **Unclassified OEM component** — visible for diagnosis but not blockable until
  it is reviewed or an advanced administrator explicitly accepts the risk.

Before accepting an advanced system-package choice, Device Guard should record
the package name, signer digest, version, enabled/hidden state and the firmware
build. The UI must explain that an OEM component can be required even when it
has a harmless-looking label. Applying the selection must use the existing
requested → applied/failed verification model and must never show protection as
active after a partial result.

## System policy controls

The authenticated administrator console exposes sixteen separate controls,
each bound to the official Android Enterprise `UserManager` restrictions it is
made of and applied through `DevicePolicyManager#addUserRestriction`:

- developer options and Android debugging (`DISALLOW_DEBUGGING_FEATURES`);
- USB file transfer;
- installation from unknown sources (per-user, plus the Android 10 global key);
- all package installation, including stores and installers;
- adding or changing accounts;
- VPN configuration;
- network reset, tethering and Wi-Fi configuration where supported;
- private DNS;
- date and time changes;
- Safe Boot, factory reset and user/profile creation;
- application uninstall and application-control settings.

Every control is written and then read back from
`DevicePolicyManager#getUserRestrictions`, and reports one of **unsupported**,
**not requested**, **requested**, **applied** or **failed** for the running SDK.
A saved switch is never rendered as enforcement: changing one clears the stored
verification, so the row reads "saved — not verified yet" until an apply pass
confirms it against the platform.

A failed *critical* control that the administrator requested adds an error to the
reconciliation result, which is what makes protection report as faulted. Two
cases deliberately do not fault: a restriction the running Android release does
not implement, because an older device is not a broken device; and a failure to
*withdraw* a control, because the device is then stricter than asked rather than
weaker, and faulting there would strand an administrator reopening a capability.
Wi-Fi configuration is the single advisory control — Android defines the
restriction but OEM behaviour varies, so a refusal is recorded and shown without
faulting protection.

### Pilot migration safety

Defaults are keyed to a deployment profile derived from the running application
ID. `gradle/production-identity.gradle` already assigns a distinct production
identity, and Android refuses to change an application ID on an in-place update,
so a provisioned pilot cannot become a production install. Anything
unrecognised — a fork, a rename, an unreadable record — resolves to the pilot
profile, and a profile once recorded as pilot is never promoted.

The pilot defaults reproduce the Pilot 0.5.1 restriction set exactly, so an
upgraded pilot enforces what it enforced before and **keeps developer options and
ADB available**. `SystemPolicyMigrationTest` pins that set literally. Developer
options and ADB default to on only for the production profile. Blocking all
package installation is never a default on either profile: Android applies
`DISALLOW_INSTALL_APPS` to the device owner as well, which would disable the
signed self-update that gate 3 below requires before ADB can be withdrawn.

### Open integration requirements

Two items are deliberately outside this change and are required before the
production profile is complete:

1. **Console entry point.** `SystemPolicyActivity` is implemented, declared and
   unexported, and the strings `admin_system_policy_row` and
   `admin_system_policy_supporting` exist for it, but no row in `MainActivity`
   opens it yet. It needs an `ActionRow` in the protection section that starts
   the activity behind `requireSession()`, exactly as the app-list row does.
2. **Production identity constant.** `SystemPolicyProfile.PRODUCTION_APPLICATION_ID`
   duplicates the application ID literal in `gradle/production-identity.gradle`.
   If issue #25 changes that ID, the constant must move with it. The safe failure
   mode if it is forgotten is that a production device is treated as a pilot.
   Publishing the flag as a `BuildConfig` field from the Gradle files would
   remove the duplication.

## Maintenance mode

Production deployments should disable debugging and routine escape surfaces by
default. Authorized maintenance should be a narrow, audited exception rather
than a general pause of protection.

An administrator should be able to choose which capability to open:

- application-store access;
- installation of a local APK;
- selected Android settings;
- USB file transfer;
- ADB/debugging as an explicit break-glass option.

Maintenance mode should require an active administrator PIN session, have a
short configurable expiry, close on reboot, and restore and verify the previous
policy automatically. The audit log should record the administrator action,
opened capabilities, start, expiry, cancellation and final reconciliation
result, but no PIN or recovery secret.

ADB maintenance needs an additional warning because clearing the debugging
restriction can expose a privileged transport. It should not be enabled merely
because Tailscale is connected, and it should never remain open indefinitely.

## Acceptance criteria before customer production

The following are release gates rather than optional polish:

1. Fix the final production application ID and APK signing key before enrolling
   the first customer device.
2. Provide QR or equivalent repeatable Device Owner provisioning.
3. Complete a real signed self-update from one installed version to a higher
   version before disabling ADB as the normal recovery path.
4. Validate system-app selection and recovery on each supported OEM firmware
   family.
5. Exercise apply, pause, maintenance expiry, reboot and failed reconciliation
   on physical Device Owner devices.
6. Exercise single-app and single-site kiosk escape and recovery paths on
   physical hardware.
7. Confirm that a wrong system selection cannot hide Device Guard, the active
   WebView provider, the active keyboard, System UI or the management transport.
8. Document recovery when the update endpoint, Wi-Fi, VPN, WebView or target
   kiosk application is unavailable.

## Proposed delivery sequence

- **0.5.2:** system-application inventory, safety classifications, system policy
  controls and timed maintenance mode.
- **0.5.3:** physical-device and OEM fixes, signed higher-version self-update
  drill, provisioning automation and recovery runbooks.
- **1.0 production candidate:** fixed production identity/signing, supported
  device matrix, staged rollout and fleet-level status reporting.

Version numbers are planning labels and may change. The security gates above do
not.
