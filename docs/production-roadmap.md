# Production roadmap

This document records the product boundary on the Pilot 0.5.4 release line and
the planned work toward a supported managed-device release. It is intentionally
explicit about what the administrator console can and cannot configure today.

## Execution tracking

The public [Device Guard Production Roadmap](https://github.com/users/ShalomMaman/projects/3)
is the execution source of truth. This document preserves the rationale and
security boundary; the linked Issues own scope, priority and acceptance:

- **Pilot 0.5.2 — delivered foundation:**
  [system-application inventory](https://github.com/ShalomMaman/android-lockdown-dpc/issues/18),
  [verified system controls](https://github.com/ShalomMaman/android-lockdown-dpc/issues/20),
  [timed maintenance mode](https://github.com/ShalomMaman/android-lockdown-dpc/issues/26), and
  [management-package identity pins](https://github.com/ShalomMaman/android-lockdown-dpc/issues/27).
  All four are covered by JVM tests and none has been exercised on hardware.
- **Pilot 0.5.3 — delivered:** protected signed publication,
  cross-platform APK signer verification, an offline in-place update drill and
  public channel read-back are complete. The remaining release gates are:
  [real signed self-update drill](https://github.com/ShalomMaman/android-lockdown-dpc/issues/19),
  [physical kiosk validation](https://github.com/ShalomMaman/android-lockdown-dpc/issues/22),
  [Android/OEM matrix](https://github.com/ShalomMaman/android-lockdown-dpc/issues/23), and
  [repeatable Device Owner provisioning](https://github.com/ShalomMaman/android-lockdown-dpc/issues/28).
  The executable procedure for #22 and #23 is [`hardware-validation.md`](hardware-validation.md);
  results are recorded in [`device-matrix.md`](device-matrix.md). The offline half
  of #19 is implemented in `tools/update_drill.py` and the on-device half is
  documented in [`update-drill.md`](update-drill.md); #28 tooling and runbook are
  `tools/provisioning_payload.py` and [`provisioning.md`](provisioning.md).
- **Pilot 0.5.4 — current release line:** an explicit, fail-closed Google Play
  compatibility mode for applications that require the Store package, bounded
  link-handler verification retries, and the public collaboration and release
  documentation improvements are delivered. Strict store blocking remains the
  default. Group P in [`hardware-validation.md`](hardware-validation.md) is the
  remaining physical-device proof for the compatibility mode.
- **1.0:** [final production identity and signing](https://github.com/ShalomMaman/android-lockdown-dpc/issues/25).
  [Privacy-preserving fleet health](https://github.com/ShalomMaman/android-lockdown-dpc/issues/24)
  is implemented in this release as a local, on-device report plus an
  operator-initiated redacted export: Device Guard gains no telemetry, no
  analytics endpoint and no default off-device transmission, and a fleet view is
  assembled by whoever collects the exports. That is a security boundary, not a
  deferral.

## What Pilot 0.5.4 does today

The 0.5.4 console implements the administrator experience the rest of this
document describes: a searchable system-application inventory with safety tiers,
verified system policy controls, timed maintenance mode, and management identity
pinning. The remaining gates are hardware gates.

The application picker is no longer a third-party-only picker. It enumerates
installed and previously managed packages and presents system applications
behind the safety tiers described below, while still refusing to make protected
core components selectable. Device Guard itself and a verified management
transport are never selectable.

The `ADMIN_SELECTED_SYSTEM` classification is now written by an administrator
screen rather than by nothing, so an opted-in system package is a recorded
administrator decision with a risk acceptance behind it.

| Capability | Pilot 0.5.4 status |
| --- | --- |
| Select ordinary installed applications | Available |
| Remember and display DPC-hidden third-party applications | Available |
| Block known stores, browsers and social applications | Available through built-in catalogues |
| Browse and select system applications | Available, behind the safety tiers below |
| Change the protected essential-system catalogue in the console | **Not available, deliberately.** Protected core is a code catalogue, not a setting |
| Disable developer options and ADB | Available as a control. Off by default on the pilot profile — ADB is still the documented recovery path — and on by default on the production profile |
| Timed maintenance mode with automatic restore | Available; **not exercised on hardware** |
| Pin and verify a management package's signing certificate | Available; **no real signer has been read from a real device** |
| Local device health report and redacted export | Available. No telemetry, no endpoint, no default off-device transmission |
| Signed application self-update | Available in the pilot channel. The higher-version drill is rehearsed offline only; see [`update-drill.md`](update-drill.md) |
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

### Implemented: shown is wider than selectable

The inventory screen implements this model in `policy/SystemAppClassifier`, a
pure classifier the console consults before it draws a row. The decision worth
recording is that **what an administrator can see and what they can change are
deliberately different sets**, resolved in a fixed order:

1. **Protected core** — Device Guard, `ESSENTIAL_SYSTEM`, verified management
   transports, and two *runtime* facts: the active input method and the active
   WebView provider, read from the device rather than from a catalogue. An OEM
   keyboard absent from every catalogue is still unblockable, because the
   failure it prevents — a device with no way to type and no way to repair it —
   does not depend on our catalogue being complete.
2. **Policy-ruled** — packages `ALWAYS_BLOCKED`, `KNOWN_BROWSER_AND_SOCIAL` or
   `KIOSK_ESCAPE_SURFACES` already decide. These are shown with their reason and
   **no checkbox**: `LockdownPolicyController` blocks them unconditionally, so a
   checkbox would display a state the next reconciliation pass overrules.
3. **Known manageable system app** — a narrow reviewed catalogue
   (`SystemAppClassifier.KNOWN_MANAGEABLE_SYSTEM`) of media, gallery, games and
   assistant components, selectable without a per-device risk acceptance.
4. **Unclassified OEM component** — visible for diagnosis, failing closed until
   an administrator accepts the risk. The acceptance records package name,
   signer digest, version, prior state and firmware build, and is re-checked on
   every load: a changed signer or version reports `DRIFTED` and the component
   fails closed again.

Two consequences are load-bearing rather than incidental. A system package
reaches the allow/block rules **only** through the guarded
`AllowedAppsStore.setAdminSelectedSystemPackages` store, which strips the
protected catalogues again on write; the third-party "managed packages" set
stays free of system packages, because that set has no second gate and would
otherwise hide every system package an operator merely scrolled past under
"allow only what I select". And the screen never marks policy state itself:
saving hands off to `LockdownPolicyController`, which owns the requested →
applied/failed contract.

Packages Device Guard has hidden are omitted from bulk `PackageManager` queries,
so the inventory is the union of what the platform reports and every package we
have persisted a reason to remember — otherwise a blocked application would
vanish from the screen that blocked it.

Group controls such as "block all application stores" are **not** implemented;
the filters make the affected packages inspectable, which is the prerequisite
for them.

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

The console entry point is now wired: `MainActivity` opens `SystemPolicyActivity`,
`MaintenanceActivity`, `ManagementIdentityActivity` and `DeviceHealthActivity`
behind `requireSession()`, and each of those screens refuses to draw without a
live administrator session of its own.

One item remains:

1. **Production identity constant.** `SystemPolicyProfile.PRODUCTION_APPLICATION_ID`
   duplicates the application ID literal in `gradle/production-identity.gradle`.
   If issue #25 changes that ID, the constant must move with it. The safe failure
   mode if it is forgotten is that a production device is treated as a pilot.
   Publishing the flag as a `BuildConfig` field from the Gradle files would
   remove the duplication.

## Maintenance mode

Production deployments disable debugging and routine escape surfaces by default.
Authorized maintenance is a narrow, audited exception rather than a general
pause of protection. This is implemented in `maintenance/` as of 0.5.2.
Every authorization is bound to the current DPC process: process death or
restart invalidates the window and forces a verified base-policy restore. This
deliberately favors early closure over keeping a maintenance session alive.

An administrator chooses which capability to open:

- application-store access;
- installation of a local APK;
- selected Android settings;
- USB file transfer;
- ADB/debugging as an explicit break-glass option.

A window requires an active administrator PIN session, is bounded by a maximum
of four hours, and closes on expiry, on reboot, on a suspicious clock and on an
administrator cancel. Every close path restores the administrator's own stored
choices — not an inverse of what the window did, so a half-applied window still
lands in the same place — and reads the result back through the same
`SystemPolicyEnforcer` every other pass uses. A restore that cannot be proved is
reported as a failure and the window record is kept for the next pass rather
than being forgotten. The audit log records the action, the opened capability
keys, the duration, the close reason and the restore result, and no PIN,
recovery code or kiosk address.

Expiry is measured against the monotonic clock, so moving the calendar clock
cannot extend a window; a monotonic reading that has gone backwards, or a
calendar clock that has run far ahead of it, is read as a restart and closes the
window.

ADB maintenance carries an additional warning because clearing the debugging
restriction exposes a privileged transport. It is never implied by another
capability, is never pre-selected, and being reachable over the management
transport is not a reason to open it.

What is **not** proven: none of this has run on a device. The reboot detector,
the restore path and the break-glass warning are covered by JVM tests only, and
group M of [`hardware-validation.md`](hardware-validation.md) is what closes
that gap.

## Google Play compatibility mode

Some Play-distributed applications refuse to start unless the Google Play Store
package is available, even when Google Play services and the WebView provider
are untouched. That was reproduced on a Device Owner-provisioned Android 13
pilot with protection verified.

The response is an explicit administrator opt-in, off by default, that exempts
`com.android.vending` — and no other store — from the hidden-store rule, and
that pays for the exemption by pinning `DISALLOW_INSTALL_APPS` and both
unknown-source restrictions on and reading them back. A pass that cannot confirm
that installation lock hides the Store again and reports protection as
unverified, so protection is never `ACTIVE` over an unverified lock. Google Play
services and the active WebView provider stay protected by their own rules.

The boundary is stated rather than papered over: Android can hide a package but
not a single launcher entry, so on an ordinary launcher an available Store may
remain visible and openable, and installation is what is blocked. Kiosk
containment is stronger and unchanged — the Store can never be a lock-task
allowlist member or a pinned target — so a contained device keeps it off the
user's surface while dependent applications keep working.

The full design, the operator workflow and the fail-closed rules are in
[`play-store-compatibility.md`](play-store-compatibility.md). The cost is real
and documented: the signed self-update path cannot install while the
installation lock is on.

What is **not** proven: none of this has run on a device beyond the diagnostic
maintenance window that established the dependency. Group P of
[`hardware-validation.md`](hardware-validation.md) is what closes that gap.

## Known gaps in the 0.5.4 implementation

These are recorded rather than hidden, and none of them is a hardware gate:

1. **The health export carries no audit tail.** `DeviceHealthRedaction` enforces
   an allowlist of stable audit event codes, but `AuditLog` still stores
   localized prose with no machine code, so the collector passes an empty list
   and every export omits the section. The fail-closed end works — nothing
   untrusted escapes — but the allowlist is a contract for a future `AuditLog`,
   not evidence that entries travel today. Giving `AuditLog` an event code
   alongside its prose is the fix.
2. **Maintenance-mode enforcement outside the console is unproven.** Expiry is
   armed on `JobScheduler` and re-checked on boot, package replacement and a
   fifteen-minute sweep, so a window no longer depends on its screen being open.
   None of that has run on a device, and OEM job throttling is exactly the kind
   of behaviour a JVM test cannot reach. Group M of
   [`hardware-validation.md`](hardware-validation.md) is what closes it.
3. **The production identity constant is duplicated**, as described above.

## Acceptance criteria before customer production

The following are release gates rather than optional polish. Gates 4, 5, 6 and 7
are executed with [`hardware-validation.md`](hardware-validation.md) and
evidenced in [`device-matrix.md`](device-matrix.md); gate 2 uses
[`provisioning.md`](provisioning.md) and gate 3 uses
[`update-drill.md`](update-drill.md). As of 0.5.4 the offline release chain is
proven, but no complete runbook-qualified hardware record has been entered in
[`device-matrix.md`](device-matrix.md).

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

## Delivery sequence

- **0.5.2 — delivered.** System-application inventory, safety classifications,
  system policy controls, timed maintenance mode, management identity pinning
  and the local device health report, plus the provisioning, update-drill and
  hardware-validation tooling and runbooks.
- **0.5.3 — delivered.** The protected release workflow, signed
  prerelease, metadata Auto-merge and public read-back are delivered. Hardware
  validation remains explicitly open.
- **0.5.4 — current release line.** Google Play compatibility is an explicit
  administrator choice with a verified installation lock and fail-closed
  package visibility. The mode still requires its Group P hardware evidence.
- **Next pilot validation phase.** Execute the validation runbook on real Device
  Owner devices, complete the signed higher-version self-update on hardware,
  rehearse provisioning, and fix what those runs find. This phase turns
  "implemented" into "proven" for named firmware families.
- **1.0 production candidate:** fixed production identity and signing, a
  supported-device matrix with real evidence in it, and staged rollout.

The order is deliberate: everything that can be proved without hardware has been
proved, so a device is now needed for evidence rather than for development.

Version numbers are planning labels and may change. The security gates above do
not.
