# Kiosk mode

Device Guard 0.5 has three explicit operating profiles:

| Profile | `KioskMode` | What it does |
| --- | --- | --- |
| Managed app filtering | `OFF` | The 0.4 behaviour: allow/block lists, browser and store blocking, link interception. No lock task, no HOME takeover. |
| Single-app kiosk | `SINGLE_APP` | Android Lock Task pinned to exactly one administrator-selected application. |
| Single-site kiosk | `SINGLE_SITE` | Lock Task pinned to an in-app WebView confined to exactly one HTTPS origin. |

Kiosk is **opt-in**. An upgrade never enables it: `KioskConfigStore` starts at
`KioskMode.OFF` / `KioskState.OFF`, a corrupted mode preference falls back to
`OFF`, and `KioskStateMachine` refuses every path into `ACTIVE` that does not
begin with an authenticated `CONFIGURE`.

## Security boundary

Kiosk mode contains **a cooperative user on a Device Owner-provisioned device**.
It is not a defence against a determined attacker with physical possession, a
bootloader unlock, ADB, or a firmware flash — the boundaries in [`SECURITY.md`](../SECURITY.md)
still apply.

Specifically in scope:

- A student cannot reach another application, the launcher, Overview, the
  notification shade, the keyguard, or the power menu while Lock Task holds.
- A student cannot navigate the single-site WebView off the configured origin,
  open a popup, follow an `intent://` link into another app, download a file, or
  proceed through a TLS error.
- A reboot returns to the configured kiosk target rather than to a launcher.
- Leaving, switching or reconfiguring kiosk requires an authenticated
  administrator session.

Explicitly **out of scope**:

- **Single-site kiosk is navigation containment, not a network firewall.** The
  guard in `KioskNavigationGuard` decides top-level navigation only.
  Sub-resource loads — scripts, fonts, images, XHR/fetch to a CDN or an API on
  another host — are not restricted, because real school portals are cross-origin
  by construction. A page on the allowed origin can still talk to the wider
  internet, and content it embeds can render arbitrary remote data. If a
  deployment needs network-level restriction, that belongs to the network, not to
  this WebView.
- Physical attacks, recovery mode, unlocked bootloaders, and OEM backdoors.
- Screen mirroring, external displays, and accessibility services installed
  outside Device Guard's control.

## Authorization

Every operator-facing transition goes through `KioskController`, which derives
the administrator session from `AdminSession` itself rather than accepting an
"authenticated" flag from its caller. The pure rules live in `KioskStateMachine`:

```
OFF --CONFIGURE(admin,valid)--> ARMED --ENTER(admin,valid)--> ACTIVE
ACTIVE --EXIT(admin)--> ARMED --CLEAR(admin)--> OFF
ACTIVE --BOOT_RESTORE(no admin, valid)--> ACTIVE
ACTIVE --BOOT_RESTORE(no admin, invalid)--> FAULT
{ARMED,ACTIVE} --FAULT--> FAULT
```

`BOOT_RESTORE` is the only unauthenticated route into `ACTIVE`, it is reachable
only from a persisted `ACTIVE`, and it can never reach `ARMED` or `OFF`. A reboot
is therefore not a way out of kiosk.

`KioskController` is a backend surface: nothing in it is exported, and no
component exposes an intent that changes kiosk state. Console wiring lands in a
later change.

### Administrator entry from inside kiosk

`AdminEntryGesture` — seven taps within three seconds on an unlabeled 56 dp
target in the top-start corner of the kiosk host — starts the existing console
through `KioskAdminEntry.consoleIntent`. That intent is always **explicit** (it
names `ui.MainActivity`), carries no authority, and lands on the locked PIN
screen. There is no secret code path and no hardcoded PIN; the gesture buys an
opportunity to authenticate, nothing more. The DPC package stays on the Lock Task
allowlist precisely so this recovery route works.

## Lock Task

`KioskController.reconcile` sets:

- `setLockTaskPackages(admin, {dpcPackage} ∪ {target if SINGLE_APP})` and verifies
  each entry with `isLockTaskPermitted`.
- `setLockTaskFeatures(admin, LOCK_TASK_FEATURE_NONE)` on **API 28+**. This is the
  minimal set: no Home, no Overview, no notifications, no system info area, no
  global actions, no keyguard. The visible cost is that the power-button menu is
  unavailable while kiosk holds; a device is still powered down by holding the
  power button. On **API 26–27** there is no feature selector at all and Lock Task
  uses the platform's legacy behaviour.
- The kiosk HOME preference: an `ACTION_MAIN` + `CATEGORY_HOME` persistent
  preferred activity pointing at `KioskHostActivity`, plus enabling that
  component. Both are removed on exit.

`KioskHostActivity` is declared `android:enabled="false"` in the manifest, so the
HOME component simply does not exist on a device that never enabled kiosk. HOME
is never hijacked in the managed-filtering profile.

### Persistent preferred activities

Android can only clear persistent preferred activities per package, so removing
the kiosk HOME preference also removes the `http`/`https` link handlers that
managed filtering installs. `KioskConfigStore` tracks whether a kiosk HOME
preference is installed; `LockdownPolicyController.apply()` calls
`KioskController.reconcile` **before** `configureBlockedBrowser`, so the link
handlers are re-registered in the same pass. `pause()` calls it afterwards, so an
active kiosk keeps its HOME preference even while managed filtering is paused.

## Single-app kiosk

A target is accepted only when it is explicitly selected and
`KioskConfigValidator` confirms it is installed, enabled, launchable, not the DPC
itself, and not an essential system component. The resolver
(`KioskController.resolveTarget`) reads `PackageManager`; the decision is pure and
unit tested.

Launch mechanism by API level:

- **API 28+**: `ActivityOptions.makeBasic().setLockTaskEnabled(true)` starts the
  target directly into Lock Task.
- **API 26–27**: the host calls `startLockTask()` and the allowlisted target
  inherits the locked task.

If the target cannot be launched, or comes straight back to the host within
1.5 s, the host shows its error state instead of relaunching in a loop or falling
back to a launcher.

## Single-site kiosk

`KioskUrl.normalize` accepts only an absolute, hierarchical, credential-free
HTTPS URL with an ASCII host containing at least one dot and no dot-segments. It
rejects `http`, `intent`, `javascript`, `data`, `blob`, `file`, `content`,
custom app schemes, opaque URIs, embedded credentials, whitespace, control
characters and backslashes. Internationalized domains must be configured in their
punycode (`xn--`) form; non-ASCII hosts are rejected outright, which removes the
homograph class rather than trying to detect it.

The containment unit is the **origin** — scheme, host, effective port.
`https://portal.school.example` does not imply `https://mail.school.example`,
`https://school.example`, or `https://portal.school.example:8443`.

WebView configuration in `KioskHostActivity`:

| Setting | Value | Why |
| --- | --- | --- |
| JavaScript | enabled | Real school portals require it. |
| `JavascriptInterface` bridges | none, ever | Page script gets no path into the DPC. |
| File / content access | off | Includes `file://`-origin access flags. |
| Multiple windows, auto-opened windows, `onCreateWindow` | off / refused | A popup would bypass the navigation check. |
| Downloads | refused with a notice | |
| Mixed content | `MIXED_CONTENT_NEVER_ALLOW` | |
| TLS errors | `handler.cancel()` + error state | Fail closed; never "continue anyway". |
| Safe Browsing | on | |
| Third-party cookies | off | |
| Geolocation, form data, autoplay | off | |
| WebContents debugging | only in debuggable builds | Off in release. |
| Long-press | consumed | Removes the "Web search" escape from the text selection menu. |

A blocked navigation or download shows a transient notice and leaves the page
intact; it never throws away a session the user legitimately started. Network
failures, TLS failures, and an unusable configuration show the full error state
with a retry — never another browser or launcher.

## Package and system-app policy

Device Guard does **not** operate a total system allowlist. Hiding every system
package bricks OEM devices in ways the console cannot repair, so the model is
explicit and conservative. `LockdownPackages.classify` returns:

| Class | Behaviour |
| --- | --- |
| `ESSENTIAL_SYSTEM_PACKAGE` | Never hidden, never suspended, never a kiosk target. `ESSENTIAL_SYSTEM` is pinned by test to be disjoint from every block catalogue. |
| `MANAGEMENT` | Management connectivity; exempt from blocking **only** when its signer check passes. |
| `KIOSK_ESCAPE_SURFACE` | Hidden while kiosk is `ACTIVE`, restored when it is not. Untouched on a device that never enabled kiosk. |
| `ADMIN_SELECTED_SYSTEM` | A system app an administrator explicitly opted into managing, via `AllowedAppsStore.setAdminSelectedSystemPackages`. Empty by default; essential packages are filtered out on write. |
| `ORDINARY` | The existing allow/block rules. |

In kiosk, Lock Task already prevents navigating to most packages, so blanket
hiding is unnecessary. What is not optional is the known escape surfaces — file
managers, document pickers, download UIs, the HTML viewer, the setup wizard — a
share sheet or an OEM shortcut into one of those is a real exit. Those are hidden
and the result is verified through the same `setApplicationHidden` /
`isApplicationHidden` round-trip the rest of the policy uses.

`KioskConfigStore.wasEscapeSurfaceHidingApplied` keeps a device that never
enabled kiosk on exactly the 0.4 code path, while guaranteeing one reconciliation
pass that restores those packages after kiosk is switched off. The flag is only
cleared after a pass that completed without errors.

## Critical management packages

Management packages are configuration records, not string literals:

```java
record ManagementPackage(String packageName, Set<String> approvedCertificateSha256)
```

`LockdownPackages.MANAGEMENT_DEFAULTS` ships one record — `com.tailscale.ipn`
with **no** pinned certificate — so the current pilot behaves exactly as before.
An operator tightens a record with `AllowedAppsStore.setManagementCertificatePins`;
configuration can only tighten an existing record, never add a new management
package, because that would be a privilege grant from preferences.

`LockdownPackages.verifySigner` fails closed:

| Verdict | Meaning | Trusted? |
| --- | --- | --- |
| `UNPINNED` | No digest configured. | Yes — **explicit proof gap** (see below). |
| `MATCH` | Configured digest matches an installed signer. | Yes |
| `MISMATCH` | Digest configured, no installed signer matches. | No |
| `UNKNOWN_SIGNER` | Digest configured, platform reported no readable signer. | No |

An untrusted verdict removes the package from `trustedManagement`. The package
then gets no uninstall protection, is **hidden** rather than exempted — an
impostor must not keep the exemption its package name would have bought — and the
whole apply is reported as unverified.

### Proof gap: unpinned Tailscale

With no digest configured, the Tailscale record authenticates a **package name**
and nothing else. Any application installed under `com.tailscale.ipn` inherits
the management exemption. This is deliberate — it preserves the pilot — but it is
a real gap. Configure the release signing certificate's SHA-256 digest to close
it. `DISALLOW_INSTALL_UNKNOWN_SOURCES`, `DISALLOW_APPS_CONTROL` and store
blocking narrow, but do not eliminate, the window in which such a package could
be installed.

## Android version behaviour

| API | Behaviour |
| --- | --- |
| 26–27 (8.0–8.1) | Lock Task via `startLockTask()`; **no** `setLockTaskFeatures`, so the platform's legacy feature set applies. Single-app targets inherit the host's locked task. |
| 28+ (9) | `setLockTaskFeatures(LOCK_TASK_FEATURE_NONE)` and verification via `getLockTaskFeatures`. `ActivityOptions.setLockTaskEnabled(true)` for single-app launch. Signer digests read from `SigningInfo`. |
| < 28 | Signer digests read from the deprecated `PackageInfo.signatures`. |
| 33+ (13) | `PackageManager` queries use the `…Flags.of` overloads, matching the rest of the policy engine. |
| 34+ (14) | Policy application is asynchronous; the existing bounded-retry verification in `configureBlockedBrowser` and `PolicyUpdateAuditReceiver` still apply. Kiosk adds no new assumption here. |

## What is not proven without a device

The following require a Device Owner-provisioned handset and are **not** verified
by the unit tests in this change:

- That `startLockTask()` actually holds, and that `LOCK_TASK_FEATURE_NONE`
  suppresses Home, Overview, the shade, global actions and the keyguard on a
  given OEM build.
- That the HOME persistent preferred activity survives reboot on a given OEM
  build and that no vendor launcher wins the race.
- That a single-app target genuinely enters Lock Task through
  `ActivityOptions.setLockTaskEnabled` on API 28+.
- That hiding each `KIOSK_ESCAPE_SURFACES` entry succeeds on a given OEM build,
  and that no vendor-specific escape surface is missing from the catalogue.
- That no OEM shortcut, gesture, or accessibility surface escapes Lock Task.
- Real-world WebView behaviour of the containment rules against a specific school
  portal, including whether the site works with third-party cookies disabled.
