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
  notification shade, or the keyguard while Lock Task holds. On API 28+ the power
  menu is suppressed too; on API 26–27 there is no feature selector, so the
  platform's legacy behaviour decides and the power menu is not claimed.
- In a **single-app** kiosk on API 28+ the Home key is deliberately enabled and
  returns to `KioskHostActivity`, never to a launcher: `KioskHostActivity` is the
  registered HOME activity and Lock Task refuses to start any activity outside the
  allowlist, so a vendor launcher that won the preference race cannot be reached
  either. What Home buys is the contained kiosk home surface, and with it the
  administrator gesture. It grants nothing — see "Administrator entry" below.
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
component exposes an intent that changes kiosk state.

### Console flow

The operator-facing flow lives inside the authenticated `MainActivity` console,
under **Kiosk profile → Operating profile**. It is four screens, and the split is
the point: no single tap can take a classroom device away from the person holding
it.

| Screen | What it does | Authorization |
| --- | --- | --- |
| Operating profile | Shows the current profile, state and target; offers the three profiles as a radio group | `AdminSession` |
| Choose the locked app | Searchable list of eligible single-app targets | `AdminSession` |
| Set the locked website | HTTPS editor with a live normalized address and allowed origin | `AdminSession` |
| Lock this device? | Confirmation and recovery explanation, then activation | `AdminSession` |

Selecting a profile is a *pending* choice. Saving it calls
`KioskController.requestConfigure`, which only reaches `ARMED` — nothing an end
user can see changes. Locking is a separate, confirmed step
(`requestEnter`). Exiting (`requestExit`) and removing the configuration
(`requestClear`) are equally explicit.

Every one of those four screens is marked `requiresSession`, so the console drops
to the PIN screen on resume if the three-minute administrator session has
expired. That check is a courtesy: `KioskController` reads `AdminSession` itself,
so a screen cannot assert that it is authenticated.

The console's own **dialogs** re-check the session at *save*, not only when they
were opened. `AdminSession` expires on wall time rather than on interaction, so a
console left on a desk with the blocking-method or display-language dialog open
could otherwise be saved by whoever picked the device up three minutes later —
and that write commits before the console drops back to the PIN screen. Rotating
the recovery code goes through a confirmation dialog for the same reason it is
routed through `requireSession` again: it revokes a standing credential a school
holds off-device, and the row directly above it is "Change the administrator PIN".

The **display-language picker stays in the authenticated console** (Display →
Display language) and is deliberately absent from the locked kiosk surface. The
kiosk host still renders in the chosen language: it extends `AppCompatActivity`
for exactly that reason, which is what applies the persisted per-app locale below
API 33.

A console caller waits for the serialized policy pass that a kiosk transition
queues (`KioskController.requestX(context, onPolicyReconciled)`), because leaving
kiosk clears this package's persistent preferred activities — taking the
managed-filtering link handlers with it — and that pass is what puts them back.
Reporting "managed filtering is in force again" before it finishes would be a
claim the device has not made yet.

### Administrator entry from inside kiosk

`AdminEntryGesture` — seven taps within three seconds in the **top corner on the
side the text starts from** (top-left in English, top-right in Hebrew) — starts
the existing console through `KioskAdminEntry.consoleIntent`. That intent is
always **explicit** (it names `ui.MainActivity`), carries no authority, and lands
on the locked PIN screen. There is no secret code path and no hardcoded PIN; the
gesture buys an opportunity to authenticate, nothing more. The DPC package stays
on the Lock Task allowlist precisely so this recovery route works.

The counter observes `KioskHostActivity.dispatchTouchEvent` and **forwards the
event untouched**. Up to 0.5.0 it was an invisible, click-consuming 56 dp `View`
laid over the surface, which swallowed every touch in the one square where a
school portal puts its logo, its home link or its hamburger menu — in either
direction, because the target mirrors with the layout. The hit test itself is
pure (`AdminEntryCorner`) and unit tested in both directions.

#### Reaching the gesture in a single-app kiosk

The gesture only helps if the screen it lives on is reachable. In 0.5.0 it was
not: single-app mode handed the display to the pinned package and pinned Lock Task
to `LOCK_TASK_FEATURE_NONE`, so a target that traps Back — a full-screen player,
an exam client, a signage app — left `KioskHostActivity` unreachable for as long
as it ran. The console promised a recovery path that did not exist, and
re-provisioning (a wiped classroom device) became the first resort rather than the
last.

The supported Device Owner shape is used instead. `KioskRecoveryPolicy` decides
two things, both pure and unit tested:

| Decision | Rule |
| --- | --- |
| `allowHomeKey(mode, homeRegistered)` | `LOCK_TASK_FEATURE_HOME` is set **only** for `SINGLE_APP`, and **only** once `addPersistentPreferredActivity` has actually made this DPC the HOME host. Single-site needs nothing — its host *is* the foreground activity. |
| `surfaceFor(mode, configValid, targetLaunched)` | The first pass of a single-app host starts the target. Every later resume — the Home key, or a target that closed itself — renders the **contained kiosk home** instead of relaunching. |

The contained kiosk home names the locked application and offers one action,
"Return to the app", plus the corner gesture every surface of this activity
carries. It is not an exit: the console it can reach still opens on its PIN screen,
and `KioskController` re-derives `AdminSession` for every transition regardless.

`KioskController.reconcile` therefore enables the host component and registers the
HOME preference **before** applying the feature set that depends on them. If the
platform refuses `LOCK_TASK_FEATURE_HOME`, the minimal set is reapplied and
`kiosk-lock-task-home-unavailable` is recorded, so the console reports "recorded,
but the device did not confirm every step" rather than implying a recovery route
that is not there. On **API 26–27** there is no feature selector at all, so Home
is not available and the gesture is reachable only once the pinned app closes;
`kiosk_recovery_single_app` says exactly that, in both languages.

Because nothing relaunches on its own any more, the 1.5 s relaunch cooldown is
gone: there is no loop left for it to break, and a target that bounces straight
back now lands on the kiosk home instead of an error screen claiming the app is
unavailable.

**The trade-off, stated.** A single-app target that closes *itself* now shows the
kiosk home rather than being relaunched automatically. The host could tell the two
apart by watching `onNewIntent` for the HOME intent and auto-relaunching otherwise
— but if any build did not deliver that intent, the host would relaunch over the
recovery surface and the P1 would be back. This fails toward reachability
deliberately: the cost is one tap on "Return to the app", the alternative is an
unrecoverable classroom device.

**Administrator note.** The target is invisible and its hit area is one 56 dp
square out of a full display, so it is not something a student finds by pressing
the screen; it is something you have to know about and aim at. The three-second
window means a slow, exploratory tap sequence does *not* complete it. Brief every
person who is expected to service these devices, and treat the gesture as a
convenience rather than as a secret: the security boundary is the PIN, not the
corner.

## Lock Task

`KioskController.reconcile` sets:

- `setLockTaskPackages(admin, {dpcPackage} ∪ {target if SINGLE_APP})` and verifies
  each entry with `isLockTaskPermitted`.
- The kiosk HOME preference: an `ACTION_MAIN` + `CATEGORY_HOME` persistent
  preferred activity pointing at `KioskHostActivity`, plus enabling that
  component. Both are removed on exit. This is applied **before** the feature set,
  because the feature set can depend on it.
- `setLockTaskFeatures` on **API 28+**, per profile:
  `LOCK_TASK_FEATURE_NONE` for single-site and for a fault state under managed
  filtering — no Home, no Overview, no notifications, no system info area, no
  global actions, no keyguard — and `LOCK_TASK_FEATURE_HOME` for single-app, where
  Home is the route back to the DPC's own kiosk home and to the administrator
  gesture (see above). Everything else stays suppressed either way. The visible
  cost is that the power-button menu is unavailable while kiosk holds; a device is
  still powered down by holding the power button. On **API 26–27** there is no
  feature selector at all and Lock Task uses the platform's legacy behaviour, so
  neither the power-menu claim nor the Home route applies there.

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
itself, and not a protected package. The resolver
(`KioskController.resolveTarget`) reads `PackageManager`; the decision is pure and
unit tested.

**Protected** is decided by `KioskAppCatalog.isProtectedFromKiosk`, which is the
single rule the console picker filters with *and* the resolver feeds into the
validator. It covers three classes:

| Class | Why it may not be pinned |
| --- | --- |
| `ESSENTIAL_SYSTEM_PACKAGE` | Taking over system UI, settings or an IME is not repairable from the console. |
| `MANAGEMENT` | Pinning the management transport would trade remote access for containment. |
| `KIOSK_ESCAPE_SURFACE` | A file manager or documents picker *is* the way out. Hiding it everywhere else and then pinning it as "the one allowed app" would be self-defeating. |

The escape-surface exclusion is the one a picker built on "installed and
launchable" alone gets wrong: `com.android.documentsui` passes every device
check. `KioskAppCatalogTest` pins every entry of `KIOSK_ESCAPE_SURFACES`,
`ESSENTIAL_SYSTEM` and the management records as non-selectable.

Classification uses an **empty** administrator-selected system set on purpose: an
operator opting a system app into ordinary allow/block management must not
thereby make an escape surface eligible as the pinned kiosk application.

The picker lists installed, launchable applications **including ones this policy
currently hides**, and including remembered packages the DPC has managed before.
Hidden packages are invisible to `getLaunchIntentForPackage`, so both the picker
and `resolveTarget` resolve launchability with `queryIntentActivities` under
`MATCH_UNINSTALLED_PACKAGES | MATCH_DISABLED_COMPONENTS`. Pinning a hidden app is
legitimate: `applyPackagePolicy` unhides the kiosk target on the next pass. Each
row shows the application label and the package name, the label isolated without
a forced direction and the package name isolated left-to-right so its
dot-separated segments keep their order inside a Hebrew page.

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

The console editor normalizes as you type and shows **both** the opening address
and the derived allowed origin before anything is stored, because those are
different things and an operator has to see which containment they just asked
for. It also states, on the same screen, that links leaving the origin are
blocked and that this is not a network firewall. Both values are rendered
left-to-right isolated so a Hebrew console does not reorder a URL. The same
`KioskUrl.normalize` rule runs in the editor and on the device, so nothing is
accepted in the console that the device would then refuse.

`KioskNavigationGuard` is consulted from `shouldOverrideUrlLoading`, which
Android calls for **subframe navigations as well as top-level ones** on API 24+.
The guard therefore blocks a cross-origin iframe navigation too. That is a
deliberate fail-closed choice and a real compatibility cost: a portal that embeds
a third-party widget by navigating an iframe cross-origin will show the blocked
notice. Sub-resource loads — scripts, fonts, images, XHR — are *not* filtered, so
the containment remains navigation containment rather than a network control.

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
| `onRenderProcessGone` | detach, destroy, show the error state | Without it a renderer crash kills the process — and that process is HOME while kiosk holds, so the device would sit in a crash loop with no launcher behind it. |
| Back | `OnBackPressedCallback`, permanently enabled | Goes back inside the WebView when it can, and is swallowed otherwise. Registered on the dispatcher rather than by overriding `onBackPressed`, which at `targetSdk 33+` is no longer invoked for a back *gesture* — only for the legacy button. |

A blocked navigation or download shows a transient notice and leaves the page
intact; it never throws away a session the user legitimately started. Network
failures, TLS failures, and an unusable configuration show the full error state
with a retry — never another browser or launcher.

## Reboot and package-update lifecycle

`PolicyRefreshReceiver` handles `BOOT_COMPLETED` and `MY_PACKAGE_REPLACED`. It
performs **no** policy work inline; it queues, in order, on the single
reconciliation thread owned by `PolicyReconciliationCoordinator`:

1. `restoreKioskAsync` — re-asserts an already-active kiosk (lock task, the
   lock-task feature set, the HOME preference) via
   `KioskController.restoreAfterBootOnce`.
2. `reconcileAsync` or `pauseAsync` — the existing full package pass, whose
   `PendingResult` finishes the broadcast.

Restoration is one-directional and unauthenticated by design: `BOOT_RESTORE` is
reachable only from a persisted `ACTIVE`, so this path can never enter, leave or
change a kiosk profile. A reboot is neither a way in nor a way out.

`KioskHostActivity.onCreate` calls the same `restoreAfterBootOnce`. The flag is
per process, so whichever of the two runs first does the work and the other
no-ops. On a device where kiosk is `OFF`, `restoreKioskAsync` short-circuits
before touching `DevicePolicyManager`, so managed filtering behaves exactly as it
did in 0.4.

## Audit events

Kiosk writes to the same `AuditLog` as the rest of the console:

| Event | When |
| --- | --- |
| `audit_kiosk_configured_off` / `_app` / `_site` | A profile was saved |
| `audit_kiosk_activated` | Lock task was entered |
| `audit_kiosk_activation_failed` | An activation request was refused, with the machine reason |
| `audit_kiosk_exited` | Lock task was left and managed filtering restored |
| `audit_kiosk_cleared` | The configuration was removed |
| `audit_kiosk_restored` / `audit_kiosk_restore_failed` | Reboot or update reconciliation |
| `audit_kiosk_fault` | The runtime could not honour the stored configuration |
| `audit_kiosk_admin_entry` | The corner gesture opened the console |

What is deliberately **not** logged: administrator PINs and recovery codes (they
never reach this layer at all), and the path, query and fragment of a single-site
target. A single-site configure event records the **origin** only — scheme, host
and effective port. Query strings routinely carry tokens, and the audit log is
readable from the console by anyone holding the administrator PIN.

## Localization

Every operator-facing kiosk string lives in `res/values/strings.xml` (English,
the default locale) and `res/values-iw/strings.xml` (Hebrew), including the text
on the locked surface itself. `LocaleParityTest.kt` and
`tools/check_locale_parity.py` enforce key, plural-category and placeholder
parity across both, so a kiosk string added to one locale and forgotten in the
other is a build failure rather than an English sentence in the middle of a
Hebrew screen.

Machine-readable reasons are *not* strings.xml entries. `KioskStateMachine`,
`KioskConfigValidator` and `KioskController.reconcile` emit stable codes
(`admin-authentication-required`, `target:not-installed`,
`kiosk-lock-task-features-unverified`); `ui/KioskConsoleLogic.kt` classifies them
purely and the composable maps the classification to a resource. That keeps the
codes language-neutral for logs and support, and keeps every displayed word under
the parity check. An unrecognised code is shown verbatim rather than mapped onto
a reassuring bucket.

Layout uses Compose's logical `start`/`end` padding and `TextAlign.End`, so it
mirrors under RTL without per-direction rules. Package names, URLs and origins
are wrapped in U+2066/U+2069 (`ltrIsolated`) so they stay visually
left-to-right inside a Hebrew paragraph; third-party application labels use
first-strong isolation (`bidiIsolated`) because their language is unknown at
build time — including the label the activation row and the confirmation card
name as "the target", which up to 0.5.0 was forced left-to-right and rendered a
Hebrew label such as `סרטונים (בטא)` with its parentheses resolved against the
wrong base. The Java kiosk host has the same two helpers in `kiosk/BidiText.java`,
pinned to the Kotlin pair by `BidiTextParityTest`. Neither icon used in this flow
— a padlock, a globe — is directional, so neither is mirrored.

Free-text fields resolve their own direction rather than inheriting the page's:
the website editor is pinned left-to-right (a URL is almost entirely neutral and
weak characters, so an RTL paragraph displaces its punctuation and port and makes
the caret jump), and the two app searches use content direction, the platform
equivalent of `dir="auto"`.

The layout direction itself comes from `R.bool.use_rtl_layout`, answered by the
same resource folder the strings came from, rather than from
`Configuration#getLayoutDirection`. Device Guard ships two translations, so a
device set to a third right-to-left language with the display language on "System
default" used to resolve English strings into a fully mirrored layout — which also
moved the administrator corner away from "the side the text starts from", the
wording both recovery notes use. `LockdownTheme` and `KioskHostActivity` read the
same bool, so text and layout cannot disagree.

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

### Deferred: an administrator UI for `ADMIN_SELECTED_SYSTEM`

The planned product behavior and production acceptance criteria are now tracked
in [`production-roadmap.md`](production-roadmap.md). The important current-state
summary is unchanged: Pilot 0.5.1 does not display arbitrary system packages in
the administrator application picker.

`AllowedAppsStore.setAdminSelectedSystemPackages` exists, filters
`ESSENTIAL_SYSTEM` on write, and is exercised by the policy engine. A console
screen that writes it is nonetheless **deferred to a later release**, and 0.5
ships no such screen.

The backend guard is necessary but not sufficient. `ESSENTIAL_SYSTEM` is a
curated catalogue of packages we know must survive; it is not, and cannot be, an
exhaustive list of every package a given OEM build needs. Handing an
administrator a list of *all* system packages with checkboxes invites hiding a
vendor launcher, a vendor telephony shim, or an OEM-specific settings provider
that is absent from the catalogue — and the resulting device is not repairable
from the console, which is the exact failure mode the conservative model exists
to prevent. Until there is a way to establish which system packages are safe on a
given build, the honest answer is to keep the model conservative rather than to
ship a screen whose worst case is a bricked classroom device.

Operators who need a specific system app under allow/block control today can have
the record written by a build that calls `setAdminSelectedSystemPackages`
directly, with the risk accepted deliberately.

### Management connectivity is presented, not configured

The console has one read-only **Management connectivity** view. It lists each
`ManagementPackage` record and states its pin status in as many words:
*signing certificate pinned*, *no certificate pinned — trusted by name only*, or
*not installed on this device*. The shipped Tailscale default is unpinned, and
the view says so rather than implying the package was authenticated. Writing
pins remains `AllowedAppsStore.setManagementCertificatePins`; the console does
not expose it, because a mistyped digest fails closed and hides the management
transport. `AllowedAppsActivity` now reads the excluded management packages from
`LockdownPackages.managementPackageNames()` instead of a package-name literal, so
the app list, the policy engine and the kiosk target rules exclude the same set.

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
| 26–27 (8.0–8.1) | Lock Task via `startLockTask()`; **no** `setLockTaskFeatures`, so the platform's legacy feature set applies and Home is not available as a recovery route. Single-app targets inherit the host's locked task. |
| 28+ (9) | `setLockTaskFeatures` — `LOCK_TASK_FEATURE_NONE`, or `LOCK_TASK_FEATURE_HOME` for single-app — verified via `getLockTaskFeatures`, with a fall back to the minimal set if HOME is refused. `ActivityOptions.setLockTaskEnabled(true)` for single-app launch. Signer digests read from `SigningInfo`. |
| < 28 | Signer digests read from the deprecated `PackageInfo.signatures`. |
| 33+ (13) | `PackageManager` queries use the `…Flags.of` overloads, matching the rest of the policy engine. |
| 34+ (14) | Policy application is asynchronous; the existing bounded-retry verification in `configureBlockedBrowser` and `PolicyUpdateAuditReceiver` still apply. Kiosk adds no new assumption here. |

## Recovery

Before enabling kiosk on a device you cannot easily reach, make sure all three of
these are true:

1. The administrator PIN is known to more than one person.
2. A current recovery code is stored somewhere outside the device.
3. Somebody who will be near the device knows the corner gesture.

Kiosk is not a state the device leaves on its own. A reboot returns to the kiosk
target, an app update reasserts it, and every exit path requires an authenticated
`AdminSession`. **Without the PIN and without the recovery code, the only way out
is re-provisioning the device** — normally management removal or a factory reset
followed by fresh provisioning, which destroys local data. That is the intended
property, and it is why the activation screen is separate, confirmed, and states
it before locking.

If kiosk is active but its configuration has gone stale (target uninstalled, site
policy tightened), the host lands in `FAULT` and shows a safe error screen rather
than a launcher. The corner gesture still works there, because the error state is
still the kiosk host and the DPC package is still on the Lock Task allowlist.

## What is not proven without a device

Everything in this section is **unverified on real hardware**. Kiosk mode has not
been tested on a Device Owner-provisioned handset, and no OEM build has been
checked. Do not read the unit tests as hardware verification: they prove the
pure rules — the state machine, the URL and origin rules, the target eligibility
rules, the console's classification of every refusal — and nothing about what
Android actually does when asked.

The following require a Device Owner-provisioned handset and are **not** verified
by the unit tests in this change:

- That `startLockTask()` actually holds, and that `LOCK_TASK_FEATURE_NONE`
  suppresses Home, Overview, the shade, global actions and the keyguard on a
  given OEM build.
- **That `LOCK_TASK_FEATURE_HOME` is accepted at all**, given that this DPC
  registers `KioskHostActivity` as the persistent preferred HOME activity in the
  same pass. The platform rejects the flag when it sees no launcher it can use;
  the code applies it after the registration, verifies with
  `getLockTaskFeatures`, and falls back to the minimal set while recording
  `kiosk-lock-task-home-unavailable`, so a refusal is safe and visible rather than
  silent — but the accepting case is unverified here. This is the **first** thing
  to check for this change on the pilot handset (scenario K-3).
- That pressing Home in an active single-app kiosk resumes `KioskHostActivity`
  rather than reaching a launcher or a resolver, on a given OEM build, and that
  the contained kiosk home is what appears rather than an immediate relaunch of
  the target.
- That Overview, the shade, the keyguard and (API 28+) the power menu remain
  suppressed once `LOCK_TASK_FEATURE_HOME` is the applied feature set — the flag
  is documented as additive, but only a device shows it.
- That observing corner taps in `dispatchTouchEvent` still completes the gesture
  over a live `WebView`, and that the portal's own top-corner control now
  responds.
- That the HOME persistent preferred activity survives reboot on a given OEM
  build and that no vendor launcher wins the race.
- That a single-app target genuinely enters Lock Task through
  `ActivityOptions.setLockTaskEnabled` on API 28+.
- That hiding each `KIOSK_ESCAPE_SURFACES` entry succeeds on a given OEM build,
  and that no vendor-specific escape surface is missing from the catalogue.
- That no OEM shortcut, gesture, or accessibility surface escapes Lock Task.
- Real-world WebView behaviour of the containment rules against a specific school
  portal, including whether the site works with third-party cookies disabled, and
  whether blocking cross-origin *subframe* navigation breaks it.
- That `queryIntentActivities` under `MATCH_UNINSTALLED_PACKAGES |
  MATCH_DISABLED_COMPONENTS` really does resolve a launcher entry point for a
  package this DPC has hidden, on a given OEM build. The picker and the validator
  both depend on it; if a build disagrees, a hidden app is refused as
  `target:not-launchable` rather than being pinned incorrectly, so the failure is
  safe but visible.
- That `dpm.isLockTaskPermitted(dpcPackage)` returns false after
  `setLockTaskPackages(admin, {})` on a given build. If some build reports the
  device owner as implicitly permitted, `disableKiosk` would record
  `kiosk-lock-task-release-unverified` on every policy pass of a kiosk-off
  device, turning ordinary managed filtering into a reported failure. This is the
  first thing to check on the pilot handset.
- That the administrator corner gesture is reachable and that seven taps in three
  seconds is the right balance on a real classroom display.
- That `onRenderProcessGone` recovery leaves the kiosk host usable rather than
  wedged.
