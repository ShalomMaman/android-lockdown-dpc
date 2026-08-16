# Hardware validation runbook

Device Guard's automated suite is a JVM suite. It proves pure rules — the kiosk
state machine, URL and origin containment, target eligibility, the system-policy
verification contract, locale parity — and it proves **nothing about what Android
actually does** when a Device Owner asks for those things. Every claim about lock
task, HOME preference, escape-surface hiding, user restrictions and silent
installation is currently unverified. [`kiosk-mode.md`](kiosk-mode.md#what-is-not-proven-without-a-device)
enumerates the gaps; this document is how they get closed.

This runbook is written to be executed rather than read. A technician holding a
provisioned handset should be able to run it end to end without inventing a step,
and the record it produces should let a reviewer who was not in the room decide
whether a firmware family is fit for a customer.

Results are recorded in [`device-matrix.md`](device-matrix.md). This document
defines the procedure; that one holds the evidence.

## What this runbook does and does not establish

It establishes that a specific Device Guard build, on a specific device model at
a specific firmware build, behaves as the console claims for the cases listed
here.

It does **not** establish that the device is secure against an attacker with
physical possession, a bootloader unlock, a firmware flash or recovery-mode
access. Those boundaries are stated in [`SECURITY.md`](../SECURITY.md) and are
unchanged by any result below. It also does not generalise: a pass on one
firmware build is evidence for that build and, at most, a prior for the next one
from the same vendor. See [`device-matrix.md`](device-matrix.md#re-validation-triggers).

## Roles

| Role | Responsibility |
| --- | --- |
| **Operator** | Executes the steps on the device. Holds administrator PIN copy 1. |
| **Witness** | Records evidence, holds administrator PIN copy 2 and the recovery code, and is the person who can unlock the device if the operator is locked out. Never leaves the room while a kiosk case is running. |
| **Reviewer** | Accepts or rejects the run afterwards from the recorded evidence alone. Does not need to have been present. |

The operator and the witness are two people. This is not ceremony: several cases
deliberately drive the device into a state whose only exits are the administrator
PIN, the recovery code, or a data-destroying reset.

## Equipment

- One device per firmware family under test, dedicated to testing and containing
  no data anyone needs.
- A USB cable and a workstation with `adb` and the Android SDK platform tools.
- A camera or a second phone for photographing screens. Screen recording from the
  device itself is not available while lock task holds.
- A reachable HTTPS test site on a known origin, and a second HTTPS site on a
  different origin, for the single-site cases.
- A signed Device Guard APK of a **higher** version code than the installed one,
  and its signed update manifest, for the self-update case
  ([`secure-updates.md`](secure-updates.md)).
- A printed copy of the abort procedure in
  [Abort and recover](#abort-and-recover). It is needed exactly when the device
  cannot show it to you.

## Preconditions

Do not begin until all of these are true. Each is a precondition because a case
below can fail unrecoverably without it.

- **PRE-1 — Clean device.** The device is factory reset immediately before
  provisioning, has no accounts added, and holds no data. `dpm set-device-owner`
  is refused on a device with an existing account, and the failure mode is a
  second factory reset.
- **PRE-2 — Known build.** Record the exact firmware build before anything else:
  Settings → About phone → Build number, plus the Android release. This string is
  the identity of the matrix column entry. A run whose build is not recorded is
  not evidence.
- **PRE-3 — Two PIN holders.** The administrator PIN is chosen before the run,
  written down once, and held by the operator and the witness independently.
  It is never written into this repository, an issue, a screenshot or a photo.
- **PRE-4 — Recovery code off device.** The recovery code issued at first run is
  transcribed to paper or to a password manager **outside** the device before any
  kiosk case starts, and it is verified as legible. It is single use: case A-3
  consumes it and rotates a new one.
- **PRE-5 — ADB is break-glass and stays enabled.** `DEVELOPER_OPTIONS_AND_ADB`
  (`DISALLOW_DEBUGGING_FEATURES`) remains **off** for the whole run except inside
  case S-7, which turns it on and off again under supervision. ADB is the last
  recovery rung before a destructive reset; withdrawing it early converts a
  recoverable failure into a wipe.
- **PRE-6 — Charged and powered.** The device is above 60% or on mains power. A
  device that dies inside lock task with an unserved PIN penalty costs a reset.
- **PRE-7 — Network.** Wi-Fi is joined and working before provisioning, and the
  credentials are known to the witness. Several cases restrict network
  configuration; rejoining a network afterwards may not be possible from the
  device.
- **PRE-8 — The audit log is a ring buffer.** `AuditLog` keeps the **last 50
  entries** and there is no export. Photograph the log at each checkpoint the
  cases name, not at the end of the day.
- **PRE-9 — Console entry points exist in the build under test.** Some cases
  depend on console rows that are tracked as open integration work rather than
  shipped. Each such case names its dependency and is recorded as *blocked*, not
  *failed*, if the row is absent. See
  [Cases gated on unshipped features](#cases-gated-on-unshipped-features).

## Recording evidence

Every case records the same five things. A case without them is not complete,
whatever the device did.

1. **Case ID and verdict** — `pass`, `fail`, `blocked` (a dependency is not in the
   build), or `not applicable` (the release genuinely does not implement the
   capability, which is a documented outcome and not a defect).
2. **Device record** — model, Android release, firmware build from PRE-2, Device
   Guard `versionName`/`versionCode`.
3. **The observation** — a photograph or screenshot of the screen the expected
   result names, timestamped. For a suppression claim ("Overview does not open"),
   photograph the screen that *stayed*, and record the gesture attempted.
4. **The machine record** — a photograph of the console's **Administration audit
   log** (Records and monitoring → Administration audit log) covering the case,
   and, where the case names one, the verbatim machine reason string the console
   displayed (`kiosk-lock-task-home-unavailable`, `target:not-launchable`, and so
   on). Copy the string exactly; the console shows an unrecognised code verbatim
   rather than mapping it onto a friendlier one, and that literal is the value.
5. **Where it is filed** — the run is attached to the hardware-validation issue
   for that device family, and the resulting cell state is written into
   [`device-matrix.md`](device-matrix.md) with a link to that issue comment.

Never photograph or transcribe: an administrator PIN, a recovery code, or the
path, query or fragment of a single-site kiosk URL. The audit log already omits
the last of these by design — a single-site configure event records the origin
only — and a photograph of the address bar must not reintroduce what the log
deliberately dropped.

**Fail actions** are mandatory, not advisory. When a case fails, stop the group,
perform the named fail action, and record the state you found. Continuing past a
failed kiosk case is how a test device becomes a wipe.

## Case format

Each case states: what it applies to, the steps, the exact expected result, the
fail action, and the evidence beyond the standard five.

---

## Group P — Provisioning and baseline

### P-1 Device Owner provisioning

**Applies to:** every device.

**Steps**

1. Factory reset the device. Do not add an account and do not complete any
   vendor sign-in.
2. Join Wi-Fi (PRE-7).
3. `adb install -t app-debug.apk` (or the release APK under test).
4. `adb shell dpm set-device-owner com.example.lockdowndpc/.admin.LockdownAdminReceiver`

**Expected:** the command prints success and names Device Guard as the active
device owner. Opening the app shows the console rather than a "not provisioned"
state.

**Fail action:** if the command reports that an account exists or that
provisioning is not allowed, factory reset again and repeat once. A second
failure is a matrix-level result: record it as a **failed** cell for the
provisioning capability on that firmware family and stop — no later case is
meaningful without Device Owner.

**Evidence:** the console's provisioning state, and the exact refusal text if it
failed.

### P-2 Administrator PIN and recovery code

**Applies to:** every device.

**Steps**

1. Set an administrator PIN of 6–12 digits (PRE-3).
2. Record the recovery code the console issues, off the device (PRE-4).
3. Lock the console, reopen it, and authenticate with the PIN.

**Expected:** the PIN is accepted, the console opens, and the recovery code is
displayed exactly once.

**Fail action:** if the recovery code cannot be read or is not displayed, do not
proceed to any kiosk case. Rotate the recovery code from Access security and
capture the new one before continuing.

### P-3 A kiosk-off device does not report a lock-task failure

**Applies to:** every device. **Run this before any kiosk case.**

This is the first check named in
[`kiosk-mode.md`](kiosk-mode.md#what-is-not-proven-without-a-device): if some
build reports the device owner as implicitly lock-task-permitted after
`setLockTaskPackages(admin, {})`, then `disableKiosk` records
`kiosk-lock-task-release-unverified` on **every** policy pass of a kiosk-off
device, and ordinary managed filtering reports as failed on a device that is
working correctly.

**Steps**

1. With kiosk never enabled, configure a policy mode and a small app list.
2. Activate protection.
3. Read the protection status and the audit log.

**Expected:** protection reports **active**, not failed, and no entry contains
`kiosk-lock-task-release-unverified`.

**Fail action:** record a **failed** cell for "lock task release" on this
firmware family and raise a defect referencing `KioskController.disableKiosk`.
Continue the run — the rest of managed filtering is still worth measuring — but
mark every later kiosk verdict as taken against a device that already reports a
spurious error.

---

## Group F — Managed app filtering

Kiosk stays `OFF` for this whole group.

### F-1 Blocklist blocks a selected application

**Steps**

1. Protection settings → Blocking method → "block the selected apps".
2. Select one installed third-party application. Save.
3. Activate protection.
4. From the launcher, attempt to open the blocked application.

**Expected:** the application is not launchable, and the console reports
protection **active** (verified), not "applying" and not failed.

**Fail action:** capture the console's failure reason verbatim and stop the
group. A filtering failure invalidates every kiosk result that depends on hiding.

### F-2 Allowlist hides everything not selected

**Steps**

1. Switch the blocking method to "allowed apps only".
2. Select exactly one third-party application. Save and apply.
3. Inspect the launcher.

**Expected:** third-party applications other than the selected one and Device
Guard are hidden. System applications remain, per the conservative model in
[`kiosk-mode.md`](kiosk-mode.md#package-and-system-app-policy) — a device with
every system package hidden is a defect, not a stricter pass.

**Fail action:** if any package in `ESSENTIAL_SYSTEM` was hidden, this is a P1.
Pause protection immediately, confirm the package returns, and stop the run.

### F-3 Switching methods preserves both lists

**Steps**

1. With a saved allowlist selection, switch to blocklist, save, and inspect the
   list.
2. Switch back to allowlist and inspect the list.

**Expected:** each method shows its own saved selection; neither switch discards
the other's list.

**Fail action:** record the lost selection and its method. Non-blocking for the
kiosk group.

### F-4 Link interception

**Steps**

1. With protection active, open an `https://` link from a messaging or notes
   application.

**Expected:** the blocked-browser notice appears rather than a browser.

**Fail action:** record which application handled the link. This case is the one
that regresses after a kiosk exit; F-4 is repeated as K-11.

### F-5 Pause restores hidden packages

**Steps**

1. Pause protection from the console.
2. Inspect the launcher.
3. Resume protection.

**Expected:** hidden third-party packages reappear on pause and are hidden again
on resume, and the console reports the verified state after each transition.

**Fail action:** if a package does not return, record its name and whether a
second reconciliation pass (reboot) restores it.

---

## Group A — Administrator access

### A-1 PIN lockout ladder

**Steps**

1. From the locked console, enter a wrong PIN five times.
2. Record the lockout the console reports.
3. Wait it out, then fail once more (sixth), then again (seventh), then an eighth
   time, recording each penalty.

**Expected:** the penalties are 60 seconds after the fifth failure, 5 minutes
after the sixth, 30 minutes after the seventh, and 60 minutes for the eighth and
every failure beyond it. The console states the remaining time rather than
silently rejecting.

**Fail action:** if a penalty is shorter than the ladder or absent, record the
observed value; this is a security defect and blocks a customer rollout on this
firmware family.

**Note:** this case costs up to 96 minutes of waiting. Run it in parallel with
nothing else on the device, and do not shorten it by clearing app data — that is
the exact bypass the case exists to detect.

### A-2 A lockout survives a reboot

**Steps**

1. Drive the device into an unserved penalty (five failures).
2. Reboot the device.
3. Attempt to authenticate immediately.

**Expected:** the remaining penalty is still enforced. A reboot does not serve it.

**Fail action:** record the penalty state after reboot verbatim. A reboot that
clears the lockout is a security defect.

### A-3 Recovery code, single use and rotation

**Steps**

1. With the device locked out, enter the recovery code held by the witness.
2. Confirm the console opens.
3. Attempt to reuse the same recovery code.
4. Rotate a new recovery code from Access security, through its confirmation
   dialog, and record it off the device.

**Expected:** the first use succeeds, the second use is refused, and rotation
issues a new code exactly once. The audit log records the rotation without
recording either code.

**Fail action:** if the code is reusable, this is a security defect. Stop the run
and record it. If the code fails on first use, the device now has one fewer
recovery rung — proceed to a fresh PIN session and treat every later kiosk case
as running without a recovery code.

### A-4 Session expiry and save-time re-check

**Steps**

1. Authenticate, open the blocking-method dialog, and leave the device untouched
   for more than three minutes.
2. Attempt to save the dialog.

**Expected:** the save is refused and the console drops to the PIN screen. The
setting is **not** written.

**Fail action:** verify whether the setting was written despite the expiry. A
write that lands is the defect; a refusal that also loses an unrelated setting is
a lesser one. Record which.

---

## Group K — Kiosk

This is the group that can strand the device. The witness holds the PIN and the
recovery code for every case here, and the abort procedure is within reach.

### K-1 Configuring a kiosk profile changes nothing visible

**Steps**

1. Kiosk profile → Operating profile → single-app kiosk.
2. Choose a locked application (a third-party application that is not a file
   manager, not Device Guard and not a management transport — the picker should
   already exclude those).
3. Save.

**Expected:** the console reports the profile as configured; the device is **not**
locked. The launcher, Overview and the shade all still work. The audit log shows
`audit_kiosk_configured_app` naming the package.

**Fail action:** if the device locks on save, this is a P1 — configuration and
activation must be separate. Exit kiosk with the PIN and stop the group.

### K-2 Single-app activation and lock task holds

**Steps**

1. From the confirmation screen ("Lock this device?"), activate.
2. Once the target is in the foreground, attempt in turn: Back, Overview/Recents,
   the notification shade, the launcher gesture, and the power button menu.

**Expected:** the target holds the screen. Overview does not open, the shade does
not pull down, no launcher appears. On API 28+ the power menu does not open; on
API 26–27 make **no claim** about the power menu — the platform's legacy
behaviour applies and the record for that cell is *not applicable*. The audit log
shows `audit_kiosk_activated`.

**Fail action:** if any surface opens, photograph it, then use the corner gesture
(K-5) and the PIN to exit. Record which surface escaped and by which gesture;
that is the defect, and it is a matrix-level **failed** cell for lock task on this
firmware family.

### K-3 `LOCK_TASK_FEATURE_HOME` is accepted

**Applies to:** API 28+ only. **This is the highest-value case in the runbook**
and the one [`kiosk-mode.md`](kiosk-mode.md#what-is-not-proven-without-a-device)
names first for the recovery change.

The platform rejects `LOCK_TASK_FEATURE_HOME` when it sees no launcher it can
use. Device Guard registers `KioskHostActivity` as the persistent preferred HOME
activity in the same pass, immediately before applying the feature set. Whether
that ordering is sufficient on a given OEM build is exactly what is unknown.

**Steps**

1. With a single-app kiosk active (K-2), read the console result banner that the
   activation produced.
2. Press Home.

**Expected — accepted:** no error reason is reported, and Home resumes Device
Guard's **contained kiosk home**: a screen naming the locked application with a
single "Return to the app" action. It must not be a launcher, an app resolver
("Complete action using…"), or an immediate relaunch of the target.

**Expected — refused (also a valid, recorded outcome):** the console reports
"recorded, but the device did not confirm every step" with the machine reason
`kiosk-lock-task-home-unavailable`, and the minimal feature set is in force, so
Home does nothing. This is handled behaviour, not a defect — but it means local
recovery from a Back-trapping target is unavailable on this firmware, which the
matrix must say plainly.

**Fail action:** if Home reaches a launcher, an app resolver or any surface
outside Device Guard, stop immediately. That is an unauthenticated escape from
kiosk and is a P1. Photograph it, exit kiosk with the PIN, and mark the cell
**failed** with the defect reference. Do not ship single-app kiosk on this
firmware family until it is closed.

**Evidence:** the verbatim result banner text, the machine reason string if any,
and a photograph of whatever Home produced.

### K-4 The contained kiosk home returns to the target

**Applies to:** API 28+ with K-3 accepted.

**Steps**

1. From the contained kiosk home, tap "Return to the app".

**Expected:** the locked application resumes, still inside lock task.

**Fail action:** if the target does not resume, or resumes outside lock task
(Overview now opens), record which. The second is a P1.

### K-5 The administrator entry gesture from inside kiosk

**Applies to:** every device.

The gesture is seven taps within three seconds in the top corner **on the side
the text starts from** — top-left with the console in English, top-right in
Hebrew. It is observed in `dispatchTouchEvent` and the touch is forwarded
untouched, so the page or app underneath must still receive it.

**Steps**

1. From inside the active kiosk surface (the contained kiosk home, the single-site
   WebView, or the kiosk error state), tap the correct corner seven times within
   three seconds.
2. Repeat the run with the console display language set to Hebrew (Display →
   Display language) and use the mirrored corner.
3. Separately, tap the same corner **slowly** — seven taps spread over about ten
   seconds.
4. In a single-site kiosk, tap a control the portal itself places in that corner
   (a logo or a hamburger menu) once.

**Expected:** step 1 and step 2 open Device Guard on its **locked PIN screen** —
never an authenticated console. The audit log records `audit_kiosk_admin_entry`.
Step 3 does not open anything. Step 4 activates the portal's own control, because
the gesture observes rather than consumes touches.

**Fail action:** if the gesture does not complete, the device has no local
recovery route on this firmware and every later kiosk case must be run with the
abort procedure staged. If it opens an *authenticated* console, stop the run: that
is a P1 authentication bypass.

**Evidence:** for step 4, a photograph showing the portal control responded. This
is the regression the 0.5.1 remediation claims to have fixed and it has never
been observed on hardware.

### K-6 Suppression survives the HOME feature set

**Applies to:** API 28+ with K-3 accepted.

`LOCK_TASK_FEATURE_HOME` is documented as additive, so Overview, the shade, the
keyguard and the global actions menu should remain suppressed. Only a device
shows it.

**Steps**

1. With single-app kiosk active and HOME accepted, attempt Overview, the
   notification shade, the power menu, and locking the screen with the power
   button followed by a wake.

**Expected:** none of Overview, the shade or the power menu opens. Waking the
device returns to the kiosk surface without a keyguard.

**Fail action:** photograph the surface that opened. Any of these opening is a
**failed** cell for lock-task feature suppression and makes single-app kiosk
unsuitable for this firmware family until closed.

### K-7 Escape-surface hiding and restoration

**Steps**

1. Before activating kiosk, confirm that a documents picker or file manager is
   present (for example `com.android.documentsui`).
2. Activate any kiosk profile.
3. Attempt to reach a file manager or documents picker — from a share sheet inside
   the locked application, from any OEM shortcut, and from a download prompt.
4. Exit kiosk with the PIN and wait for the reconciliation pass to finish.
5. Inspect the launcher.

**Expected:** in step 3 no file manager, documents picker, downloads UI, HTML
viewer or setup wizard is reachable. In step 5 those packages are restored, and
the console reports the exit as verified.

**Fail action:** record the **exact package name** of any escape surface that was
reachable. This is the single most valuable defect this runbook can produce: the
`KIOSK_ESCAPE_SURFACES` catalogue is curated and cannot be complete for an OEM
build nobody has tested. A missing entry is a catalogue defect, not a device
defect, and it is fixed centrally.

### K-8 Single-site containment

**Steps**

1. Configure a single-site kiosk on the known test origin. Confirm the console
   shows both the opening address and the derived allowed origin before saving.
2. Activate.
3. From the loaded page, in turn: follow a link to the second origin; follow a
   link to a `http://` URL; follow an `intent://` link; attempt a file download;
   attempt to open a popup; long-press text and look for "Web search"; navigate to
   a subdomain of the allowed host; navigate to the allowed host on a different
   port.

**Expected:** the allowed origin loads. Every other navigation shows the transient
blocked notice and **leaves the current page intact**. No browser, launcher,
resolver or download UI appears. The subdomain and the non-default port are both
blocked — the containment unit is the origin, not the registrable domain.

**Fail action:** photograph anything that leaves the WebView. Record the URL class
that escaped (scheme, cross-origin, subdomain, port) — the machine reasons are
`blocked-scheme:<scheme>`, `insecure-scheme:http` and `external-origin`, and which
one is missing tells you where the defect is.

**Evidence:** photograph the blocked notice, not the address. Do not record the
path or query of the test URL.

### K-9 Single-site kiosk with an unreachable site

**Steps**

1. With single-site kiosk active, disconnect the device from the network (airplane
   mode from the settings the policy still allows, or by taking the access point
   down — do not use ADB unless the device offers no other route).
2. Observe the kiosk surface.
3. Attempt the retry action.
4. Attempt the administrator corner gesture (K-5) from this screen.
5. Restore the network and retry.

**Expected:** the host shows its full error state with a retry — never a browser,
a launcher, an "open in another app" prompt or a captive-portal handoff. The
corner gesture still works from the error state, because it is still the kiosk
host. Retry after restoring the network loads the site.

**Fail action:** if any external application is offered, photograph it; that is an
escape from containment. If the gesture does not work from the error state, the
device is only recoverable from the abort ladder — record this and treat it as
blocking for unattended deployments.

### K-10 Reboot restoration

**Steps**

1. With a single-app kiosk active, reboot the device.
2. Observe what appears after boot, without touching the screen.
3. Repeat with a single-site kiosk active.

**Expected:** the device returns to the configured kiosk target, not to a
launcher, and not to a setup wizard. The audit log records `audit_kiosk_restored`.
No PIN is required for restoration, and restoration cannot change the profile.

**Fail action:** if a launcher appears at any point — even briefly before the
kiosk takes over — record how long it was reachable and whether anything could be
launched in that window. A persistent launcher is a **failed** cell for HOME
preference persistence; a transient one is a recorded limitation with its
duration.

**Evidence:** record the interval between boot completion and the kiosk surface
appearing. On a classroom device this window is the exposure.

### K-11 Exiting kiosk restores managed filtering

**Steps**

1. Exit kiosk with the PIN and wait for the console to report the reconciliation
   pass as finished — do not tap through the waiting state.
2. Repeat case F-4 (open an `https://` link).
3. Confirm the escape surfaces from K-7 are back.

**Expected:** link interception works again. Removing the kiosk HOME preference
also removes this package's `http`/`https` link handlers, and the same
reconciliation pass is what re-registers them; the console must not report
success before that pass finishes.

**Fail action:** if links open in a browser after the exit, record whether a
second apply (or a reboot) repairs it. Either answer is useful: the first says the
ordering is wrong, the second says the pass did not complete.

### K-12 A kiosk configuration that goes stale

**Steps**

1. With a single-app kiosk active, make the target unusable from outside the
   console — uninstall or disable it over ADB as break-glass (PRE-5).
2. Reboot the device.

**Expected:** the host lands in the `FAULT` state and shows a safe error screen,
not a launcher. The audit log records `audit_kiosk_restore_failed` or
`audit_kiosk_fault` with a machine reason in the `target:` family
(`target:not-installed`, `target:not-enabled`, `target:not-launchable`). The
corner gesture still works from the error screen.

**Fail action:** if a launcher appears, that is an escape. If the device shows a
blank or unresponsive screen with no gesture, go to the abort procedure and record
that `FAULT` is unrecoverable locally on this firmware.

### K-13 Renderer failure in a single-site kiosk

**Steps**

1. With a single-site kiosk active, kill the WebView renderer process over ADB as
   break-glass.

**Expected:** `onRenderProcessGone` detaches and destroys the WebView and shows
the kiosk error state with a retry. The kiosk host process survives. It must not
crash-loop: the host is HOME while kiosk holds, and there is no launcher behind
it.

**Fail action:** if the device enters a crash loop or shows a system "keeps
stopping" dialog with no way forward, record the loop and go to the abort
procedure. This is a **failed** cell and blocks single-site kiosk on this
firmware.

### K-14 API 26–27 behaviour is what the console says it is

**Applies to:** Android 8.0 and 8.1 only.

**Steps**

1. Activate a single-app kiosk on a target that does not close itself.
2. Read the on-screen recovery note (`kiosk_recovery_single_app`).
3. Press Home.
4. Close the target from within itself, if it can be closed.

**Expected:** there is no lock-task feature selector on this release, so Home is
not a recovery route; the note says exactly that ("On Android 8 the screen is only
reachable once the locked app closes itself"). The gesture becomes reachable once
the target closes.

**Fail action:** if the note claims a capability the release does not have, that
is a copy defect and must be filed even though the device behaved correctly.
Record the case as *not applicable* for the HOME capability and *pass* or *fail*
for the copy.

### K-15 Pinning an application this policy currently hides

**Steps**

1. With allowlist filtering active and an application hidden by policy, open the
   kiosk app picker.
2. Select the hidden application as the single-app target and save.
3. Activate.

**Expected:** the picker lists the hidden application (resolved through
`queryIntentActivities` with `MATCH_UNINSTALLED_PACKAGES | MATCH_DISABLED_COMPONENTS`),
and activation unhides and launches it.

**Fail action:** if the picker omits it, or the configuration is refused with
`target:not-launchable`, record that. The failure is *safe* — nothing is pinned
incorrectly — but it means the picker and the validator disagree with this
firmware, and an administrator cannot pin an application they have blocked.

---

## Group I — Inventory and package reconciliation

### I-1 Installing an application while allowlist filtering is active

**Steps**

1. With allowlist mode active, install a third-party APK over ADB as break-glass.
2. Wait for the console to settle and inspect the launcher.

**Expected:** the newly installed package is hidden without administrator action
and appears in the managed inventory as blocked. A short interval between
installation completing and hiding is expected and documented
([`package-reconciliation.md`](package-reconciliation.md)); measure it.

**Fail action:** if the package stays visible, record whether a manual apply or a
reboot hides it.

**Evidence:** the measured interval, in seconds.

### I-2 Blocklist behaviour for a new package

**Steps**

1. Switch to blocklist mode, apply, then install a package that is **not** on the
   blocklist.

**Expected:** the package remains available. This is the definition of the mode,
not a defect.

### I-3 Reconciliation after the DPC process is killed

**Steps**

1. Force-stop or kill the Device Guard process over ADB.
2. Install a third-party package while it is down.
3. Wait for the system to rebind the `DeviceAdminService`.

**Expected:** the service performs a full reconciliation on restart and the
package is hidden, without the administrator opening the console.

**Fail action:** record how long rebinding took, and whether opening the console
was required. An OEM build with aggressive process management that never rebinds
is a **failed** cell for reconciliation and a serious deployment constraint.

### I-4 System-application inventory safety

**Applies to:** builds where the inventory screen is reachable (PRE-9).

**Steps**

1. Open the system-application inventory and locate: the **active keyboard**, the
   **active WebView provider**, System UI, and Device Guard itself.
2. Attempt to select each for blocking.
3. Find an unclassified OEM component, accept the risk, and save.
4. Update or replace that component (an OEM update, or reinstall a different
   version over ADB), then reopen the screen.

**Expected:** step 2 offers no checkbox for any of the four — they are protected
core, and the keyboard and WebView provider are protected from a **runtime**
reading rather than from a catalogue. Step 3 records package name, signer digest,
version, prior state and firmware build. Step 4 reports `DRIFTED` and the
component fails closed again.

**Fail action:** if any of the four in step 2 can be selected, stop. Hiding the
active keyboard or the WebView provider produces a device that cannot be repaired
from the console.

---

## Group S — System policy controls

The console screen for these controls is `SystemPolicyActivity`. At the time of
writing no row in `MainActivity` opens it; if the build under test still lacks the
row, record this whole group as **blocked** (PRE-9).

### S-1 The default set applies and verifies

**Steps**

1. Open system policy controls on a freshly provisioned pilot device.
2. Apply without changing anything.
3. Read every row.

**Expected:** each control reports one of **unsupported**, **not requested**,
**requested**, **applied** or **failed**. The pilot default set is applied, and
**developer options and ADB remain available** — the pilot profile deliberately
leaves them on. Protection reports active.

**Fail action:** if developer options are restricted by default on a pilot build,
stop the run: the break-glass rung in PRE-5 has been removed. Verify ADB still
connects before doing anything else.

### S-2 A control the release does not implement reports *unsupported*

**Applies to:** Android 8.0/8.1 (and 9 for the Android 10 keys).

**Steps**

1. On an Android 8.x device, read the rows for **private DNS**, **date and time**,
   **user and profile creation** and **installation from unknown sources**.
2. Request each and apply.

**Expected:** private DNS reports **unsupported** on 8.x and 9 (its restriction is
gated at API 29). Date and time reports **unsupported** on 8.x (gated at API 28).
User and profile creation applies its API 26 part and reports the user-switch part
per release. Unknown sources applies the per-user restriction and reports the
Android 10 global key as unsupported below API 29. **None of these faults
protection** — an older device is not a broken device.

**Fail action:** if an unsupported control faults protection, this is a defect in
the criticality model, not in the device. Record which control and which release.

**Evidence:** photograph the whole row list on this release. It is the per-release
support column of the matrix, and it is cheaper to capture once than to
reconstruct.

### S-3 The advisory Wi-Fi control

**Steps**

1. Request **Wi-Fi configuration** and apply.
2. Attempt to change the Wi-Fi network from Settings.

**Expected:** whatever the OEM Settings build does, protection does **not** fault.
If the restriction is refused, the row records it and the console shows it.

**Fail action:** if a refusal faults protection, record it as a criticality defect.
If the restriction *applies* and the device can no longer join a network, confirm
with the witness that the credentials from PRE-7 are still valid before
withdrawing it.

### S-4 A critical control that fails does fault protection

**Steps**

1. Request a critical control that this release supports.
2. Apply, then read the console.
3. If the platform accepts everything and nothing fails naturally, record this
   case as **not applicable on this device** rather than manufacturing a failure.

**Expected:** a requested critical control that the platform refuses produces a
console state of failed protection with the control named — never "active".

### S-5 Withdrawing a control that cannot be withdrawn

**Steps**

1. Turn off a previously applied control and apply.
2. If the platform refuses to withdraw it, read the console.

**Expected:** a failure to *withdraw* does not fault protection. The device is
stricter than asked rather than weaker, and faulting there would strand an
administrator trying to reopen a capability.

### S-6 A saved switch is not enforcement

**Steps**

1. Change a control switch and **do not** apply.
2. Read the row.

**Expected:** the row reads as saved and not yet verified. It must not display as
enforced. This is the central honesty rule of the policy engine and it is worth a
photograph.

### S-7 ADB withdrawal and restoration, supervised

**Run last in this group, with the witness present, and restore before moving on.**

**Steps**

1. Confirm the recovery code and both PIN copies are to hand.
2. Request **developer options and Android debugging** and apply.
3. Confirm `adb devices` no longer shows the device authorised.
4. From the console, withdraw the control and apply.
5. Confirm ADB access returns.

**Expected:** the restriction applies and is verified; ADB access is lost; the
console can withdraw it again and ADB returns.

**Fail action:** if ADB does not return after step 4, the device has lost its
break-glass rung. Do **not** run any further kiosk case on it. Record the state
and, if the console can no longer repair it, go to the abort procedure — noting
that the remaining rung is a data-destroying reset.

---

## Group M — Maintenance mode

**Gated:** these cases are executable only on a build where timed maintenance mode
is present. If it is absent, record the group as **blocked** and name the build.
The expected behaviour below is the contract stated in
[`production-roadmap.md`](production-roadmap.md#maintenance-mode); if the shipped
behaviour differs from it, the discrepancy is itself the finding.

### M-1 Opening a capability

**Steps**

1. With an active administrator PIN session, open maintenance mode for a single
   capability (application-store access, local APK installation, selected
   settings, or USB file transfer).
2. Confirm the opened capability works and that **nothing else** was opened.

**Expected:** exactly the chosen capability is available. The audit log records
the administrator action, the opened capability, the start and the expiry — and no
PIN or recovery secret.

**Fail action:** record any capability that opened without being chosen. A general
pause of protection under the name "maintenance" is the defect this case exists to
catch.

### M-2 Expiry restores and verifies

**Steps**

1. Open maintenance mode with a short expiry.
2. Wait past the expiry without touching the device.
3. Read the console and retest the capability.

**Expected:** the capability closes on its own, the previous policy is restored
**and verified**, and the audit log records the expiry and the final
reconciliation result. The console does not report protection as active before the
verification pass finishes.

**Fail action:** if the capability stays open past expiry, record by how long, and
whether opening the console closes it. An indefinitely open maintenance window is
a serious defect.

### M-3 Reboot closes maintenance mode

**Steps**

1. Open maintenance mode, then reboot before it expires.
2. After boot, retest the capability.

**Expected:** maintenance mode is closed and the full policy is in force.

### M-4 ADB maintenance carries its own warning

**Steps**

1. Attempt to open ADB/debugging as a maintenance capability.

**Expected:** an explicit additional warning, distinct from the other
capabilities, and a bounded expiry. It is not enabled implicitly by any other
choice, including a connected management transport.

**Fail action:** if ADB can be opened indefinitely or without the distinct
warning, record it. Combine with S-7 before deciding whether the device is safe to
leave in a classroom.

---

## Group N — Management identity

**Partly gated.** The read-only **Management connectivity** view exists in the
console (Kiosk profile → Management connectivity), so N-1 is executable today.
Writing pins is not exposed in the console — `AllowedAppsStore.setManagementCertificatePins`
is a backend API — so N-2 and N-3 require a build that calls it, and are recorded
as **blocked** otherwise.

The shipped default is `com.tailscale.ipn` with **no** pinned certificate, which
authenticates a package *name* and nothing else. That is a real gap, documented as
such in [`kiosk-mode.md`](kiosk-mode.md#proof-gap-unpinned-tailscale).

### N-1 An unpinned management package is reported honestly

**Steps**

1. Open Kiosk profile → Management connectivity.

**Expected:** the shipped record reads *no certificate pinned — trusted by name
only*, or *not installed on this device*. It must not read as authenticated.

### N-2 A matching pin grants trust

**Steps**

1. On a build that writes pins, configure the installed transport's real signing
   certificate SHA-256 digest.
2. Apply and read the view.

**Expected:** the record reads *signing certificate pinned*, the package keeps
uninstall protection and its policy exemption, and protection reports verified.

### N-3 A mismatched pin fails closed

**Run with the witness present. This case deliberately removes remote access.**

**Steps**

1. On the same build, configure a digest that does not match the installed
   transport.
2. Apply.
3. Read the console and check whether the transport still works.

**Expected:** the verdict is `MISMATCH`, the package is **hidden** rather than
exempted, it loses uninstall protection, and the whole apply is reported as
unverified. Remote access via that transport is gone.

**Fail action:** the recovery is local: authenticate at the console and correct
the pin. Confirm that this works **before** relying on it — a device whose only
management path was that transport, with a mistyped digest and no local access, is
recoverable only through the abort ladder.

**Evidence:** record whether local correction restored the transport, and how long
it took.

---

## Group U — Signed self-update

The trust conditions are in [`secure-updates.md`](secure-updates.md). This group
closes roadmap gate 3: a real signed higher-version self-update on hardware, which
is what makes withdrawing ADB defensible.

### U-1 A higher version installs silently

**Steps**

1. Note the installed `versionCode`.
2. Publish a signed manifest for a higher `versionCode`, correctly signed by the
   metadata key and matching the installed package and signer.
3. Trigger an immediate check from the console.

**Expected:** the update downloads and installs without any user prompt and
without pausing or weakening protection. The device reports the new version
afterwards.

**Fail action:** capture the failure reason the console reports. If the install
prompts for confirmation, silent installation is unavailable on this firmware
family — a **failed** cell that blocks ADB withdrawal there.

### U-2 A tampered artifact is refused

**Steps**

1. Publish a manifest whose SHA-256 does not match the served APK.
2. Trigger a check.

**Expected:** installation does not start; the failure is reported; protection is
unchanged.

### U-3 A non-higher version is refused

**Steps**

1. Publish a manifest with a version code equal to, then lower than, the installed
   one.

**Expected:** both are refused. Silent downgrade is not available.

### U-4 Updating while kiosk is active

**Steps**

1. Activate a kiosk profile.
2. Perform a U-1 update.

**Expected:** `MY_PACKAGE_REPLACED` re-asserts the active kiosk — lock task, the
feature set and the HOME preference — and the audit log records
`audit_kiosk_restored`. The device does not fall back to a launcher at any point.

**Fail action:** if a launcher is reachable during or after the update, record the
window. This is the same exposure as K-10 and is measured the same way.

---

## Group P — Google Play compatibility

**Gated:** these cases need a build with Google Play compatibility mode in the
system policy console, an Android 13 or later device, and an installed
application that is known to require the Google Play Store package — a Play Core,
in-app update, licensing or integrity dependency. Record the application by
category rather than by name if naming it would identify a customer. The contract
under test is the one stated in
[`play-store-compatibility.md`](play-store-compatibility.md).

The letter O is skipped deliberately: it is unreadable next to a zero in a
handwritten record.

### P-1 Strict mode is the default

**Steps**

1. On a device that has never opened the Google Play compatibility section, apply
   protection and read the console.
2. Look for the Play Store on the launcher and try to open it.

**Expected:** the compatibility switch is off, the Store is hidden, and the
dependent application shows its own "Google Play is not available" style error.
This is the shipped default and the baseline the next case is measured against.

**Fail action:** if the switch is on without anyone turning it on, stop. An
inferred opt-in is the defect this group exists to catch.

### P-2 Opting in makes the application work and keeps installation blocked

**Steps**

1. With an active administrator PIN session, turn Google Play compatibility on,
   read the confirmation dialog in full, and confirm it.
2. Apply and verify. Record the status line under the switch.
3. Start the dependent application.
4. From the Play Store, try to install any application.
5. From a file manager or a download, try to install a local APK.
6. Read the two installation rows in the console.

**Expected:** the application starts. Every installation attempt in steps 4 and 5
is refused by Android. **All package installation, including stores** and
**Installation from unknown sources** both read *Verified in force* and their
switches are shown as kept on by the compatibility mode. Protection is reported
as active and verified.

**Evidence:** photograph the console status line and the refusal Android shows on
the install attempt. Record which Android version and OEM build the refusal came
from — the wording is vendor-specific and the refusal itself is the finding.

**Fail action:** if any installation succeeds, this is a **critical** failure.
Record it, turn compatibility back off, and do not deploy the build.

### P-3 A device that refuses the installation lock hides the Store again

**Steps**

1. Only if the firmware under test refuses `DISALLOW_INSTALL_APPS` — which P-2
   would already have shown as a failed control. Otherwise record this case as
   **not applicable on this firmware** and say why.
2. With compatibility on, apply and verify.

**Expected:** protection is reported as **not verified**, the console names the
control that failed, and the Play Store is hidden rather than left available.
Device Guard never reports active protection over an unverified installation lock.

### P-4 The boundary the console states is the boundary the device has

**Steps**

1. With compatibility on and verified, on an ordinary launcher, look for the
   Play Store icon and try to open it.
2. Configure a single-app kiosk with the dependent application as the target and
   enter kiosk.
3. From inside kiosk, try every route to the Store you can find: the launcher, a
   share sheet, an in-app link, the Overview key.

**Expected:** on the ordinary launcher the Store may be visible and openable —
that is what the console says, and it is not a failure. Installation from it is
refused. Inside kiosk the Store is not reachable by any route, and the dependent
application still starts and works.

**Fail action:** if the Store is reachable from inside kiosk, record the exact
route. That is a containment failure and belongs with the Group K findings.

### P-5 Maintenance, expiry and reboot leave the lock in place

**Steps**

1. With compatibility on and verified, open a maintenance window with
   application-store access.
2. Install something from the Store — this is expected to work inside the window.
3. Let the window expire, or cancel it.
4. Retry the installation. Reboot and retry once more.

**Expected:** installation works only inside the window. After the window closes,
and again after the reboot, installation is refused, the Play Store is still
available to the dependent application, and the console reports protection as
active and verified. The audit log records the open, the close reason and the
verified restore.

**Fail action:** if installation stays possible after the window closes, this is
a **critical** fail-open. Record how long it persisted and whether opening the
console corrected it.

### P-6 Turning it off restores strict mode

**Steps**

1. Turn Google Play compatibility off, confirm, and apply.
2. Look for the Store and start the dependent application.
3. Read the two installation rows.

**Expected:** the Store is hidden, the dependent application shows its own error
again, and the installation controls return to whatever the administrator had
saved — which on a default device means the store lock is off again.

---

## Cases gated on unshipped features

Record these as **blocked** rather than failed when the dependency is absent from
the build under test, and name the version tested.

| Group | Depends on |
| --- | --- |
| I-4 | The system-application inventory screen being reachable from the console. |
| Group S | A row in `MainActivity` that opens `SystemPolicyActivity` behind `requireSession()` — tracked as an open integration requirement in [`production-roadmap.md`](production-roadmap.md#open-integration-requirements). |
| Group M | Timed maintenance mode. |
| N-2, N-3 | A build that writes management certificate pins. N-1 needs nothing beyond the shipped read-only view. |
| Group P | Google Play compatibility mode in the system policy console, an Android 13 or later device, and an installed application that requires the Google Play Store package. |

A blocked group is not a pass. The matrix records it as *not tested*.

## Abort and recover

Use this ladder in order. Every rung costs more than the one above it, and the
last one destroys data. Record which rung was needed — that number is a product
finding, not just an incident note.

1. **The corner gesture and the PIN.** Seven taps within three seconds in the top
   corner on the side the text starts from, then the administrator PIN, then exit
   kiosk from the console. This is the designed route.
2. **The witness's PIN copy.** If the operator's PIN is wrong or the operator is
   locked out under the A-1 ladder, wait out the penalty rather than adding
   failures — the ladder reaches 60 minutes and stays there.
3. **The recovery code.** Single use. Using it here consumes it; rotate a new one
   from Access security as soon as the console is open, and record the new one off
   the device.
4. **ADB break-glass.** Only while `DISALLOW_DEBUGGING_FEATURES` is off (PRE-5).
   With the device connected, attempt
   `adb shell dpm remove-active-admin com.example.lockdowndpc/.admin.LockdownAdminReceiver`.
   A Device Owner may refuse removal, and `DISALLOW_FACTORY_RESET` and the other
   applied restrictions can also block shell routes; if the command is refused,
   record the exact refusal and go to rung 5. Do not spend more than a few minutes
   here.
5. **Factory reset or a recovery-mode reflash.** This is the documented end of the
   ladder and it is the reason for the two-person rule.
   **A factory reset or a recovery-mode reflash destroys all local data on the
   device, including the audit log and any evidence not already captured off the
   device.** Photograph the audit log before resetting if the device can still
   show it. After the reset the device is at PRE-1 and the run restarts from P-1.

If the device is **physically unreachable** — deployed, locked, and neither the
gesture nor the network is available — there is no remote route. Device Guard has
no remote unlock and adds none: the kiosk exit paths all require a local
authenticated `AdminSession`. Retrieve the device and restart at rung 1.

## After the run

1. Write each case verdict into [`device-matrix.md`](device-matrix.md), as a cell
   state with a link to the evidence.
2. Open one defect per failure, with the machine reason string in the title where
   there is one, and reference it from the cell.
3. Record any escape surface found in K-7 as a catalogue change request against
   `LockdownPackages.KIOSK_ESCAPE_SURFACES`, with the package name.
4. State plainly, in the run summary, which cases were **blocked** and why. A
   matrix that silently omits a blocked group reads as coverage that does not
   exist.
