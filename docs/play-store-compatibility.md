# Google Play Store compatibility mode

Some applications distributed through Google Play refuse to start while the
Google Play Store package (`com.android.vending`) is unavailable, even when
Google Play services and the active WebView provider are untouched. Play Core,
in-app update, licensing and integrity flows can all reach for the Store
package itself.

This document describes the explicit, administrator-controlled exception Device
Guard offers for that case, and — more importantly — the boundary it does not
cross. It is the durable reference for
[Issue #64](https://github.com/ShalomMaman/android-lockdown-dpc/issues/64).

## The evidence this is built on

On a Device Owner-provisioned Android 13 pilot, with protection `ACTIVE` and
verified, an affected Play-distributed application showed its own "Check that
Google Play is enabled" error. Opening an authenticated, bounded maintenance
window with application-store access made the application start. Closing the
window reproduced the failure.

That establishes a runtime dependency on the Store *package* being available. It
does not establish that hiding the Store is wrong, and it does not change the
security boundary below. No device, customer, account, network or
package-inventory identifier is recorded anywhere in this repository as a result
of that test.

## Strict mode is the default

Nothing changes for a device that does not opt in, including an existing pilot
upgraded into a build that contains this feature. Application stores stay
hidden, `com.android.vending` stays in the built-in blocked catalogue, and the
installation controls keep the defaults they have always had.

The opt-in is stored on its own, in its own preference file, and is written only
where an authenticated administrator has confirmed a dialog that states the
consequences. **No allowlist entry, installed package or observed failure ever
turns it on.** An application being allowed does not imply that its store is.

## What the mode does

While Google Play compatibility is on and verified:

1. `com.android.vending` — and only that package — is exempted from the hidden
   store rule. Samsung Galaxy Store, Mi Picks, AppGallery, the Amazon Appstore
   and every other entry in the catalogue stay hidden.
2. The installation lock is raised and held. `DISALLOW_INSTALL_APPS`
   (**All package installation, including stores**) and both unknown-source
   restrictions (`DISALLOW_INSTALL_UNKNOWN_SOURCES` and, from Android 10, its
   global counterpart) are requested regardless of what the administrator chose
   for them, and are read back from the device like every other control. Their
   switches are shown on the console as locked on, with the reason.
3. Google Play services and the active WebView provider are unaffected. They are
   protected by separate rules — `ESSENTIAL_SYSTEM` and the WebView provider
   resolution — and this mode neither widens nor narrows them.

## What the mode costs

**Device Guard cannot install its own signed updates while the installation lock
is on.** Android applies `DISALLOW_INSTALL_APPS` to the device owner as well,
which is the same reason that control is opt-in in the first place
([`secure-updates.md`](secure-updates.md)). An operator who turns this mode on
must plan updates another way — an authenticated maintenance window, or a
physical service visit. The console says so before the choice is confirmed.

## The security boundary

Android's Device Owner APIs can hide or suspend a whole package. They cannot
portably hide one launcher entry while leaving the package usable by other
applications. Device Guard therefore makes two different claims, and they are
not the same claim:

| Deployment | What is true |
| --- | --- |
| Managed app filtering on an ordinary launcher | The Store package is **available**, so its icon may remain visible and it may be openable. Installation is blocked and verified. Device Guard does **not** claim the Store is hidden. |
| Single-app or single-site kiosk | The Store is not part of the surface a user can reach. The lock-task allowlist holds the DPC and, at most, the pinned target; the Store can never be either. The package stays available to dependent applications. |

The kiosk statement rests on rules that exist independently of this feature:
`KioskAppCatalog.isProtectedFromKiosk` refuses every package in the blocked
catalogue as a kiosk target, and `KioskController.applyLockTaskPackages` builds
the allowlist from the DPC and the validated target alone. Keeping
`com.android.vending` in `ALWAYS_BLOCKED` — and applying the exception at the
policy pass instead of carving it out of the catalogue — is what keeps both
rules true.

## Fail-closed behaviour

The Store is made available on the strength of a read-back, never of a stored
switch:

- Every policy pass sends the installation controls and reads them back. Only
  when both report `APPLIED` does that pass leave the Store unhidden.
- If either control is refused, silently ignored or unreadable, the pass records
  `play-compatibility-install-lock-unverified`, keeps the Store hidden, and
  reports protection as **not verified**. Both controls are critical, so the
  device also faults on the control itself. Protection is never reported as
  `ACTIVE` over an unverified installation lock.
- A fresh opt-in that has not been applied yet has no verified outcome, which is
  the absence of evidence rather than evidence of a lock. The console shows it
  as such.
- A maintenance window excuses the control it relaxed from the verification
  requirement — there is nothing to read back once an authorised window has
  turned it off — but the excusal is per control and never widens. Only the
  store installation control can grant store availability that way; a refused
  store lock inside a local-APK window is still a failure, still hides the Store
  and still faults.

## Maintenance windows, reboot, pause and reconciliation

The compatibility floor is part of *the base policy* — the policy this device is
configured for — rather than a fourth thing layered on top. That single
definition, `SystemPolicyStore.baseChoices`, is what every stage reads:

- **Reconciliation** (boot, package change, periodic sweep, console apply)
  applies the base policy, floor included.
- **A maintenance window** is an exception to the base policy. A window that
  opens **application-store access** relaxes the store installation lock for its
  bounded, authenticated, audited duration, and makes the stores visible itself.
  The console reports that state distinctly instead of showing a relaxed device
  as a locked one.
- **A window that opens only unknown sources** — the local APK install
  capability — carries no store authorisation, so it does not grant store
  availability. Authorising a technician to install a local APK is not
  authorising an application store to sit beside it, and the mode's contract is
  that the Store is available only while every installation control it pins on
  is genuinely enforced. The Store is **withheld for the duration of that
  window** and becomes available again when it closes. This is reported as its
  own state and is **not** a fault: nothing failed, the device is simply stricter
  than the compatibility mode would like, on the strength of an authorisation the
  administrator actually gave.

  The withholding is a **precondition, not an effect**. Before a single
  restriction is relaxed, the open path hides `com.android.vending` and reads it
  back; only then does the enforcer touch the restrictions. The precondition
  reads **no preference at all** — it fires on the shape of the window, for every
  window that relaxes an installation control without carrying application-store
  access, whatever the compatibility switch currently says. That is deliberate:
  the switch is intent, package visibility is device state, and the two disagree
  for as long as an administrator has changed the switch without applying. A
  precondition that consulted the switch could be skipped by turning
  compatibility off and opening a local-APK window before the next apply, leaving
  an already-visible Store beside cleared unknown-source restrictions. On a device
  that is already strict the Store is already hidden and the extra write is a
  verified no-op; a device without the Store installed is a safe no-op too. If
  the Store cannot be hidden, or cannot be proven hidden, **the window does not
  open** —
  `MaintenanceStatus.REFUSED` with reason `precondition-unverified`, no plan, no
  report, nothing relaxed, and the administrator's restore debt handled exactly
  as for any other refusal (an intent this call created is withdrawn; a debt owed
  by an already-open window is kept). The ordering matters because the exposure
  is the Store's own interface and network surface, which no installation
  restriction closes: hiding it afterwards, or on a later reconciliation pass,
  would leave a real interval in which a relaxed window and a reachable Store are
  both live.
- **The restore** at expiry, reboot, cancel or failed open puts the base policy
  back — the floor with it. Restoring the administrator's raw switches would end
  a window with the Store available and no installation lock, which is exactly
  the fail-open this design removes.
- **After a window opens or closes**, on a device that has opted in, an ordinary
  reconciliation pass follows. On a close it matters because the restore hides
  every managed store — the correct fail-closed default, and what a strict device
  wants — without having verified the installation lock at that moment; the
  following pass re-asserts the exception on the strength of its own read-back,
  so the sequence is always *hidden first, available only once the lock is
  proven*. On an open, and after a refused precondition, it only brings package
  visibility back into line with the base policy; it is **not** what enforces the
  withheld state, which the synchronous precondition above has already done. A
  device that never opted in keeps exactly the maintenance behaviour it has
  today.
- **Pause** withdraws every control and unhides every managed package, this one
  included. A paused device is not a protected device and does not pretend to be.

## Operator workflow

1. Open the console with the administrator PIN and go to **System policy
   controls**.
2. Read the **Google Play compatibility** section. It states the boundary in
   full and stays on screen; it is not only inside the confirmation dialog.
3. Turn the switch on and confirm the consequences.
4. Press **Apply and verify now**. The status line under the switch reports what
   the device confirmed.
5. Verify that the affected application starts, and that installation is
   refused — from the Store and from a local APK.

To go back to strict mode, turn the switch off, confirm, and apply again. The
Store is hidden at that pass and the installation controls return to the
administrator's own saved choices.

## What is not proven

The rules above are proven as JVM tests
(`app/src/test/java/com/example/lockdowndpc/policy/PlayStoreCompatibilityTest.java`).
They prove nothing about what a given OEM build does with package hiding or with
`DISALLOW_INSTALL_APPS`. Group P of
[`hardware-validation.md`](hardware-validation.md#group-p--google-play-compatibility)
is the procedure that closes that gap, and it requires a Play Core-dependent
application on Android 13 or later.

## Where the code is

| Concern | File |
| --- | --- |
| The rule, as pure decisions | `app/src/main/java/com/example/lockdowndpc/policy/PlayStoreCompatibility.java` |
| The administrator's stored decision | `app/src/main/java/com/example/lockdowndpc/policy/PlayStoreCompatibilityStore.java` |
| The base policy every stage reads | `SystemPolicyStore.baseChoices` |
| The package exception and its fail-closed gate | `LockdownPolicyController.apply` |
| The console section | `app/src/main/java/com/example/lockdowndpc/ui/SystemPolicyActivity.kt` |
