# Night and work hours

Night and work hours suspend every application outside an always-available
core while a window is in force: 23:00 to 06:00 every night and 09:00 to 17:00
Sunday to Thursday. The administrator turns both windows on or off with one
switch in System policy. This document is the durable reference for
[Issue #86](https://github.com/ShalomMaman/android-lockdown-dpc/issues/86): what
the schedule enforces, how it fails closed, and the limits it accepts.

## What a window does

- Suspension is the only mechanism. A window never hides or unhides anything;
  hiding stays with the base package policy.
- Every policy pass recomputes the windows from the clock. No stored "in
  window" flag is trusted, so a reboot, a clock change or a time zone change
  converges on the next pass.
- The always-available core is never suspended: Maakeh itself, the
  trusted management and VPN applications, essential system packages, the
  default dialer, SMS and clock applications (system packages only), the home
  launcher, the active input method, active device administrators, the WebView
  provider, the kiosk target, and, while they apply, the maintenance stores and
  the Play Store kept for compatibility.
- Pausing protection releases what the schedule suspended and cancels its
  alarms.

## One rule for every other step

Other steps of the pass also suspend packages: the social containment fallback,
the Chrome exemption, a browser-backed WebView provider. While a window is
active, every package outside the core and the allowlist is a *window target*,
and **no step lifts a suspension on a window target**. The rule is decided from
the schedule and the clock, not from any record, so it holds even when a record
is unreadable.

- An approved social application that an earlier containment fallback
  suspended stays suspended for the rest of the window; it is released once the
  window ends.
- Chrome shown by its exemption inside a window is suspended first and unhidden
  only once Android confirms the suspension. It is never visible and launchable
  inside a window. If Android does not confirm the suspension, Chrome stays
  hidden and the pass is not verified.

Inside a window the schedule suspends every target itself on every pass, even
one Android already reports suspended: Android reports the combined suspension
state, and a suspension another app or step placed may be lifted at any time.
The call is idempotent. The schedule records every target and releases only
what it recorded. A recorded package that another step needs suspended after
the window (an unapproved social application, Chrome while its exemption is not
shown) is handed over to that step instead of released.

A corrupt home filter configuration stops the rest of the pass, but not the
schedule step: the windows are still enforced, with the live always-on VPN and
the default VPN kept available because the configured one is unknown, and the
pass still reports the corrupt configuration.

## Failing closed

| Stored state | What is enforced |
| --- | --- |
| Never written | Nothing; the device behaves as before the feature. |
| Explicit "off" record | Nothing. |
| A readable schedule | That schedule. |
| Damaged, wrong-typed, emptied on load, an unknown format, or a format marker without a stated content | Both default windows, no allowlist, and the pass is reported as not verified. |

Both preference files carry a format marker. Android loads an unparseable
preference file as an empty map, so a file that exists, or once existed, without
its marker is damaged, never "off" and never "nothing owned".

An unreadable ownership record is *unknown*, never "nothing owned", and the
pass that finds it is reported as not verified. A save that fails marks the
record unknown too, rather than leaving the previous value: the schedule
suspends even when the save fails, so the previous value could under-report.
No window target is released on account of an unknown record, and the record
is kept until it is rewritten from Android's own read-back:

- inside a window, the rewrite records every window target;
- outside a window no package is a target, so every launchable package Android
  reports suspended that no other step holds is released, which is what a
  readable record would have led to, and the record keeps whatever Android did
  not confirm released;
- a pause releases every launchable suspended package, as it releases every
  other suspension.

Without an application inventory nothing is rewritten. A recorded package that
is no longer in the launcher cannot be recovered by a rewrite: it stays
suspended, which errs on the restrictive side.

## Triggers and retries

- **Boundary alarm.** Each boundary arms a primary alarm (exact when Device
  Guard may schedule exact alarms, otherwise a short inexact window) and an
  inexact fallback that can fire in Doze. The fallback is always armed, because
  Android cancels exact alarms without any broadcast when the permission is
  revoked.
- **Screen on and unlock**, while the process runs.
- **A periodic sweep** every fifteen minutes, JobScheduler's minimum.
- **A retry after a failed pass.** The instant a missed boundary is measured
  from advances only after a pass that was verified end to end. A pass that was
  not verified schedules a one-off retry with backoff (1, 2, 4 and 8 minutes,
  then every 15). The screen-on check, the sweep and the retry run a pass while
  the last one did not verify, even inside the same window with no boundary in
  between, and all of them respect the same backoff.

## Accepted limits

**A window can start late.** Without exact alarm access, Android decides when
an inexact alarm fires. On an idle device or one saving battery that can be
minutes, or up to about an hour, after the boundary, and OEM battery managers
may delay it further. Android 14 and newer deny exact alarm access to a fresh
installation by default, and `USE_EXACT_ALARM` is reserved for alarm clock and
calendar applications, so Maakeh does not declare it. The console states
the exact-alarm state as it is, promises no bound, and points the administrator
to **Alarms and reminders** in Android Settings. The screen-on check, the sweep
and the retry narrow the gap but cannot close it: each runs the pass in the
background, so an application may open for a moment before the pass finishes.
This is a platform limit, accepted for this feature.

**Android 9 and newer rely on the date and time restriction.** The windows
come from the wall clock, and from Android 9 the only thing that keeps the user
from setting the clock is the date and time system policy control
(`DISALLOW_CONFIG_DATE_TIME`). It is enforced by default; turning it off is an
administrator action in System policy, and with it off the user could move the
clock and end a window early. The schedule does not check or override that
choice: it relies on the administrator keeping the control on.

**Only applications with a launcher entry are targets.** The schedule's
inventory is the launcher. An application without a launcher entry, opened
only through a deep link or another application, is not suspended by a window.
The main package policy already hides every application that is not approved,
so such an application is reachable only when an administrator approved it;
deep-link-only applications are out of scope for night and work hours.

**Android 8.0 and 8.1 need automatic date and time.** Every window comes from
the wall clock, and the date and time restriction that keeps the user from
setting the clock exists only from Android 9. On Android 8.0 and 8.1 the
schedule can be turned on only once Android confirms that automatic date and
time is required (`DevicePolicyManager.setAutoTimeRequired`). Until then the
switch states why it cannot be turned on, and a pass with an enforcing schedule
on those releases requires it again and is not verified while it is not
confirmed. Turning the schedule off leaves automatic date and time required.

- **An ended window can stay enforced while the filter is unverified.** If the home filter
  configuration is corrupt or VPN verification fails, suspensions from the ended window
  stay in place until a pass verifies the network. The policy errs on the strict side.
- **Double write failure, then restart.** If both the ownership record and its "unknown"
  mark fail to save, and the process restarts outside a window, an older valid record can
  load. A package the schedule suspended can then stay suspended past the window until the
  next window records every target again. This errs on the strict side; it never opens an app.
- **Android 8.0 and 8.1 share one suspension state.** On these versions a window target that
  another component had already suspended is recorded and released at the end of the window,
  even if that component still wants it suspended. Every Maakeh step that keeps a package
  suspended outside windows is excluded from the release, so this only affects suspensions made
  by other apps (for example an OEM wellbeing tool).

## Validation still owed

The JVM tests cover the rules above against fake Android layers. Physical-device
evidence is still owed for: suspending a hidden Chrome before showing it, the
exact and inexact alarms under Doze on each firmware family, the retry job after
a reboot, and `setAutoTimeRequired` on an Android 8.0/8.1 device. Record results
in the [device matrix](device-matrix.md).
