# Supported device matrix

This document is an **evidence ledger**, not a compatibility claim. A cell says
what was observed on a named device at a named firmware build, or it says that
nothing was observed. There is no third option: an untested cell is never filled
in from a datasheet, from a sibling model, or from the fact that the code is
written to handle the case.

The procedure that fills the cells is [`hardware-validation.md`](hardware-validation.md).
The behaviour being validated is described in [`kiosk-mode.md`](kiosk-mode.md)
and [`production-roadmap.md`](production-roadmap.md).

**Current state: every cell is "not tested."** Device Guard has never run on a
Device Owner-provisioned handset. Nothing below has been observed.

## Cell states

| State | Notation | Meaning |
| --- | --- | --- |
| Not tested | `—` | No run exists. Also the state for a capability whose console entry point is absent from the build tested — the runbook calls that *blocked*, and blocked collapses to *not tested* here, because no evidence was produced either way. |
| Passed with evidence | `pass` + link | A run of the named cases completed on this firmware build with the expected result, and the evidence is linked. |
| Failed with defect reference | `fail` + issue | A run produced a result other than expected. The linked issue holds the machine reason string and the photograph. A cell stays `fail` until a *new* run on a *new* build passes; closing the defect in code does not clear it. |
| Not supported | `n/s` | The release or firmware genuinely does not implement the capability, Device Guard reports that honestly, and nothing faults. This is a documented outcome, not a defect — but it constrains what may be sold into that fleet. |

A summary cell carries the **weakest** state among the capability rows behind it.
One `fail` makes the summary `fail`; one `—` among otherwise-passing rows makes
the summary `—`. Coverage is not an average.

## Coverage summary

Rows are Android releases from the application's `minSdk` (26) to its current
`targetSdk` (36). Columns are firmware families, not vendors: two Samsung models
on different One UI majors are two device records under one column, and a column
exists only when a family is actually in scope for a deployment.

| Android release (API) | AOSP / Pixel | Samsung One UI | Xiaomi HyperOS / MIUI | Motorola / Lenovo | Transsion (Tecno / Infinix / itel) | Education & rugged (MTK / Rockchip AOSP-derived) | GMS-less (EMUI / HarmonyOS) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 8.0 (26) | — | — | — | — | — | — | — |
| 8.1 (27) | — | — | — | — | — | — | — |
| 9 (28) | — | — | — | — | — | — | — |
| 10 (29) | — | — | — | — | — | — | — |
| 11 (30) | — | — | — | — | — | — | — |
| 12 / 12L (31–32) | — | — | — | — | — | — | — |
| 13 (33) | — | — | — | — | — | — | — |
| 14 (34) | — | — | — | — | — | — | — |
| 15 (35) | — | — | — | — | — | — | — |
| 16 (36) | — | — | — | — | — | — | — |

Every cell is `—`. No device record exists yet.

## Capability register

These are the capabilities the matrix tracks. The **OEM-variable** column is the
honest part: it marks the capabilities where the Android contract is known but
what a given firmware does with it is not, so a pass on one column carries no
information about another. The rest are expected to behave the same everywhere
and are still tested, because "expected" is not "observed".

| ID | Capability | OEM-variable | Runbook cases | Behaviour when the platform refuses |
| --- | --- | --- | --- | --- |
| C-1 | Device Owner provisioning via `dpm set-device-owner` | Yes | P-1 | Provisioning fails outright; no later capability is reachable. |
| C-2 | Lock task holds (Overview, shade, launcher, keyguard suppressed) | **Yes** | K-2, K-6 | Any surface that opens is an escape; there is no fallback. |
| C-3 | `LOCK_TASK_FEATURE_HOME` accepted alongside the kiosk HOME preference | **Yes** | K-3 | The minimal feature set is reapplied and `kiosk-lock-task-home-unavailable` is recorded. Safe and visible, but local recovery from a Back-trapping target is unavailable. |
| C-4 | HOME preference persistence across reboot; no vendor launcher wins the race | **Yes** | K-10, U-4 | A launcher becomes reachable. Measure the window; a persistent launcher is a `fail`. |
| C-5 | Administrator corner gesture over a live surface, both directions | Yes | K-5, K-9, K-12 | No local recovery route; the device depends on the abort ladder. |
| C-6 | Escape-surface catalogue completeness (`KIOSK_ESCAPE_SURFACES`) | **Yes** | K-7 | A vendor file manager, downloads UI or setup wizard absent from the catalogue stays reachable. This is a catalogue defect, fixed centrally, and it is the capability most likely to differ per firmware. |
| C-7 | Single-site navigation containment (origin, scheme, popup, download, TLS) | No | K-8 | A blocked navigation shows a notice; anything that leaves the WebView is an escape. |
| C-8 | Kiosk error and fault states stay contained | Yes | K-9, K-12, K-13 | A launcher, resolver or crash loop instead of the error state. |
| C-9 | Package hiding and restoration (`setApplicationHidden` round-trip) | Yes | F-1, F-2, F-5, K-7 | The apply reports failed rather than active. |
| C-10 | Package-install reconciliation and `DeviceAdminService` rebinding | **Yes** | I-1, I-3 | Aggressive OEM process management can delay or prevent rebinding, leaving a newly installed package visible. |
| C-11 | Link interception after a kiosk exit (persistent preferred activities) | Yes | F-4, K-11 | Links open in a browser; the reconciliation ordering is what re-registers them. |
| C-12 | System-policy control support per release (`UserManager` restrictions) | **Yes** | S-1, S-2 | An unsupported restriction reports `unsupported` and does not fault. A critical control the platform refuses faults protection. |
| C-13 | Wi-Fi configuration restriction (the single advisory control) | **Yes** | S-3 | Recorded and shown; never faults. A device that cannot rejoin a network is a deployment risk, not a policy error. |
| C-14 | ADB withdrawal and restoration from the console | Yes | S-7 | The break-glass rung is lost; only the console or a reset remains. |
| C-15 | Protected-core enforcement (active IME, WebView provider, System UI, the DPC) | Yes | I-4 | If any is selectable, the device can be made unrepairable from the console. |
| C-16 | Timed maintenance mode: open, expiry, reboot close | Yes | M-1 – M-4 | Gated on the feature being present in the build tested; see the runbook's gated cases. |
| C-17 | Management-package identity pinning and fail-closed mismatch | Yes | N-1 – N-3 | A mismatch hides the transport; recovery is local only. Writing pins has no console surface, so N-2 and N-3 need a build that calls the backend API. |
| C-18 | Silent Device Owner installation of a signed higher version | **Yes** | U-1 – U-4 | A prompt instead of a silent install means the self-update gate is unmet, and ADB cannot be withdrawn on that firmware. |

## What the release alone decides

These follow from the Android contract and the code, and they are the reason some
cells will legitimately read `n/s` rather than `fail`. They are **not** evidence,
and they do not substitute for a run.

| Release | Consequence |
| --- | --- |
| 8.0–8.1 (26–27) | No `setLockTaskFeatures`. The platform's legacy lock-task behaviour applies; HOME is not a recovery route (C-3 and C-4 are `n/s`), and no claim is made about the power menu. Single-app targets inherit the host's locked task via `startLockTask()`. |
| 9 (28) | `setLockTaskFeatures` available and verified via `getLockTaskFeatures`; `ActivityOptions.setLockTaskEnabled(true)` for single-app launch; signer digests from `SigningInfo`. `DISALLOW_CONFIG_PRIVATE_DNS` and the global unknown-sources key are still absent, so those controls report `unsupported`. |
| 10 (29) | The Android 10 global unknown-sources key and private DNS become available. |
| 13 (33) | `PackageManager` queries use the `…Flags.of` overloads; per-app locale storage moves to the platform. |
| 14 (34) | Policy application is asynchronous; the existing bounded-retry verification applies. Kiosk adds no new assumption. |

## Device records

A column is a family; a **device record** is what actually gets tested. Each
record is created before its first run and is identified by the firmware build,
because that is the unit that behaves.

| Field | Source |
| --- | --- |
| Record ID | `family-model-release`, for example `samsung-a13-13` |
| Model and marketing name | Settings → About phone |
| Android release and API level | Settings → About phone |
| Firmware build | Settings → About phone → Build number (runbook PRE-2), verbatim |
| Device Guard version | `versionName` / `versionCode` under test |
| Run date and operator/witness | The run summary |
| Evidence link | The hardware-validation issue comment holding the photographs and machine reason strings |

**No device records exist.** The first run creates the first one.

### Record template

Copy this table per record and fill only what a run produced.

| Capability | State | Evidence / defect |
| --- | --- | --- |
| C-1 … C-18 | `—` | |

## Minimum coverage before a customer rollout

These are gates, not targets. They restate roadmap acceptance criteria 4, 5 and 6
in matrix terms.

1. **Every model in the order is its own record.** Not a sibling, not the same
   chipset, not "the same OEM". C-6 and C-10 in particular differ between models
   from one vendor.
2. **Both ends of the fleet's release range are tested** on that model — the
   lowest Android release any unit ships with, and the highest it will be updated
   to. If units will receive an OS upgrade during the contract, the target release
   is tested before the upgrade is allowed, not after.
3. **Every OEM-variable capability (C-2, C-3, C-4, C-6, C-10, C-12, C-13, C-18)
   is `pass` or `n/s`** on each record. `n/s` is acceptable only where the
   [release table](#what-the-release-alone-decides) predicts it and the console
   states the limitation to the administrator; an `n/s` that surprises the
   operator is a copy defect (runbook K-14).
4. **No `fail` cell is open.** A defect closed in code does not clear a cell; a
   new run on a new build does.
5. **The kiosk group is complete on any device that will run kiosk.** K-2, K-3,
   K-5, K-7, K-9, K-10, K-11 and K-12 all recorded. A kiosk device whose recovery
   route (C-3 or C-5) is untested must not be deployed anywhere the device cannot
   be physically retrieved the same day.
6. **The self-update gate (C-18) is `pass` before ADB is withdrawn** on that
   family. This is roadmap gate 3, and it is per firmware family rather than
   global, because silent installation is exactly the kind of behaviour an OEM
   build changes.
7. **The escape-surface catalogue is reconciled.** Any package found in K-7 is
   either added to `KIOSK_ESCAPE_SURFACES` and re-tested, or recorded as an
   accepted, documented limitation with the customer's sign-off.
8. **Recovery is rehearsed on the real model.** At least one full abort-ladder
   run on a unit of the ordered model, including the recovery code, with the rung
   reached recorded.

Anything short of these is a pilot, and it is described to the customer as a
pilot.

## Re-validation triggers

A record is evidence about the build it was taken on. Re-run the affected groups
when any of these changes:

| Trigger | Re-run |
| --- | --- |
| OEM firmware update on a tested model | The full kiosk group and C-6, C-10, C-18. A firmware update is a new record, not an amendment to the old one. |
| Android major upgrade on a tested model | Everything. A new row in the summary table. |
| A new model, even from a tested family | Everything. |
| A Device Guard release that changes lock task, the HOME preference, escape-surface hiding or the update channel | The affected capability rows on every record that is still in service. |
| A change to `KIOSK_ESCAPE_SURFACES`, `ESSENTIAL_SYSTEM` or the management records | C-6, C-9, C-15, C-17. |
| A new `UserManager` restriction added to `SystemPolicyControl` | C-12 on the lowest release in the fleet, where `unsupported` is the likely and correct answer. |

## Honesty note

The point of this file is that it can only be improved by running the tests. It
cannot be improved by writing in it. If a cell reads `—`, the correct statement
to a customer, a reviewer or a colleague is "we have not tested that", and the
correct statement about the fleet is whatever the weakest relevant cell says.
