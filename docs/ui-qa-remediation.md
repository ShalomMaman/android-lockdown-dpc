# UI / i18n / kiosk-admin remediation

What an independent review of the 0.5 branch found, what changed in response, and
what is still unproven. The review itself was static: no Gradle run, no emulator,
no device. This document exists so the difference between "fixed in source" and
"observed working" stays visible.

## Fixed

### Local authenticated recovery is reachable from a single-app kiosk

The blocking one. The console documented a corner gesture that opens the PIN
screen, unconditionally — but in single-app mode the display was handed to the
pinned package with `LOCK_TASK_FEATURE_NONE`, so a target that traps Back left
`KioskHostActivity` unreachable and the gesture with it. The stated fallback
("only re-provisioning the device removes kiosk") became the first resort. In a
school that is a wiped device.

The DPC is now the persistent HOME host *and* the HOME key is allowed back to it
in single-app mode, which returns to a contained kiosk home rather than to a
launcher. See [`kiosk-mode.md`](kiosk-mode.md#reaching-the-gesture-in-a-single-app-kiosk)
for the design, the interlocks and why this is not an unauthenticated escape.
`kiosk_recovery_single_app` states the API 26–27 limitation rather than hiding it.

One behaviour changed as a consequence: a single-app target that closes itself now
shows the contained kiosk home instead of being relaunched automatically. That is
deliberate — telling "the user pressed Home" apart from "the target exited" means
trusting `onNewIntent` delivery on every OEM build, and getting it wrong would put
the relaunch back on top of the recovery surface. One tap on "Return to the app"
is the cost; an unrecoverable classroom device is the alternative.

### Policy writes re-check the administrator session

`AdminSession` expires on wall time, not on interaction, and the blocking-method
and display-language dialogs only checked it when they were *opened*. Both now
re-check at save, so a console left open on a desk cannot be committed by whoever
picks the device up three minutes later. Rotating the recovery code — which
revokes a credential a school holds off-device — goes through a confirmation
dialog instead of a single tap on a 64 dp row.

### Switching blocking methods no longer erases the app list

Each method keeps its own saved selection (`AllowedAppsStore`), so switching is
reversible and an administrator who taps the other radio button to read what it
does loses nothing. An existing single selection is migrated onto the method it
was saved under. The dialog says so in both languages.

### Bidi, layout and copy

| Was | Now |
| --- | --- |
| A third-party app label forced left-to-right on the activation row and the confirmation card, scrambling a Hebrew label such as `סרטונים (בטא)` | First-strong isolation (`KioskSnapshot.targetDisplay`), matching how the picker already renders the same data |
| The website field laid out in an RTL paragraph, displacing a URL's punctuation and port and jumping the caret | Field pinned left-to-right; the two app searches use content direction (`dir="auto"`); the PIN field pinned left-to-right |
| The "exit kiosk" row subtitled with `kiosk_exited` — "Kiosk is off" — directly under "Active — the device is locked" | A dedicated `kiosk_action_exit_supporting` saying what the row will do |
| An invisible click-consuming 56 dp view swallowing taps on a portal's logo or hamburger menu | A non-consuming `dispatchTouchEvent` observer over a pure, unit-tested hit test |
| A status value with no weight measuring its own fact-row label down to zero width | Both texts weighted; the value shrinks instead of the label |
| An RTL system locale resolving English strings into a mirrored layout | Direction read from `R.bool.use_rtl_layout`, answered by the folder the strings came from |
| A `·` separator assembled in Kotlin | `kiosk_profile_state_summary`, visible to translators and to the parity check |
| Result banners silent to TalkBack; `ActionRow` announcing no role; disabled rows at ≈3.2:1 | Polite live regions (Compose and the kiosk host), `Role.Button`, M3 disabled colours with the supporting line kept at full contrast |
| Three Hebrew registers in one file; `apps_selected_count` dropping its noun in `other` | Impersonal throughout; the noun restored |
| An activation warning promising power-menu suppression the API 26–27 floor cannot enforce | Qualified per Android version, in both languages |

The locale-parity rule gained one narrow exemption, implemented identically in
`LocaleParityTest.kt` and `tools/check_locale_parity.py`: a value holding no word
at all — only placeholders and punctuation — is not reported as untranslated,
because there is nothing in it to translate. Both have tests for it.

## Deliberately not done

- **`androidTest` / Compose UI tests.** Every UI claim still rests on JVM tests of
  Android-free helpers plus XML parity. Adding an instrumentation suite is the
  right next step and is a change of a different shape.
- **`android:configChanges` on the kiosk host**, so a rotation stops reloading a
  single-site portal from scratch, and **`FLAG_KEEP_SCREEN_ON`** for a classroom
  display. Both are real, neither is an accessibility or localization defect.
- **Gender-tagged Hebrew status keys.** The two pairs are documented in place with
  the subject each agrees with, which is what stops the next translator from
  reverse-engineering it from Kotlin; splitting the keys is a larger change.

## Residual proof gaps

Nothing below is observed. `kiosk-mode.md` carries the full device matrix; these
are the ones this change *adds*, and they are the first things to run on the pilot
handset:

1. **That `LOCK_TASK_FEATURE_HOME` is accepted**, given that the kiosk HOME
   preference is registered in the same pass immediately before it. A refusal is
   handled — the minimal feature set is reapplied and
   `kiosk-lock-task-home-unavailable` is reported — so failure is safe and visible,
   but the accepting case is unverified.
2. **That Home in an active single-app kiosk resumes the host** rather than
   reaching a launcher or a resolver, on a given OEM build, and lands on the
   contained kiosk home rather than relaunching the target.
3. **That Overview, the shade, the keyguard and the power menu stay suppressed**
   once HOME is the applied feature set.
4. **That corner taps still complete the gesture over a live `WebView`** now that
   they are observed rather than consumed, and that a portal's own top-corner
   control responds again.
5. Everything the review already listed as device-only: rendering and bidi
   resolution by eye in both languages, runtime plural selection on API 26 and 36,
   TalkBack, contrast on a real panel, and the API 32→33 locale-storage boundary.
