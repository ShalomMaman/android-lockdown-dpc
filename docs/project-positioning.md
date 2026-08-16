# Project positioning and discoverability

This document keeps Device Guard's public description accurate, searchable and
consistent. It is not a growth-at-any-cost plan. Discoverability must never
outrun the evidence in the supported-device matrix or turn a pilot into an
implied production guarantee.

## Public name

- **Product name:** Device Guard for Android
- **Repository slug:** `android-lockdown-dpc`
- **Short category:** open-source Android Device Owner / DPC
- **One-line description:** Open-source Android Device Owner (DPC) for verified
  app allowlisting, system-app controls, secure kiosk mode and signed
  self-updates.

The repository slug remains unchanged while enrolled pilot builds obtain their
update metadata and artifacts through GitHub repository URLs. A future rename
requires a stable, project-controlled update domain first; redirects are not a
long-term release-channel design.

“Device Guard” is always paired with “for Android” in headings and external
copy. The unqualified term has unrelated historical uses and is not sufficiently
distinctive on its own.

## Who the project serves

1. **Managed-device operators** who need a locally enforced Android application
   allowlist or blocklist without deploying a full cloud MDM.
2. **Schools and dedicated-display operators** who need a single-app or
   single-site Android kiosk with an explicit recovery path.
3. **Android Enterprise and DPC developers** looking for a fail-closed,
   verifiable Device Owner implementation and signed self-update reference.
4. **Open-source reviewers and contributors** working on OEM compatibility,
   kiosk containment, provisioning, localization and recovery safety.

The project is not marketed as covert monitoring, an unbreakable parental
control, a certified EMM, or a general consumer app that can become Device Owner
after an ordinary installation.

## Search vocabulary

Use these phrases naturally where they accurately describe the relevant page.
Do not repeat them mechanically.

### Primary

- open-source Android Device Owner
- Android DPC
- Android app allowlist
- Android kiosk mode
- Android device lockdown

### Feature-specific

- single-app Android kiosk
- single-site Android kiosk
- Android system app blocking
- Android Lock Task mode
- Android dedicated device
- signed Android self-update
- Android Device Owner provisioning
- bilingual Android kiosk
- RTL Android device management

### Audience-specific

- school display kiosk
- digital signage Android kiosk
- managed Android phone
- offline Android device management

Every keyword must lead to useful content. A release note about update signing
should explain update signing; it should not be padded with unrelated kiosk
terms.

## Repository presentation

The repository landing page should answer four questions before presenting
implementation detail:

1. What is Device Guard?
2. Which managed-device and kiosk jobs does it perform?
3. Is it safe to deploy today?
4. Where can a user download, evaluate, contribute or report a vulnerability?

The README leads with the product outcome, three operating profiles, the pilot
warning and the main calls to action. Detailed security contracts, runbooks and
evidence remain in `docs/` and are linked rather than duplicated.

Repository metadata should use the same description and a focused set of GitHub
topics. Recommended topics are:

```text
android
android-enterprise
device-owner
device-policy-controller
dpc
app-allowlist
kiosk-mode
lock-task-mode
dedicated-devices
digital-signage
system-apps
mdm
kotlin
java
jetpack-compose
rtl
```

## Evidence-led content plan

Publish content only when it creates durable value for an operator or
contributor:

- A release page for each signed public artifact, with the supported status,
  upgrade path, security-relevant changes and known limitations.
- A short guide when a repeatable operator task is proven, such as QR
  provisioning, signed updates, OEM package classification or kiosk recovery.
- Real screenshots only from the version named in the caption. Never use a
  mockup as proof of a working feature.
- A device compatibility result only after the hardware-validation record is
  complete. Link failures as openly as passes.
- Architecture and security articles that link to the exact implementation and
  tests, making the repository useful even to teams that do not deploy the app.

Good external contribution channels include Android development communities,
Android Enterprise and digital-signage communities, F-Droid-compatible review
channels, and curated open-source Android lists. Posts should solve a concrete
problem and link to the relevant guide; automated backlink campaigns, copied
posts and keyword stuffing are out of scope.

## Stable website prerequisite

A project website can become the stable discovery and update entry point after:

1. a project-controlled domain is selected;
2. release and metadata URLs are separated from documentation URLs;
3. HTTPS ownership and renewal are automated;
4. the signed updater accepts and verifies the new endpoint in a staged release;
5. already enrolled pilot devices have crossed to that release successfully.

Until then, GitHub is the canonical public home. GitHub Pages may document the
project, but it must not become the update root merely for convenience.

## Release discoverability checklist

- The version, status and download link agree across README, release notes and
  update metadata.
- The release title describes user impact, not only an internal milestone.
- The first paragraph includes the relevant product category in plain English.
- Security or recovery changes link to the corresponding durable document.
- Hardware claims link to a device-matrix record.
- Screenshots have useful English alt text and name the build shown.
- No secrets, device identifiers, recovery material or private customer data
  appear in images, logs or metadata.
- Repository description and topics still match the implemented product.

## Measures of healthy discovery

Success is measured by qualified use, not raw impressions:

- external visitors reach the provisioning, security and contribution pages;
- Issues contain reproducible OEM or workflow evidence;
- contributors can identify a suitable task without private context;
- release downloads are followed by successful, documented test-device runs;
- search results describe the project as a pilot until the production gates
  actually pass.

The project does not add application telemetry or third-party tracking to
measure repository promotion.
