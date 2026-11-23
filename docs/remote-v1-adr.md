# ADR 43 — Remote management v1

**Status: Accepted.** This decision records the architecture for the
[delegated management epic][epic] and resolves the design choice in [ADR issue #43][issue].
[Activation has separate gates](remote-management.md#blockers-for-pr-9-activation).

## Decision

Keep Device Guard as the Android Device Owner. Remote enrolment is opt-in on a
fresh device, starts with a verified local baseline and leaves local PIN mode
available for separate deployments. Moving an already-managed device requires
the supported reset and reprovisioning path. [Design #82][p82], [Android 12+ setup #83][p83],
[mode boundary #95][p95], [provisioning and exit](provisioning.md#recovering-a-device-with-the-wrong-component-or-identity).

- A separate service relays complete, target-bound fleet policies signed offline
  and receives device-signed reports. The offline fleet root signs key sets. The
  owner's offline fleet policy key signs every policy change, including any
  loosening, and signs recovery verifiers. The online command key can sign only
  fresh, device-bound `lock_now` and `reapply`. Release, update and per-device
  identity keys have separate purposes. [Wire contract #96][p96], [fleet tooling #103][p103], [signing checks #104][p104].
- The DPC verifies signatures, targeting and increasing versions, then commits
  through an authenticated journal. Its serialized policy engine reads Android
  state back before reporting a verified generation. The independent guard
  and retained trust protect stored version floors. A root-signed local
  re-anchor can repair supported storage failures while preserving live
  restrictions. [Durability #93][p93], [audit retry #94][p94], [verifier and projection #97][p97],
  [guard #99][p99], [sealed trust and rotation #100][p100], [re-anchor #101][p101], [recovery and projection fixes #102][p102].
- Fresh enrolment proves possession of the attested device key. Before signing
  a fleet policy, the offline tool independently checks the enrolment record
  against its own ticket inventory and expected identity. Signed sync supplies
  policy and read-back evidence. The network client and enrolment gate are
  enabled only in the separately signed `remoteTest` artifact at the merged
  baseline. [Tooling #103][p103], [device client #105][p105].
- Prove consent, access revocation, fleet isolation and verifiable reports in
  a view-only phase. The first write pilot permits only ordinary app filtering
  and explicitly enumerated low-risk rules after evidence of safe recovery.
  The broader protocol and the deferred work in [design section 14](remote-management.md#14-later-separate-design-not-reviewed-here)
  grant no pilot permissions. [Threat model and privacy](remote-v1-security.md),
  [operating runbooks](remote-v1-runbooks.md), [stable device audit codes #89][p89].

## Alternatives considered

| Option | Fit and operating cost | Decision |
| --- | --- | --- |
| Extend Device Guard | Keeps the custom filtering, kiosk and read-back engine. The project owns the small relay, audit, fleet identity and key custody. Existing local deployments can stay local. Exit from Device Owner uses the documented wipe path. | Adopt. Revisit if the project cannot safely operate the relay and recovery or customers require a supported enterprise lifecycle the DPC cannot provide. |
| Google Android Management API | Covers fully managed and dedicated Android Enterprise devices through Google's Android Device Policy app. Adoption replaces the custom enforcement component, requires migration and reprovisioning of existing Device Owner devices, and adds Google service dependency. Google's permissible-use rules restrict provider eligibility and require customer agreements and data disclosure. | Defer until the intended deployment meets eligibility and a migration and exit drill proves policy and recovery parity. [Architecture][amapi], [permissible use][usage], [production release][release]. |
| Headwind MDM | The Apache-2.0 server provides QR enrolment (documented for Android 7+), app deployment and status. Its launcher has its own Device Owner receiver. The self-hosted stack adds Java/Tomcat and PostgreSQL operations. Its maintained release line includes authorization fixes. Adoption would replace the agent or require a maintained compatibility layer for Device Guard's offline signing and read-back contract. | Defer. Revisit if a maintained integration proves this contract, migration and exit with less operational burden. [Server and license][headwind], [installation][headwind-install], [launcher manifest][headwind-agent], [release evidence][headwind-release]. |

[epic]: https://github.com/ShalomMaman/android-lockdown-dpc/issues/41
[issue]: https://github.com/ShalomMaman/android-lockdown-dpc/issues/43
[p82]: https://github.com/ShalomMaman/android-lockdown-dpc/pull/82
[p83]: https://github.com/ShalomMaman/android-lockdown-dpc/pull/83
[p89]: https://github.com/ShalomMaman/android-lockdown-dpc/pull/89
[p93]: https://github.com/ShalomMaman/android-lockdown-dpc/pull/93
[p94]: https://github.com/ShalomMaman/android-lockdown-dpc/pull/94
[p95]: https://github.com/ShalomMaman/android-lockdown-dpc/pull/95
[p96]: https://github.com/ShalomMaman/android-lockdown-dpc/pull/96
[p97]: https://github.com/ShalomMaman/android-lockdown-dpc/pull/97
[p99]: https://github.com/ShalomMaman/android-lockdown-dpc/pull/99
[p100]: https://github.com/ShalomMaman/android-lockdown-dpc/pull/100
[p101]: https://github.com/ShalomMaman/android-lockdown-dpc/pull/101
[p102]: https://github.com/ShalomMaman/android-lockdown-dpc/pull/102
[p103]: https://github.com/ShalomMaman/android-lockdown-dpc/pull/103
[p104]: https://github.com/ShalomMaman/android-lockdown-dpc/pull/104
[p105]: https://github.com/ShalomMaman/android-lockdown-dpc/pull/105
[amapi]: https://developers.google.com/android/management/introduction
[usage]: https://developers.google.com/android/management/permissible-usage
[release]: https://developers.google.com/android/work/release-solution
[headwind]: https://github.com/h-mdm/hmdm-server
[headwind-install]: https://github.com/h-mdm/hmdm-server/blob/master/INSTALL.txt
[headwind-agent]: https://github.com/h-mdm/hmdm-android/blob/master/app/src/main/AndroidManifest.xml
[headwind-release]: https://github.com/h-mdm/hmdm-server/releases/tag/v5.41.4
