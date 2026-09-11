# Security Policy

## Reporting a Vulnerability

If you discover a security issue in EVE, report it privately. **Do not open a public GitHub issue.**

- Email [eve-security@lists.lfedge.org](mailto:eve-security@lists.lfedge.org), or
- use GitHub [private vulnerability reporting](https://github.com/lf-edge/eve/security/advisories/new).

Please include a description of the issue, the steps to reproduce it, the EVE versions you
believe are affected, your assessment of the impact, and a patch or proof of concept if you
have one. Report in English.

The security team acknowledges a report within **24 hours**. This is an acknowledgment of
receipt, not a commitment to a fix; remediation time depends on severity. EVE follows a
**90-day** coordinated disclosure timeline: if no fix has shipped 90 days after the report is
acknowledged, the reporter is free to disclose publicly, and the security team will publish
what it knows rather than let the issue go unrecorded. An earlier or later date can be agreed
with the reporter where a fix is imminent or a coordinated multi-vendor release requires it.

How reports are triaged, patched, embargoed, and published is described in
[docs/VULNERABILITY-HANDLING.md](docs/VULNERABILITY-HANDLING.md).

You may also report a vulnerability to a national CSIRT or to ENISA independently of this
policy. Doing so does not replace reporting it here, and the EVE security team would rather
hear about an issue twice than not at all.

## CRA Stewardship

This project is supported under the Linux Foundation CRA stewardship framework, as described
at <https://www.linuxfoundation.org/security>. Security vulnerabilities should be reported
through the mechanisms described below, which we will coordinate with our CRA steward. For
actively exploited vulnerabilities and severe incidents that may require CRA escalation,
please use the project’s emergency security reporting mechanisms as appropriate.

EVE's emergency reporting mechanism is the intake above, escalated on the strength of what
you tell us: if you believe a vulnerability is being **actively exploited**, or that the
project's own release or build infrastructure has been compromised, say so explicitly and put
it in the subject line. Active exploitation obliges the steward to file an early warning
within 24 hours and a formal notification within 72 hours, so the security team escalates
such a report to the steward immediately instead of waiting for triage to finish. There is no
separate address to remember under time pressure.

EVE is published for use in commercial products, which is what brings it within the steward
obligations in Regulation (EU) 2024/2847 Art 24.

## Safe Harbor

The EVE project will not initiate or support legal action against anyone who discovers or
reports a vulnerability in good faith under this policy, and will treat such research as
authorized conduct. Good faith means: you report promptly, you give the project a reasonable
opportunity to fix the issue before disclosing it, and you do not exploit the issue beyond
what is needed to demonstrate it.

Testing must stay within your own systems. Do not test against deployments, devices, or
controllers you do not own or have written permission to test, do not run denial-of-service
or resource-exhaustion tests against shared infrastructure, do not access or exfiltrate
another party's data, and do not use social engineering against project members or users.

The project does not operate a paid bounty program.

## Supported Versions

Which release lines receive security fixes, and until when, is maintained in
[docs/RELEASE-SUPPORT.md](docs/RELEASE-SUPPORT.md). That document is the authoritative
statement of security support; the GitHub releases page records what was published but
carries no support status.

## Scope

This policy covers the EVE edge operating system as published by the project: the
`lf-edge/eve` repository, the official EVE releases and installer images, the official
`lfedge/eve*` container images, and the repositories that build or ship code into a released
EVE image, currently `eve-api`, `eve-libs`, `eve-kernel`, `eve-monitor-rs`, `eve-rust`,
`eve-tpmea`, `edge-containers` and `runx`.

The build and test repositories `eden`, `adam`, `eve-build-tools`, `eve-tools` and `rol` are
in scope for reports, but a finding there normally affects developer and CI systems rather
than a deployed edge device. Say so in the report if you believe otherwise.

**Out of scope:** EVE is controller-agnostic. A vulnerability in a particular controller, or
in a controller's API surface as that controller implements it, belongs to that controller's
vendor, not to this project. Report it to them. Where a controller vulnerability is only
exploitable because of how EVE behaves, report it here as well.

Vulnerabilities in third-party components that EVE packages are in scope for triage: the
security team will assess the impact on EVE, coordinate with the upstream project, and ship
the fix. The upstream project owns the fix itself.

## Published Advisories

Advisories are published on the [EVE security advisories](https://github.com/lf-edge/eve/security/advisories)
page and announced on `eve-security-announce@lists.lfedge.org`. Each advisory identifies the
affected versions, the fixed versions, the impact, and the mitigation available to operators
who cannot upgrade immediately.

<!-- TBD(TSC): eve-security-announce@lists.lfedge.org does not exist yet and has to be
     requested from LF Edge. Until it does, advisories are announced on the general EVE
     mailing list at https://lists.lfedge.org/g/eve. -->

## For Downstream Vendors

A vendor shipping an EVE-based product is a manufacturer under Regulation (EU) 2024/2847 and
carries reporting and disclosure obligations that this project cannot discharge on the
vendor's behalf. [docs/RELEASE-SUPPORT.md](docs/RELEASE-SUPPORT.md) describes the support
information a vendor needs from the project, and how to join the pre-notification list that
carries embargoed advisories ahead of publication.

## Further Reading

- [docs/VULNERABILITY-HANDLING.md](docs/VULNERABILITY-HANDLING.md) — how the security team handles a report.
- [docs/SECURITY-ARCHITECTURE.md](docs/SECURITY-ARCHITECTURE.md) — EVE's security model and threat model.
- [docs/SECURITY-HARDWARE.md](docs/SECURITY-HARDWARE.md) — hardware security recommendations.
- [docs/SBOM-AND-SOURCES.md](docs/SBOM-AND-SOURCES.md) — where to find the SBoM and corresponding sources for a release.
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guidelines, including the stable-branch backport process.
