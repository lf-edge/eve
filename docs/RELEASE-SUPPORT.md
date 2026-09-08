# Release Lines and Security Support

This document states which EVE release lines receive security fixes and for how long. It is
the authoritative source for that question, referenced from [SECURITY.md](../SECURITY.md).

## How EVE releases

EVE releases on a bi-weekly cadence from `master`. Each release is tagged and published on
the GitHub releases page.

Two kinds of release exist, and the GitHub prerelease flag is what distinguishes them:

- **LTS releases** carry an `-lts` suffix and are published as full releases. They are cut
  from a `<major>.<minor>-stable` branch.
- **Agile releases** carry no suffix and are published as prereleases, as are release
  candidates.

The flag is load-bearing rather than cosmetic: because only `-lts` tags are full releases,
`https://github.com/lf-edge/eve/releases/latest` always resolves to the current LTS, which is
what the README points production users at. A newer agile release is normal and does not mean
the LTS is behind.

The consequence for security support is that the releases page cannot answer "is this line
still supported". It records what was published, not what is maintained. Use the table below.

## Support status by line

Status values:

- **Active** — receives security fixes and new LTS point releases.
- **Backports only** — receives security fixes on the stable branch, but no new release is
  being cut; consumers build from the branch or move to an active line.
- **End of life** — receives no fixes. Existing artifacts remain downloadable.

<!-- TBD(TSC): the end dates below are unset. Each needs a decision before this document
     is accurate. A line marked Active with no end date states an open-ended commitment. -->

| Line | Status | Security fixes until |
| --- | --- | --- |
| `master` | Development. Not for production, no security support. | n/a |
| 17.0.x | Active | TBD(TSC) |
| 16.0.x | Active | TBD(TSC) |
| 14.5.x | Active | TBD(TSC) |
| 13.4.x | Backports only | TBD(TSC) |
| 12.0.x | TBD(TSC) — no commit on `12.0-stable` since June 2025 | TBD(TSC) |
| 11.0.x | TBD(TSC) | TBD(TSC) |
| 10.4.x | TBD(TSC) — no commit on `10.4-stable` since July 2024 | TBD(TSC) |

A line absent from this table is end of life.

Fixes reach a stable branch through the backport process in
[CONTRIBUTING.md](../CONTRIBUTING.md#backporting).

## Artifact and update availability

Release artifacts published to the GitHub releases page are not deleted when a line reaches
end of life, so an operator can still obtain the last build of an unsupported line. Continued
availability is not security support: no further fixes are issued for that line.

The SBoM and the corresponding sources for a release are described in
[SBOM-AND-SOURCES.md](SBOM-AND-SOURCES.md).

## For downstream vendors

A vendor shipping an EVE-based product is a manufacturer under Regulation (EU) 2024/2847 and
owes its own users a support period, a vulnerability-reporting contact, and security updates.
Those obligations sit with the vendor. This project supplies the inputs a vendor needs to
meet them, and nothing here is a commitment made to the vendor's customers.

Three points are worth stating explicitly, because vendors have read the project's own table
as if it were their support commitment:

- **The support end dates above are the project's, not yours.** A vendor's support period is
  set by the vendor, based on how long its product is expected to be in use. It may be longer
  than the upstream line's, in which case the vendor carries the fixes itself once the
  upstream line ends.
- **Keeping issued updates available is a separate duty from maintaining a line.** A vendor
  must keep each security update it has shipped retrievable by its users well after the
  update was issued, whether or not the corresponding EVE line is still maintained.
- **Reporting deadlines run from the vendor's own awareness.** An actively exploited
  vulnerability obliges the vendor to notify its national CSIRT and ENISA on a short clock.
  The project's acknowledgment SLA in [SECURITY.md](../SECURITY.md) is a different and
  unrelated commitment, and meeting it does not discharge the vendor's deadline.

### Pre-notification list

The project maintains a list for vendors who ship EVE commercially, carrying embargoed
advisory information ahead of public publication so a vendor can prepare its own advisory and
update. Membership requires a named security contact who agrees to hold embargoed information
until the disclosure date.

<!-- TBD(TSC): the list does not exist yet. Decide the intake address, the membership
     criteria and approver, the embargo agreement text, and what a member receives and when.
     See docs/VULNERABILITY-HANDLING.md, "Vendor pre-notification". -->

To request membership, contact [eve-security@lists.lfedge.org](mailto:eve-security@lists.lfedge.org).
