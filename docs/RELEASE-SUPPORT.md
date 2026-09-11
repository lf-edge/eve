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

## How long a line is supported

An LTS line receives security fixes for **36 months** from the date the line became
generally available, in two phases:

- **Active**, for the first 24 months — security fixes and new LTS point releases.
- **Backports only**, for the following 12 months — security fixes land on the stable
  branch, but no further release is cut; consumers build from the branch or move to an
  active line.

After that the line is **end of life** and receives no fixes. Existing artifacts remain
downloadable.

The support-start dates below are the general-availability dates of the LTS lines, which for
12.0 onward are the dates the line's first `-lts` release was published. The 11.0 and 10.4
lines were promoted to LTS partway through, and became generally available before the first
`-lts` tag they carry; both dates are given so the difference is visible rather than
surprising.

## Support status by line

| Line | First `-lts` release | Support start | Status | Active until | Backports until |
| --- | --- | --- | --- | --- | --- |
| `master` | n/a | n/a | Development. Not for production, no security support. | n/a | n/a |
| 17.0.x | `17.0.0-lts`, 2026-07-27 | 2026-07-28 | Active | 2028-07-28 | 2029-07-28 |
| 16.0.x | `16.0.0-lts`, 2026-01-07 | 2026-01-07 | Active | 2028-01-07 | 2029-01-07 |
| 14.5.x | `14.5.0-lts`, 2025-06-18 | 2025-06-18 | Active | 2027-06-18 | 2028-06-18 |
| 13.4.x | `13.4.0-lts`, 2024-12-28 | 2024-12-28 | Active | 2026-12-28 | 2027-12-28 |
| 12.0.x | `12.0.2-lts`, 2024-06-12 | 2024-06-12 | Backports only | 2026-06-12 | 2027-06-12 |
| 11.0.x | `11.0.2-lts`, 2023-12-15 | 2023-11-30 | Backports only | 2025-11-30 | 2026-11-30 |
| 10.4.x | `10.4.5-lts`, 2023-10-27 | 2023-09-30 | Backports only | 2025-09-30 | 2026-09-30 |

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

The project maintains `eve-distributors-announce@lists.lfedge.org` for vendors who ship EVE
commercially, carrying embargoed advisory information ahead of public publication so a vendor
can prepare its own advisory and update. Membership requires a named security contact who
agrees to hold embargoed information until the disclosure date.

To request membership, contact [eve-security@lists.lfedge.org](mailto:eve-security@lists.lfedge.org).
