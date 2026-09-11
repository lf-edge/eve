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

An LTS line receives security fixes for **36 months** from the date its first `-lts`
release was published, in two phases:

- **Active**, for the first 24 months — security fixes and new LTS point releases.
- **Backports only**, for the following 12 months — security fixes land on the stable
  branch, but no further release is cut; consumers build from the branch or move to an
  active line.

After that the line is **end of life** and receives no fixes. Existing artifacts remain
downloadable.

The clock starts at a published release rather than at the branch cut or the first release
candidate, so a downstream vendor can check every date below against the releases page. From
13.4 onward a line's first `-lts` release is its `<major>.<minor>.0-lts`; the older lines
were promoted to LTS partway through and start at the first `-lts` tag they carry.

## Support status by line

| Line | First `-lts` release | Status | Active until | Backports until |
| --- | --- | --- | --- | --- |
| `master` | n/a | Development. Not for production, no security support. | n/a | n/a |
| 17.0.x | `17.0.0-lts`, 2026-07-27 | Active | 2028-07-27 | 2029-07-27 |
| 16.0.x | `16.0.0-lts`, 2026-01-07 | Active | 2028-01-07 | 2029-01-07 |
| 14.5.x | `14.5.0-lts`, 2025-06-18 | Active | 2027-06-18 | 2028-06-18 |
| 13.4.x | `13.4.0-lts`, 2024-12-28 | Active | 2026-12-28 | 2027-12-28 |
| 12.0.x | `12.0.2-lts`, 2024-06-12 | Backports only | 2026-06-12 | 2027-06-12 |
| 11.0.x | `11.0.2-lts`, 2023-12-15 | Backports only | 2025-12-15 | 2026-12-15 |
| 10.4.x | `10.4.6-lts`, 2023-10-27 | Backports only | 2025-10-27 | 2026-10-27 |

<!-- TBD(TSC): 13.4.x is Active under this policy until 2026-12-28, and the Active phase
     promises new LTS point releases, but none has been cut since 13.4.3-lts on
     2025-07-11. Either cut them, or move the line to Backports only ahead of the date and
     record that here. -->

<!-- TBD(TSC): 12.0.x, 11.0.x and 10.4.x are in their backport phase under this policy, but
     the branches are not receiving backports: last commit on `12.0-stable` June 2025, on
     `11.0-stable` January 2026, on `10.4-stable` July 2024. Either resume backporting to
     them for the remainder of the window, or shorten the window and say so. Declaring them
     end of life is not free: ZEDEDA publishes limited support for all three, to 2027-06-12,
     2026-11-30 and 2026-09-30 respectively. -->

<!-- TBD(TSC): the dates above are derived from the lf-edge/eve releases page. ZEDEDA's
     published LTS matrix agrees exactly for 12.0.x through 16.0.x, but dates 17.0.x one day
     later (2026-07-28) and uses GA dates for 11.0.x (2023-11-30) and 10.4.x (2023-09-30)
     that no EVE release carries. Decide whether to align the two tables. -->

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

<!-- TBD(TSC): the list does not exist yet and has to be requested from LF Edge. Decide the
     membership criteria and approver, the embargo agreement text, and what a member
     receives and when. See docs/VULNERABILITY-HANDLING.md, "Vendor pre-notification". -->

To request membership, contact [eve-security@lists.lfedge.org](mailto:eve-security@lists.lfedge.org).
