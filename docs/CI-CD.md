# EVE CI/CD infrastructure

EVE development happens on GitHub and we use GitHub's Actions as the core of our CI/CD infrastructure.
Within GitHub actions we try to do as much as possible with the stock Github ubuntu image
(which as of December, 2020 is `ubuntu-20.04`) VM that gets instantiated from scratch every time
jobs need to run as part of a given action. However, since we also have to produce ARM builds,
we have a hosted runner tagged `ARM64` that we use for subset of the actions. EVE uses a standard
OCI Registry (currently on [Docker HUB](https://hub.docker.com/r/lfedge/eve)) to store all of
its CI/CD build artifacts.

Definitions of EVE CI/CD actions are available under [.github/workflows](../.github/workflows) folder
and they currently include:

* [Publish](https://github.com/lf-edge/eve/actions?query=workflow%3APublish) publishes various EVE build artifacts into an OCI Registry
* [Pulls](https://github.com/lf-edge/eve/actions?query=workflow%3APRs) manages pull requests
* [Apache Yetus](https://github.com/lf-edge/eve/actions?query=workflow%3A%22Apache+Yetus%22) runs static, lint-like [Apache Yetus](http://yetus.apache.org/) checks on EVE
* [evetest PR and nightly](#evetest) run the [evetest](../evetest/README.md) integration tests on self-hosted runners

Since EVE community generally frowns on branch-heavy development most of the descriptions below
will only apply to the master branch (unless stated otherwise).

## Publish

This is the only action that uses both x86 and ARM64 runners. It runs on pushes to the `master`,
`x.y` and `x.y-stable` branches and on release tags (`x.y.z`, `x.y.z-lts` and `x.y.z-rcN`), and
pushes EVE's packages and images into EVE's OCI Registry repositories. Their tags are set by EVE's
top-level Makefile:

* Packages (`lfedge/eve-<pkg>`) are pushed under a source-derived tag, the linuxkit git tree hash
  of the package (e.g. `lfedge/eve-pillar:b8c0b1813a7819ee9eefdc77f1883da5613e7017`). It changes
  only when the package's source changes, so a build reuses every package whose tag is already in
  the registry. Branch builds add no other tag. A release tag build also gives the packages it
  pushes the release tag, which linuxkit takes from the git tag on HEAD.
* The EVE image (`lfedge/eve`) and its sources (`lfedge/eve-sources`) are pushed under
  `<version>-<hv>`, where `<version>` is the release tag or `0.0.0-<branch>-<git sha>`, and under
  `<release name>-<hv>`, where the release name is `snapshot` on `master`, the branch name on `x.y`
  and `x.y-stable`, and the tag on a release tag (e.g. `lfedge/eve:snapshot-kvm`). The release name
  gets `-<platform>` for platforms other than `generic`. No tag omits `-<hv>`; the ones in the
  registry that do are stale.

Tags without an `-<arch>` suffix are multi-arch indexes. Publish does not push `latest` tags; the
ones in the registry are stale.

## Pulls

Pulls is, effectively, a much more constrained version of the Publish action. The reason it needs
to be constrained is that it triggers on any pull request submitted to the master branch and that
may include anonymous pull requests containing malicious code in them. Builds triggered by this
action do NOT deposit artifacts into the regular OCI registry. The registry that is being used
is a quarantined one over at `evebuild/pr` and the only artifact that is ever being deposited
there is an EVE container image tagged as `<version>-<hv>-<arch>`, where `<version>` is
`0.0.0-pr<ID>-<commit>` (e.g. `docker pull evebuild/pr:0.0.0-pr12345-1a2b3c4d-kvm-amd64` will
fetch the kvm/amd64 EVE image built for a commit of Pull Request 12345).

For the same reasons, Pulls action only runs on x86 runner since even GitHub itself strongly
discourages running anything that gets triggered by pull requests on hosted runners (which
is what our ARM64 runner is). This, in turn, may result in pull requests that end up breaking
our ARM buils but that seems to be rare enough of an event for now.

## Apache Yetus

This action runs on x86 runner only, since Yetus doesn't need to have an ARM64 run.

It gets triggered on PRs submitted to the master branch, the release branches (`x.y` and `x.y-stable`)
and `feature/*` branches. We do NOT run it on tags (releases).

It may be marginally useful to run Yetus on updates to the master itself, but Yetus in its full
glory will generate too much feedback and the incremental updates are already covered by Yetus
triggering on pull request submissions.

## evetest

Integration testing is done by [evetest](../evetest/README.md). An evetest run boots real EVE device
VM(s) plus an SDN VM per test, which is much heavier than a unit test, therefore the tests are run on
self-hosted runners instead of GitHub hosted ones.

### Infrastructure

The tests run on one or more Proxmox VE hosts, using evetest's
[Distributed deployment mode](../evetest/README.md#distributed-mode): the evetest container runs on a
runner and the EVE and SDN VMs are created directly on the hypervisor by a broker, instead of being nested
inside the runner. Every host runs:

* a **broker VM** (`evetest-broker`), which talks to the Proxmox API and creates/destroys the EVE and SDN
  VMs on demand,
* one or more thin **GitHub runner VMs**, which only run the evetest container (the Go test binary and
  the Adam controller) and talk to the broker over gRPC. The workload itself runs directly on the
  hypervisor, not nested inside the runner.

A host is set up in two scripted steps, see `evetest/deploy/proxmox`: `make -C evetest proxmox-broker-installer`
produces a self-contained installer for the broker VM, and `gh-runner-installer.sh` adds a runner VM
registered against the repository. Runner VMs share a label, so a workflow can pick any free one.

### Execution model

Tests are parallelized across test suites, not within one: each suite is a job of a matrix, which
GitHub fans out across all free runners, one suite per runner at a time (`fail-fast` is off, one failing
suite never cancels the others). The throughput therefore scales with the number of runner VMs.

### PR workflow

[PR Gate](../.github/workflows/pr-gate.yml) decides when evetest may start for a pull request. It runs
when the `PR build` workflow completes and when a review is submitted, and requires that every EVE build
evetest stages (kvm and k, generic amd64) has succeeded (it reports "pending" while one is still
running, and runs again once the build completes), and that the PR is approved or a CODEOWNER requested
the run with a `/evetest` comment. The result is published as the `Ready for evetest` commit status.

[evetest-pr.yml](../.github/workflows/evetest-pr.yml) then:

1. resolves the PR and the EVE version of the build, skips itself if the same commit is already being tested
   (or is no longer the PR head), and cancels evetest runs of older commits of the same PR,
2. discovers all suites and tests (`make -C evetest list-tests`),
3. lets Claude read the PR diff, description and commits and select which suites and tests are safe to
   skip (what the diff cannot affect, and redundant near-duplicates); a CODEOWNER can force everything
   with `/evetest all` or select tests with `/evetest <name>...`,
4. runs every remaining suite as its own matrix job, reporting a commit status per suite,
5. on a failure, keeps the devices alive (`EVETEST_PAUSE_ON_FAILURE`) while Claude investigates them
   through the evetest CLI (read-only diagnostics), cross-checking the PR diff, the nightly ledger and
   earlier failures of the same run, and then resumes the run,
6. reports: the Go test output is formatted for readability and the failure analysis is published in the
   workflow summary and as a PR comment.

Tests skipped on a PR are still run by the nightly workflow.

### Nightly workflow

[evetest-nightly.yml](../.github/workflows/evetest-nightly.yml) runs every suite (no filtering) on the tip
of master and of all active LTS branches, using the latest published `lfedge/eve` image. Once a week the
run is done with coverage collection enabled: it builds a `COVER=y` image from HEAD instead. It runs the
suites in parallel like the PR workflow, with the same live failure investigation, and then:

* merges the JUnit results of all suites into an Allure report, carrying the pass/fail history of the
  previous runs forward, to show trends and flaky tests,
* appends the failures, with their root cause analysis, to the nightly ledger, which the live
  investigations consult to tell known issues from new ones,
* in a run with coverage collection, merges the Go coverage counters of all suites into one HTML coverage
  report (see [CODE-COVERAGE.md](CODE-COVERAGE.md)),
* publishes all of the above to the GitHub Pages of the repository (the `gh-pages` branch).

For a branch `<branch>` (e.g. `master`) the results are published at:

* Allure report: `https://lf-edge.github.io/eve/test/<branch>/`
  ([master](https://lf-edge.github.io/eve/test/master/))
* Coverage report: `https://lf-edge.github.io/eve/test/<branch>/coverage`
  ([master](https://lf-edge.github.io/eve/test/master/coverage))
* Nightly ledger: `https://github.com/lf-edge/eve/blob/gh-pages/test/<branch>/NIGHTLY-LEDGER.md`
  ([master](https://github.com/lf-edge/eve/blob/gh-pages/test/master/NIGHTLY-LEDGER.md))

## Maintaining Dockerfile Versions

The Dockerfiles get out of date because they use base OS images that are periodically updated.
It is important to stay up-to-date in general for bug fixes and security updates,
but sometimes the Dockerfiles must be updated immediately when the OS image
removes a version of a package.

### Dockerfile Version Updates with Dependabot

GitHub provides a feature called **Dependabot** that fixes several kinds of out of date versions
including the OS images in Dockerfiles. The limitation is that it only updates the base OS image,
not the package versions in the apk add command, so it can only be used in EVE packages that do not
hardwire package versions.

Dependabot has two independent features, and lf-edge/eve uses only one of them:

* **Security updates** are enabled in the repository settings. Dependabot opens PRs
  against master for dependencies with a known vulnerability (Go modules, Python
  packages, etc.). These are reviewed and merged like any other PR, and backported
  to stable branches as needed.
* **Version updates** of Dockerfile base images are configured in
  `.github/dependabot.yml.disabled` but are not enabled in lf-edge/eve.
  Instead use them in user forks and let Dependabot create its PRs there.
  Then the user can cherry-pick the version changes, test, tweak, squash, and submit
  their own PR to lf-edge.

To use Dependabot version updates in a user fork:

* rename `.github/dependabot.yml.disabled` to `.github/dependabot.yml` and push to master
* open: Insights -> Dependency graph -> Dependabot
* re-run by: modify `.github/dependabot.yml`, push to master
* review generated PRs
* cherry-pick from dependabot/docker/* branches

### ver-update to List Package Versions

Dependabot will not help in EVE packages that use hardwired apk package versions.
Updating them is a manual process.
The hard part is finding the out of date versions and knowing what to replace them with.
That part can be done automatically with the scripts in build-tools/ver-update.
The main steps are:

```bash
cd build-tools/ver-update
make clean
make
grep pkg/my-pkg out-alp-ver-diff
```

It can generate the versions to change using different base OS versions.
That version is specified by ALP_BASE_OS in Makefile.
