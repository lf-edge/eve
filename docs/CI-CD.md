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
* [Eden](https://github.com/lf-edge/eve/actions?query=workflow%3AEden) runs integration tests from EVE's sister project [Eden](https://github.com/lf-edge/eden)
* [Claude Code](https://github.com/lf-edge/eve/actions?query=workflow%3A%22Claude+Code%22) and [Claude Security Review](https://github.com/lf-edge/eve/actions?query=workflow%3A%22Claude+Security+Review%22) review pull requests with Claude
* [PR Event](https://github.com/lf-edge/eve/actions?query=workflow%3A%22PR+Event%22) triggers the pull request automation that needs secrets or write access

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
is a quarantined one over at `evebuild/danger` and the only artifact that is ever being deposited
there is a rootfs container tagged as `pr-ID` (e.g. `docker pull evebuild/danger:pr-12345` will
fetch a rootfs container for Pull Request 12345).

For the same reasons, Pulls action only runs on x86 runner since even GitHub itself strongly
discourages running anything that gets triggered by pull requests on hosted runners (which
is what our ARM64 runner is). This, in turn, may result in pull requests that end up breaking
our ARM buils but that seems to be rare enough of an event for now.

## Apache Yetus and Eden

These two actions run on x86 runner only. Yetus doesn't need to have an ARM64 run and Eden
would've benefited from one, but the underlying infrastructure required for that is still
too heavy to be hooked up to the GitHub actions (and it can't even be a hosted runner because
of the security concerns).

Both of these actions get triggered on PRs submitted to the master (and no other!) branch and
in addition Eden also gets triggered on updates to the master branch itself. We do NOT run
either of these on tags (releases).

In order to avoid lengthy rebuilds of EVE's rootfs, Eden action checks for `evebuild/danger:pr-12345`
artifacts and if one is available it uses it. If not it rebuilds it from scratch and then uses the
local build.

It may be marginally useful to run Yetus on updates to the master itself, but Yetus in its full
glory will generate too much feedback and the incremental updates are already covered by Yetus
triggering on pull request submissions.

## Claude reviews

Two workflows review pull requests with Claude and post the result as a PR review from
`github-actions[bot]`:

* **Claude Code** reviews the code: bugs, quality, security and performance.
* **Claude Security Review** runs the audit of
  [claude-code-security-review](https://github.com/anthropics/claude-code-security-review)
  and posts each finding as an inline comment.

Both run automatically when a pull request is opened, pushed to, reopened or marked ready for
review, if its author has write access to the repository. Draft pull requests are skipped. Anyone
who has contributed to the repository can also ask for a code review by writing `@claude` in a
comment on the pull request's Conversation tab; a comment on a line of code does not work.

The reviews run after the `PR Event` workflow, as described below. Claude runs with a read-only
token and returns its review as data, and a separate job without secrets posts it.

These runs belong to master's commit, so they do not appear among the pull request's checks.
Instead, each review sets a commit status on the pull request's head, `Claude Review` or
`Claude Security Review`: pending while it runs, then success or error, linking to the run.

The security review skips a push whose changes were already audited, such as a rebase, and does
not post a finding again when one of the same category was already posted near the same line.

## Pull request automation

Pull requests come from forks, and a `pull_request` run on a fork gets neither secrets nor a token
that can write, while GitHub blocks `pull_request_target` in public repositories. So the `PR Event`
workflow only runs on `pull_request` (opened, pushed to, reopened, ready for review) and does
nothing else. The workflows that need secrets or write access run after it on `workflow_run`, from
the master branch:

* the Claude reviews above;
* **Request Code Owners Review**, which requests reviews from the owners in the base branch's
  `.github/CODEOWNERS` of every path the pull request changes, except its author;
* **Close PRs from master**, which closes pull requests opened from a `master` or `main` branch
  and explains how to open one from a feature branch instead.

They trust nothing from the `PR Event` run and look the pull request up again. A `pull_request` run
uses the workflows of the branch the pull request targets, so on a pull request into a stable
branch these only run if that branch has the `PR Event` workflow. Runs from first-time
contributors wait for a maintainer's approval, so **Close PRs from master** also runs every 30
minutes and checks every open pull request.

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
