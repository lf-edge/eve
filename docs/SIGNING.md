# Signed EVE releases

EVE's release workflows sign their outputs with [Sigstore](https://www.sigstore.dev/)
keyless signing. No long-lived key exists: each signature carries a short-lived
certificate issued to the GitHub Actions workflow that produced it, and is
recorded in the public Rekor transparency log. Checking that identity is what
distinguishes an LF Edge build from anyone else's, including a fork that signs
its own builds the same way.

## What is signed

| Artifact | Signing identity | When |
| --- | --- | --- |
| `lfedge/eve:<tag>[-<platform>]-<hv>-<arch>`, `lfedge/eve-sources:…`, their multi-arch indexes, and an SPDX SBOM attestation on each EVE image except riscv64 | `release-sign.yml@refs/heads/master` | release tags, after approval |
| `<arch>.<hv>.<platform>.sha256sums` release asset | `release-sign.yml@refs/heads/master` | release tags, after approval |
| `lfedge/eve-<pkg>` platform manifests and indexes | `publish.yml@refs/heads/<branch>` | pushes to `master`, `N.N` and `N.N-stable` that build the package |

Each `sha256sums` also covers `<arch>.<hv>.<platform>.images.txt`, which names
the image digests the release files were extracted from. Its signature is the
`<arch>.<hv>.<platform>.sha256sums.sigstore.json` bundle next to it.

Pull requests never reach these workflows, so nothing unmerged is signed.

## Release flow

A release tag runs `publish.yml` from the tagged commit. It reuses the
packages a build of its branch pushed and signed (see below for the
exception). Then:

1. The `eve` jobs push EVE and `eve-sources` by digest, without a tag, and the
   `indexes` job pushes the multi-arch indexes the same way.
2. `assets.yml` builds the release files from those digests into a draft
   release, which only collaborators can see.
3. One call of `release-sign.yml` from `master` signs the images, the indexes,
   the SBOM attestations and the `sha256sums` files. It first checks that the
   tagged commit is on the `N.N` or `N.N-stable` branch of the tag, then waits
   for approval of the `release` environment.
4. The `tag` job tags the signed digests, and the `release` job attaches the
   bundles and publishes the release as a pre-release.

Nothing is tagged or published before the approval. Because the signing job
is `release-sign.yml` at `master`, the certificate names that file whatever
the tag's own `publish.yml` contains; the tag and its commit are in the
certificate's Source Repository Ref and Digest.

## Approving a release

When a release waits for approval, `release-sign.yml` opens an issue "Approve
release `<tag>`" that mentions the approvers, links the Publish run, where the
`sign / sign` job waits behind "Review deployments", and lists the image
digests it will sign. Before approving, rebuild the tag independently and
compare the rebuild with the release images:

1. **Find the draft release.** Drafts are visible only to users with push
   access. On <https://github.com/lf-edge/eve/releases> the draft carries the
   tag as its name and a "Draft" label; its URL is
   `releases/tag/untagged-<hex>`, not the tag. From the command line, one
   line per draft with its tag, release id and URL:

   ```sh
   gh api --paginate repos/lf-edge/eve/releases \
     --jq '.[] | select(.draft) | "\(.tag_name) \(.id) \(.html_url)"'
   ```

   `releases/tags/<tag>` and the assets' `browser_download_url` return 404
   for a draft; list the assets by release id and fetch a file by asset id:

   ```sh
   gh api --paginate repos/lf-edge/eve/releases/<release-id>/assets \
     --jq '.[] | "\(.id) \(.name)"'
   gh api -H 'Accept: application/octet-stream' \
     repos/lf-edge/eve/releases/assets/<id> > <name>
   ```

2. **Note what gets signed.** Each `<arch>.<hv>.<platform>.images.txt` on the
   draft names the `eve` and `eve-sources` digests that `release-sign.yml`
   signs, `eve` first. The run's `sign-images-*` and `sign-blobs-*`
   artifacts, under "Artifacts" on the run's Summary page, hold the same
   lists and the `sha256sums` files.

3. **Rebuild the tag** on a machine that shares nothing with the release
   runners and holds no registry or GitHub credentials, such as a disposable
   VM with the prerequisites in [BUILD.md](BUILD.md) and Go, with which
   `make` builds linuxkit from source. Force-build every
   package except `eve-alpine` and `eve-alpine-base`, which come from Docker
   Hub: each `eve-alpine` build signs its package mirror with a new key, so a
   rebuilt one differs throughout. For amd64 kvm/generic:

   ```sh
   git clone --branch <tag> https://github.com/lf-edge/eve
   cd eve
   make HV=kvm ZARCH=amd64 PLATFORM=generic REPO_TAG=<tag> FORCE_BUILD=--force \
     -o eve-alpine -o eve-alpine-base -o pkg/alpine -o pkg/alpine-base pkgs
   make HV=kvm ZARCH=amd64 PLATFORM=generic REPO_TAG=<tag> rootfs
   ```

   Run `rootfs` only after `pkgs` succeeds: a package that failed to build
   is otherwise pulled from Docker Hub. `REPO_TAG` sets the version the
   release was built with; without it, the Makefile takes the newest tag on
   the commit, which differs once a later tag points at the same commit. The
   rebuilt image is `dist/amd64/<tag>/installer/rootfs.img`.

4. **Compare** the release image, by the `eve` digest in `images.txt`, with
   the rebuild, using `tools/eve-build-diff` from a reviewed `master`
   commit, never from the tag under test:

   ```sh
   tools/eve-build-diff/eve-build-diff.py --json report.json \
     docker:lfedge/eve@sha256:<digest> <rebuild>/dist/amd64/<tag>/installer/rootfs.img
   ```

   Exit status 0 means a rule in `known-diffs.toml` explains every
   difference. Do not approve while an ERROR remains unexplained; see
   `tools/eve-build-diff/README.md`.

5. **Approve.** On the run page, open "Review deployments", select `release`
   and choose "Approve and deploy".

## Verifying a release

Verify an EVE image or release before using it: before building an installer
or live image from it, and before copying images or release files into a
local datastore or mirror. Signatures are stored next to each image on
Docker Hub, and `cosign save` does not include them; to keep a copied image
verifiable, copy it with its signatures, for example
`oras copy --recursive --to-oci-layout`.

With [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) 3.x:

```sh
TAG=17.6.0
POLICY=(--certificate-oidc-issuer https://token.actions.githubusercontent.com
  --certificate-identity https://github.com/lf-edge/eve/.github/workflows/release-sign.yml@refs/heads/master
  --certificate-github-workflow-repository lf-edge/eve
  --certificate-github-workflow-ref "refs/tags/$TAG")

cosign verify "${POLICY[@]}" lfedge/eve:$TAG-kvm-amd64
cosign verify-attestation --type spdxjson "${POLICY[@]}" lfedge/eve:$TAG-kvm-amd64

cosign verify-blob "${POLICY[@]}" \
  --bundle amd64.kvm.generic.sha256sums.sigstore.json amd64.kvm.generic.sha256sums
sha256sum --ignore-missing -c amd64.kvm.generic.sha256sums
```

Pin the identity, the repository and the tag. Any repository can call a
public reusable workflow, so a fork's call of `release-sign.yml` yields the same
identity with the fork in the repository field. A signature made by a tag's
own `publish.yml` names `publish.yml@refs/tags/<tag>` and must not be
accepted: a tag can be pushed at any commit.

cosign cannot currently check the certificate's immutable repository-owner ID,
so these checks rely on the `lf-edge` organization name.

## Verification inside the build

`publish.yml` verifies what it reuses before it pushes anything built from it,
after `make pkgs` and again after `make eve`, with `tools/eve-cosign.sh`:

- every `lfedge/eve-*` platform manifest in the linuxkit cache that the
  registry already served, by the digest in the cache rather than the tag
- the `lfedge/eve-*` base images of every package the job built, named on a
  `FROM` line or pinned by an `ARG` that a `FROM` uses

Packages are pushed only under their content tag, and only by branch builds.

The policy accepts `release-sign.yml@refs/heads/master`, and
`publish.yml` at `master`, `N.N` and `N.N-stable`. A job signs the packages
it built after pushing them, and the `manifest` job signs their indexes once
every platform manifest in an index verifies. A re-run of a branch build
also signs reused packages that do not verify, since an earlier attempt may
have pushed them and failed before signing.

The jobs that sign packages hold `id-token: write` for their whole run,
including `make` and the package Dockerfiles, on self-hosted runners that also
build pull requests. A compromised step in such a job can sign anything as
`publish.yml` on that branch, as well as push it with the job's registry
login. Release signatures are outside this boundary: only `release-sign.yml`'s
signing job, on a GitHub-hosted runner, can produce them.

A failed check is a warning until the repository variable `EVE_COSIGN_ENFORCE`
is `true`, and fails the job after that. A tag build that would have to build
a package is such a failure, except for the packages the Makefile rebuilds on
every build (`FORCE_BUILD_PKGS`): their tag does not name their content, so a
tag build rebuilds them from the tagged source, as it does EVE itself.

Not signed by EVE's workflows, and therefore not verified: `lfedge/eve-kernel`
and `lfedge/eve-rust` (published by the eve-kernel and eve-rust repositories),
`linuxkit/*` images, and external `FROM` images. The build pins them by tag or digest as before.

## Enabling on a branch

1. Create the `release` environment with required reviewers, prevent
   self-review on, and deployments limited to release tag names. Set the
   repository variable `RELEASE_APPROVERS` to the reviewers to mention, as
   `@user @user …`.
2. Package images pushed before signing carry no signature and are reused by
   content hash indefinitely. Change every package's source on the branch so
   that the next build rebuilds, pushes and signs all of them.
3. Set `EVE_COSIGN_ENFORCE` to `true` once every branch that builds releases
   has been through step 2.

A package pushed by one build and pulled by another before the first has
signed it, a window of a few seconds, fails enforced verification; re-running
the job resolves it.
