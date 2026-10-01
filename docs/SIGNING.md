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

## Verifying a release

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
- the `FROM lfedge/eve-*` base images of every package the job built

A release build also adds the release name as a tag to every package it
reuses. Only the packages the build pulls are checked, so such a tag on a
package it did not pull may name an unsigned digest.

The policy accepts `release-sign.yml@refs/heads/master`, and
`publish.yml` at `master`, `N.N` and `N.N-stable`. A job signs the packages
it built after pushing them, and the `manifest` job signs their indexes once
every platform manifest in an index verifies. A re-run of a branch build
also signs reused packages that do not verify, since an earlier attempt may
have pushed them and failed before signing.

A failed check is a warning until the repository variable `EVE_COSIGN_ENFORCE`
is `true`, and fails the job after that. A tag build that would have to build
a package is such a failure, except for the packages the Makefile rebuilds on
every build (`FORCE_BUILD_PKGS`): their tag does not name their content, so a
tag build rebuilds them from the tagged source, as it does EVE itself.

Not signed by EVE's workflows, and therefore not verified: `lfedge/eve-kernel`
(published by the eve-kernel repository), `linuxkit/*` images, and external
`FROM` images. The build pins them by tag or digest as before.

## Enabling on a branch

1. Create the `release` environment with required reviewers, prevent
   self-review on, and deployments limited to release tag names.
2. Package images pushed before signing carry no signature and are reused by
   content hash indefinitely. Change every package's source on the branch so
   that the next build rebuilds, pushes and signs all of them.
3. Set `EVE_COSIGN_ENFORCE` to `true` once every branch that builds releases
   has been through step 2.

A package pushed by one build and pulled by another before the first has
signed it, a window of a few seconds, fails enforced verification; re-running
the job resolves it.
