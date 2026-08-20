#!/usr/bin/env python3
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
"""kube-images-catalog-gen.py.

Auto-derives pkg/kube-images/upstream-images.list from the source
YAMLs and Go constants that already carry the pinned image versions
the running cluster consumes. The output is a plain, sorted list of
fully-qualified image references with the digest each tag resolved to,
one per line:

    docker.io/longhornio/longhorn-manager:v1.9.1@sha256:8ad4...
    ghcr.io/k8snetworkplumbingwg/multus-cni:v3.9.3@sha256:1f2e...
    quay.io/kubevirt/virt-operator:v1.7.3@sha256:176c...
    ...

The tag is what a human reads and what kubelet's pod specs reference;
the digest is what the build pulls, so the payload is content-addressed
and this tracked file fully determines it -- which is what keeps
kube-images off LINUXKIT_FORCE_PKGS.

Deriving stays offline: digests already recorded for an unchanged
repo:tag are carried forward from the current list, so `make
kube-images-catalog-check` needs no network. A tag with no digest to
carry is an error naming `make kube-images-catalog-pin`, which resolves
the missing ones with skopeo and rewrites the file. It fails rather
than emitting an unpinned line because an unpinned ref is the defect
being removed.

pkg/kube-images/Dockerfile loops over this file, `skopeo copy`-ing
each ref into a shared OCI image layout that mkfs.erofs then turns
into the kube-images payload.

The file is committed for reviewability; the Makefile regenerates
it whenever any of its inputs change and `make
kube-images-catalog-check` re-derives + diffs so CI catches drift.

Sources of truth per family:

  * KubeVirt operator + virt-* pods (5) — one tag drives all
      pkg/kube/kubevirt-operator.yaml — reads virt-operator's tag,
      expands to virt-{operator,api,controller,handler,launcher} at
      the same tag (KubeVirt convention).

  * Multus CNI (1)
      pkg/kube/multus-daemonset.yaml

  * Longhorn + CSI sidecars (13)
      the lh-cfg-vX.Y.Z.yaml pointed at by the `longhornCfg` const
      in pkg/kube/kube-init/components/components.go. Every
      longhornio/ image ref inside is captured — image: lines,
      env-var value: strings, --engine-image / --instance-manager-
      image args.

  * kube-vip + kube-vip-cloud-provider (2)
      pkg/kube/kubevip-ds.yaml, pkg/kube/kubevip-sa.yaml.

  * CDI operator + subordinates (7) — one const drives all
      the `cdiVersion` const in components.go, expanded to
      cdi-{operator,apiserver,controller,importer,cloner,
      uploadproxy,uploadserver} at that tag (CDI convention).

Deliberately NOT in the list:

  * external-boot-image (EVE-authored) — not pulled at all. kube-init
    assembles it on the device from the running rootfs's kernel and
    runx-initrd, so it needs no entry in this catalog.

  * descheduler, system-upgrade-controller, alpine — no local
    source of truth on this branch. They land upstream when
    rt-operator-manifests comes in from rt-k8s (each ships its
    own YAML pin).
"""
# pylint: disable=invalid-name  # a CLI script name, not an import target

import argparse
import hashlib
import pathlib
import re
import subprocess
import sys

try:
    import yaml
except ImportError:
    sys.exit(
        "ERROR: PyYAML not installed. `pip install pyyaml` (or install the "
        "system 'python3-yaml' package)."
    )

REPO = pathlib.Path(__file__).resolve().parent.parent
CATALOG = REPO / "pkg/kube-images/upstream-images.list"
COMPONENTS_GO = REPO / "pkg/kube/kube-init/components/components.go"
VERSIONS_GO = REPO / "pkg/kube/kube-init/versions/versions.go"

# Well-formed image ref: <host-or-repo>/<name>[:tag].
IMAGE_REF_RE = re.compile(
    r"[a-zA-Z0-9.-]+(?:/[a-zA-Z0-9._-]+)+:[a-zA-Z0-9._+-]+"
)


# One term of a Go const expression: a string literal or a versions.X
# reference. The pinned versions live in their own package, so a const
# here is typically a concatenation of the two ("/etc/lh-cfg-" +
# versions.Longhorn + ".yaml").
GO_TERM_RE = re.compile(r'"([^"]*)"|versions\.([A-Za-z0-9_]+)')


def read_go_const(name: str, source: pathlib.Path = COMPONENTS_GO) -> str:
    """Return the value of a single-line Go const, resolving versions.X."""
    text = source.read_text()
    match = re.search(rf"^\s*{name}\s*=\s*(.+)$", text, re.M)
    if not match:
        sys.exit(f"ERROR: const {name!r} not found in {source}")
    return eval_go_expr(match.group(1).split("//")[0].strip(), name, source)


def eval_go_expr(expr: str, name: str, source: pathlib.Path) -> str:
    """Concatenate a `"lit" + versions.X + "lit"` expression.

    Deliberately strict: anything else (a function call, a const from a
    third package, a multi-line expression) exits rather than silently
    yielding a truncated version, which would produce a catalog missing
    the tag entirely.
    """
    parts, pos = [], 0
    for m in GO_TERM_RE.finditer(expr):
        if expr[pos:m.start()].strip() not in ("", "+"):
            sys.exit(f"ERROR: cannot evaluate const {name!r} in {source}: {expr!r}")
        lit, ver = m.group(1), m.group(2)
        parts.append(lit if lit is not None else read_version(ver))
        pos = m.end()
    if not parts or expr[pos:].strip() != "":
        sys.exit(f"ERROR: cannot evaluate const {name!r} in {source}: {expr!r}")
    return "".join(parts)


def read_version(name: str) -> str:
    """Return the value of a const in the versions package."""
    match = re.search(rf'^\s*{name}\s*=\s*"([^"]+)"',
                      VERSIONS_GO.read_text(), re.M)
    if not match:
        sys.exit(f"ERROR: const {name!r} not found in {VERSIONS_GO}")
    return match.group(1)


def _walk_yaml_for_refs(node, out: set):
    """Recursively collect every image-ref-shaped string under `node`.

    Catches both `image: registry/name:tag` (dict entries) and
    Longhorn's `value: "longhornio/foo:v"` env-var strings and
    `--engine-image "longhornio/foo:v"` argument list entries.
    """
    if isinstance(node, dict):
        for v in node.values():
            _walk_yaml_for_refs(v, out)
    elif isinstance(node, list):
        for v in node:
            _walk_yaml_for_refs(v, out)
    elif isinstance(node, str):
        for m in IMAGE_REF_RE.finditer(node):
            out.add(m.group(0))


def image_refs_matching(path: pathlib.Path, pattern: re.Pattern) -> set:
    """Every image ref in `path` whose full form matches `pattern`."""
    found: set = set()
    with path.open() as fp:
        for doc in yaml.safe_load_all(fp):
            if doc is not None:
                _walk_yaml_for_refs(doc, found)
    return {r for r in found if pattern.search(r)}


def one_ref(path: pathlib.Path, pattern: re.Pattern) -> str:
    """Fail if `pattern` doesn't match exactly one ref in `path`."""
    matches = image_refs_matching(path, pattern)
    if len(matches) != 1:
        sys.exit(
            f"ERROR: expected exactly one image matching {pattern.pattern} "
            f"in {path}, got {sorted(matches)}"
        )
    return matches.pop()


def main(pin_missing: bool) -> None:
    """Derive the catalog and print it, one pinned ref per line."""
    lh_cfg_const = read_go_const("longhornCfg")
    lh_cfg = REPO / "pkg/kube" / pathlib.Path(lh_cfg_const).name
    if not lh_cfg.is_file():
        sys.exit(f"ERROR: longhorn config {lh_cfg} not found on disk")

    cdi_version = read_go_const("cdiVersion")

    kubevirt_version = one_ref(
        REPO / "pkg/kube/kubevirt-operator.yaml",
        re.compile(r"^quay\.io/kubevirt/virt-operator:"),
    ).split(":", 1)[1]

    multus_ref = one_ref(
        REPO / "pkg/kube/multus-daemonset.yaml",
        re.compile(r"^ghcr\.io/k8snetworkplumbingwg/multus-cni:"),
    )
    kubevip_ref = one_ref(
        REPO / "pkg/kube/kubevip-ds.yaml",
        re.compile(r"^ghcr\.io/kube-vip/kube-vip:"),
    )
    kubevip_cloud_ref = one_ref(
        REPO / "pkg/kube/kubevip-sa.yaml",
        re.compile(r"^ghcr\.io/kube-vip/kube-vip-cloud-provider:"),
    )
    longhorn_refs = image_refs_matching(lh_cfg, re.compile(r"^longhornio/"))
    if not longhorn_refs:
        sys.exit(f"ERROR: no longhornio/ image refs in {lh_cfg}; the config "
                 "shape changed and the catalog would ship without Longhorn")

    refs: set = set()

    # KubeVirt (5, same tag by convention).
    for name in ("virt-operator", "virt-api", "virt-controller",
                 "virt-handler", "virt-launcher"):
        refs.add(f"quay.io/kubevirt/{name}:{kubevirt_version}")

    # CDI (7, same tag by convention).
    for name in ("cdi-operator", "cdi-apiserver", "cdi-controller",
                 "cdi-importer", "cdi-cloner", "cdi-uploadproxy",
                 "cdi-uploadserver"):
        refs.add(f"quay.io/kubevirt/{name}:{cdi_version}")

    # Single-ref families.
    refs.update((multus_ref, kubevip_ref, kubevip_cloud_ref))

    # Longhorn (13). longhornio/ resolves under docker.io by default;
    # spell it out so the loop pulls from the same URL skopeo would.
    for ref in longhorn_refs:
        refs.add(f"docker.io/{ref}")

    pinned = pin(sorted(refs), resolve_missing=pin_missing)
    for line in pinned:
        print(line)


def read_pins() -> dict:
    """repo:tag -> digest, from the catalog as it stands on disk."""
    pins = {}
    if not CATALOG.is_file():
        return pins
    for line in CATALOG.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "@" not in line:
            continue
        ref, digest = line.rsplit("@", 1)
        pins[ref] = digest
    return pins


def resolve(ref: str) -> str:
    """The digest ref currently resolves to, via skopeo.

    The manifest's own digest is the sha256 of its raw bytes, which is
    what a registry means by a digest reference -- so hash what skopeo
    hands back rather than trusting a formatted field.
    """
    try:
        raw = subprocess.run(["skopeo", "inspect", "--raw", f"docker://{ref}"],
                             check=True, capture_output=True).stdout
    except FileNotFoundError:
        sys.exit("ERROR: skopeo not installed, needed to resolve digests")
    except subprocess.CalledProcessError as e:
        sys.exit(f"ERROR: cannot resolve {ref}: {e.stderr.decode().strip()}")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def pin(refs: list, resolve_missing: bool) -> list:
    """Attach a digest to every ref, carrying known ones forward."""
    known = read_pins()
    out, missing = [], []
    for ref in refs:
        digest = known.get(ref)
        if digest is None:
            if not resolve_missing:
                missing.append(ref)
                continue
            digest = resolve(ref)
            print(f"[pin] {ref} -> {digest}", file=sys.stderr)
        out.append(f"{ref}@{digest}")
    if missing:
        sys.exit("ERROR: no recorded digest for:\n  "
                 + "\n  ".join(missing)
                 + "\nRun `make kube-images-catalog-pin` to resolve them "
                   "(needs network).")
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pin", action="store_true",
                    help="resolve digests for refs that have none (needs "
                         "network and skopeo); without it, a ref with no "
                         "recorded digest is an error")
    main(ap.parse_args().pin)
