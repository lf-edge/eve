#!/usr/bin/env python3
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Rewrite the layers of an OCI image layout in place.

Two formats:

  erofs (default) -- convert every layer to a ready-made EROFS filesystem,
      exactly as containerd's EROFS differ would on the device
      (mkfs.erofs --tar=f --aufs), and label it with a media type ending
      in ".erofs". The differ then recognises the layer as native and
      places the blob instead of running mkfs.erofs itself, so first boot
      spends no CPU converting. Because a native layer's applied digest
      is the layer digest, the config's diff_ids are rewritten to match --
      that equality is the only thing containerd's unpacker checks.

  uncompressed -- decompress gzip layers to plain tar. What the device
      converts on its own; kept as the fallback format.

The conversion needs the PATCHED mkfs.erofs (see pkg/kube's erofs-utils
build): stock 1.8.6 mangles usr-merge base layers into a bogus ~2 TiB
image. The Dockerfile copies the same binary the device runs.
"""
# pylint: disable=invalid-name  # a CLI script name, not an import target
import argparse
import concurrent.futures
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid

REF_ANNOTATION = "org.opencontainers.image.ref.name"
EROFS_LAYER_MT = "application/vnd.oci.image.layer.v1.erofs"


def blob_path(root, digest):
    """Path of a blob inside an OCI layout."""
    return os.path.join(root, "blobs", "sha256", digest.split(":", 1)[1])

def read_json(root, digest):
    """Parse a JSON blob (manifest, index or config)."""
    with open(blob_path(root, digest), "rb") as f:
        return json.load(f)

def write_blob(root, data):
    """Write bytes as a blob; returns (digest, size).

    Atomically, and re-writing a blob whose size disagrees with its name:
    the layout lives in a persistent BuildKit cache, so a build
    interrupted mid-write would otherwise leave a truncated blob that
    every later build accepts because the path exists.
    """
    d = "sha256:" + hashlib.sha256(data).hexdigest()
    p = blob_path(root, d)
    if os.path.exists(p) and os.path.getsize(p) == len(data):
        return d, len(data)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(p))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, p)
    except BaseException:
        os.unlink(tmp)
        raise
    return d, len(data)

GZIP_MAGIC = b"\x1f\x8b"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def layer_magic(path):
    """First bytes of a blob, for sniffing its compression."""
    with open(path, "rb") as f:
        return f.read(4)


def is_gzip(path):
    """Whether a blob really is gzip, by magic rather than mediaType."""
    return layer_magic(path)[:2] == GZIP_MAGIC

def uncompressed_mt(mt):
    """The same media type with any gzip suffix removed."""
    for suffix in ("+gzip", ".gzip"):
        if mt.endswith(suffix):
            return mt[: -len(suffix)]
    return mt

def is_erofs_mt(mt):
    """containerd's isErofsMediaType: ends in .erofs, no +suffix."""
    base, _, has_ext = mt.partition("+")
    return not has_ext and base.endswith(".erofs")

# ---------------------------------------------------------------- erofs

def run_mkfs(args, src, magic, digest):
    """Stream a (possibly gzipped) tar layer into mkfs.erofs.

    A mkfs that exits early breaks the pipe, so the copy raises before the
    exit status is ever read. Swallow that and let the status decide, or
    the layer digest is lost from the error a parallel worker reports.
    """
    opener = gzip.open if magic[:2] == GZIP_MAGIC else open
    with opener(src, "rb") as stream, \
            subprocess.Popen(args, stdin=subprocess.PIPE) as proc:
        try:
            shutil.copyfileobj(stream, proc.stdin, length=1 << 20)
            proc.stdin.close()
        except (BrokenPipeError, OSError):
            pass
        rc = proc.wait()
        if rc != 0:
            raise RuntimeError(f"mkfs.erofs failed for {digest} (exit {rc})")


def file_digest(path):
    """sha256 of a file, as a digest string."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def convert_layer(root, digest, compression):
    """Convert one layer blob to EROFS; returns (digest, size).

    Mirrors containerd's ConvertTarErofs down to the flags and the UUID
    derivation, so the blob is what the on-device differ would have
    produced for the same layer.

    Deliberately no -T: it would pin the superblock build time (making
    the blob reproducible) at the cost of clamping every file's mtime to
    that value, changing the contents of images we don't own. Parity with
    the device's own conversion is worth more than a reproducible digest,
    and BuildKit's layer cache already skips the whole conversion when
    nothing changed.
    """
    src = blob_path(root, digest)
    u = uuid.uuid5(uuid.NAMESPACE_URL, "erofs:blobs/" + digest)
    # -b4096: mkfs.erofs otherwise takes the BUILDER's page size, and an
    # image built on a 64K-page host cannot be mounted by a 4K-page
    # kernel. These blobs cross machines, so the block size cannot be
    # left to whoever ran the build.
    args = ["mkfs.erofs", "--tar=f", "--aufs", "--quiet", "-Enoinline_data",
            "-b4096", "-U", str(u)]
    if compression != "none":
        args.append("-z" + compression)
    with tempfile.TemporaryDirectory(dir=os.path.join(root, "blobs")) as tmp:
        out = os.path.join(tmp, "layer.erofs")
        magic = layer_magic(src)
        if magic[:4] == ZSTD_MAGIC:
            # mkfs.erofs --tar reads an uncompressed tar stream, and python's
            # stdlib cannot decompress zstd before 3.14. Fail by name rather
            # than handing zstd bytes to mkfs.erofs, which reports only a
            # generic conversion error.
            raise RuntimeError(
                f"layer {digest} is zstd-compressed; only gzip and "
                "uncompressed tar layers are supported")
        run_mkfs(args + [out], src, magic, digest)
        new = file_digest(out)
        size = os.path.getsize(out)
        dst = blob_path(root, new)
        if not os.path.exists(dst) or os.path.getsize(dst) != size:
            os.replace(out, dst)
    return new, size


def collect_layers(root, desc, out):
    """Every layer descriptor reachable from an index entry."""
    mt = desc.get("mediaType", "")
    if mt.endswith("index.v1+json") or mt.endswith("manifest.list.v2+json"):
        for sub in read_json(root, desc["digest"]).get("manifests", []):
            collect_layers(root, sub, out)
        return
    for lyr in read_json(root, desc["digest"]).get("layers", []):
        if not is_erofs_mt(lyr.get("mediaType", "")):
            out.add(lyr["digest"])


def convert_all(root, digests, compression, jobs):
    """Convert unique layers in parallel; returns {old: (new, size)}.

    Layers are shared across images (Longhorn's base especially), so
    converting per unique digest and not per reference saves both build
    time and payload bytes.
    """
    converted = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {pool.submit(convert_layer, root, d, compression): d for d in sorted(digests)}
        for i, fut in enumerate(concurrent.futures.as_completed(futures), 1):
            d = futures[fut]
            converted[d] = fut.result()
            print(f"[erofs] {i}/{len(futures)} {d[:19]} -> {converted[d][1]} bytes", flush=True)
    return converted

# ------------------------------------------------------------- rewriting

def rewrite_layer(root, lyr, fmt, converted):
    """Point one layer descriptor at its rewritten blob; True if changed."""
    p = blob_path(root, lyr["digest"])
    mt = lyr.get("mediaType", "")
    if fmt == "erofs" and not is_erofs_mt(mt):
        nd, nsz = converted[lyr["digest"]]
        lyr["digest"], lyr["size"], lyr["mediaType"] = nd, nsz, EROFS_LAYER_MT
        return True
    if fmt == "uncompressed" and is_gzip(p):
        # Genuinely gzip (magic bytes): decompress to a new uncompressed
        # blob and relabel. Sniff the content, never trust the mediaType —
        # docker-save layers arrive as plain tar yet are labeled tar.gzip.
        with open(p, "rb") as f:
            raw = gzip.decompress(f.read())
        nd, nsz = write_blob(root, raw)
        lyr["digest"], lyr["size"], lyr["mediaType"] = nd, nsz, uncompressed_mt(mt)
        return True
    if fmt == "uncompressed" and "gzip" in mt:
        # Already-uncompressed tar mislabeled as gzip: fix only the
        # mediaType; the blob (and its digest/size) is already correct.
        lyr["mediaType"] = uncompressed_mt(mt)
        return True
    return False


def rewrite_manifest(root, digest, fmt, converted):
    """Rewrite one manifest's layers (and config, for erofs).

    Returns (digest, size, changed) for the manifest blob.
    """
    man = read_json(root, digest)
    changed = False
    new_diff_ids = []
    for lyr in man.get("layers", []):
        if rewrite_layer(root, lyr, fmt, converted):
            changed = True
        new_diff_ids.append(lyr["digest"])
    # A native EROFS layer applies to itself: containerd's unpacker compares
    # the differ's returned digest (the layer digest) against the config's
    # diff_id, so the config has to name the EROFS blob. In uncompressed
    # mode the diffID is unchanged by definition and the config is left
    # untouched.
    if changed and fmt == "erofs":
        cfg = read_json(root, man["config"]["digest"])
        rootfs = cfg.get("rootfs", {})
        if len(rootfs.get("diff_ids", [])) != len(new_diff_ids):
            sys.exit(f"ERROR: {digest}: {len(new_diff_ids)} layers but "
                     f"{len(rootfs.get('diff_ids', []))} diff_ids")
        rootfs["diff_ids"] = new_diff_ids
        cd, csz = write_blob(root, json.dumps(cfg, separators=(",", ":")).encode())
        man["config"]["digest"], man["config"]["size"] = cd, csz
    if not changed:
        return digest, os.path.getsize(blob_path(root, digest)), False
    data = json.dumps(man, separators=(",", ":")).encode()
    nd, nsz = write_blob(root, data)
    return nd, nsz, True


def rewrite_descriptor(root, desc, fmt, converted):
    """Returns True if desc was updated (digest/size changed)."""
    mt = desc.get("mediaType", "")
    if mt.endswith("index.v1+json") or mt.endswith("manifest.list.v2+json"):
        idx = read_json(root, desc["digest"])
        changed = False
        for sub in idx.get("manifests", []):
            if rewrite_descriptor(root, sub, fmt, converted):
                changed = True
        if not changed:
            return False
        data = json.dumps(idx, separators=(",", ":")).encode()
        nd, nsz = write_blob(root, data)
        desc["digest"], desc["size"] = nd, nsz
        return True
    nd, nsz, changed = rewrite_manifest(root, desc["digest"], fmt, converted)
    if changed:
        desc["digest"], desc["size"] = nd, nsz
    return changed

# ---------------------------------------------------------------- pruning

def reachable_digests(root, desc, out):
    """Walk a manifests-list entry (index.json descriptor or a nested one),
    collecting every digest still referenced: the descriptor's own blob,
    and — for a manifest — its config and every layer digest."""
    out.add(desc["digest"])
    mt = desc.get("mediaType", "")
    if mt.endswith("index.v1+json") or mt.endswith("manifest.list.v2+json"):
        idx = read_json(root, desc["digest"])
        for sub in idx.get("manifests", []):
            reachable_digests(root, sub, out)
        return
    man = read_json(root, desc["digest"])
    if "config" in man:
        out.add(man["config"]["digest"])
    for lyr in man.get("layers", []):
        out.add(lyr["digest"])

def prune_unreachable_blobs(root, index):
    """Delete every blob under blobs/sha256/ that index.json's manifests no
    longer reach: superseded source layers and pre-rewrite manifest/index
    blobs. Keeps the layout from shipping each layer twice."""
    live = set()
    for desc in index.get("manifests", []):
        reachable_digests(root, desc, live)
    live_hex = {d.split(":", 1)[1] for d in live}
    blobs_dir = os.path.join(root, "blobs", "sha256")
    for name in os.listdir(blobs_dir):
        if name not in live_hex:
            os.remove(os.path.join(blobs_dir, name))

def drop_nameless(index):
    """Remove index entries that carry no ref name.

    BuildKit's --mount=type=cache persists the layout across builds, and
    skopeo supersedes an existing ref by stripping the name off the old
    entry rather than removing it. kube-init addresses images by ref name,
    so a nameless entry is unreachable — but it still counts as a root in
    the prune below, which would pin a bumped image's old layers in the
    payload forever."""
    index["manifests"] = [m for m in index.get("manifests", [])
                          if m.get("annotations", {}).get(REF_ANNOTATION)]


def main(argv):
    """Rewrite every layer in a layout; returns a process exit code."""
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("layout")
    ap.add_argument("--format", dest="fmt", default="erofs",
                    choices=("erofs", "uncompressed"))
    ap.add_argument("--compression", default="none",
                    help="mkfs.erofs -z algorithm for erofs format, or 'none' "
                         "(the default: the payload ships inside the "
                         "squashfs-xz rootfs, which compresses it once)")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    ap.add_argument("--keep-unreachable", action="store_true",
                    help="do not delete blobs nothing references. For a layout "
                         "in a persistent build cache: the source tar blobs are "
                         "what lets the next build's skopeo copy reuse them "
                         "instead of re-pulling every image")
    ap.add_argument("--prune-only", action="store_true",
                    help="delete unreachable blobs and nameless index entries "
                         "and nothing else. For the copy that ships, once the "
                         "cached layout has been converted")
    a = ap.parse_args(argv)
    if a.keep_unreachable and a.prune_only:
        ap.error("--keep-unreachable and --prune-only are contradictory")

    root = a.layout
    ip = os.path.join(root, "index.json")
    with open(ip, encoding="utf-8") as f:
        index = json.load(f)
    drop_nameless(index)

    if a.prune_only:
        with open(ip, "w", encoding="utf-8") as f:
            json.dump(index, f, separators=(",", ":"))
        prune_unreachable_blobs(root, index)
        return 0

    converted = {}
    if a.fmt == "erofs":
        layers = set()
        for desc in index.get("manifests", []):
            collect_layers(root, desc, layers)
        print(f"[erofs] converting {len(layers)} unique layers on {a.jobs} workers", flush=True)
        converted = convert_all(root, layers, a.compression, a.jobs)

    for desc in index.get("manifests", []):
        rewrite_descriptor(root, desc, a.fmt, converted)  # mutates desc, preserves annotations
    with open(ip, "w", encoding="utf-8") as f:
        json.dump(index, f, separators=(",", ":"))
    if not a.keep_unreachable:
        prune_unreachable_blobs(root, index)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
