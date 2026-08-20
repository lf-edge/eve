# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for pkg/kube-images/oci-rewrite-layers.py.

Builds a tiny OCI image layout fixture (a docker-schema2 manifest, an oci
manifest wrapped in an image-index, and a docker-schema2 manifest wrapped
in a docker manifest-list, to exercise both recursion paths), runs the
tool against it, and checks the post-run invariants: gzip layers become
uncompressed tar, layer digests match their on-disk content AND equal the
true uncompressed-content digest (diffID), ref-name annotations survive,
and the config blob is never rewritten in uncompressed mode.

The erofs-format tests cover the other path: layers become ready-made
EROFS filesystems the device places instead of converting, which is only
correct if the config's diff_ids follow them.
"""
import gzip
import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest

TOOL = os.path.join(os.path.dirname(__file__), "..", "..",
                    "pkg", "kube-images", "oci-rewrite-layers.py")


def sha(data):
    """Digest string of some bytes."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def read_bytes(path):
    """Whole file as bytes."""
    with open(path, "rb") as fobj:
        return fobj.read()


def read_blob_json(root, digest):
    """Parse a blob as JSON."""
    return json.loads(read_bytes(os.path.join(root, "blobs", "sha256", digest.split(":")[1])))


def write_blob(root, data):
    """Write a blob; returns (digest, size)."""
    hexdigest = sha(data)
    with open(os.path.join(root, "blobs", "sha256", hexdigest.split(":")[1]), "wb") as fobj:
        fobj.write(data)
    return hexdigest, len(data)


FIXTURE_MTIME = 1234567890  # a real timestamp: the conversion must keep it


def tar_bytes():
    """A one-file tar stream carrying a real mtime."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        data = b"hello"
        info = tarfile.TarInfo("f")
        info.size = len(data)
        info.mtime = FIXTURE_MTIME
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def make_image(root, manifest_mt, layer_mt):
    """Add one gzip-layer image; returns its digests for later comparison."""
    raw = tar_bytes()
    gzipped = gzip.compress(raw, mtime=0)  # header mtime would make the digest vary per run
    ldig, lsz = write_blob(root, gzipped)
    diffid = sha(raw)  # config records the UNCOMPRESSED digest
    cfg = json.dumps({"rootfs": {"type": "layers", "diff_ids": [diffid]}}).encode()
    cdig, csz = write_blob(root, cfg)
    man = json.dumps({
        "schemaVersion": 2, "mediaType": manifest_mt,
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                   "digest": cdig, "size": csz},
        "layers": [{"mediaType": layer_mt, "digest": ldig, "size": lsz}],
    }).encode()
    mdig, msz = write_blob(root, man)
    return {"manifest_digest": mdig, "manifest_size": msz,
            "diff_id": diffid, "config_digest": cdig}


def build_compressible_fixture(root, nbytes=1 << 20):  # pylint: disable=too-many-locals
    """A one-image layout whose single layer holds very compressible bytes."""
    os.makedirs(os.path.join(root, "blobs", "sha256"))
    with open(os.path.join(root, "oci-layout"), "w", encoding="utf-8") as fobj:
        fobj.write('{"imageLayoutVersion":"1.0.0"}')

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        data = b"compress me " * (nbytes // 12)
        info = tarfile.TarInfo("big")
        info.size = len(data)
        info.mtime = FIXTURE_MTIME
        tar.addfile(info, io.BytesIO(data))
    raw = buf.getvalue()
    ldig, lsz = write_blob(root, gzip.compress(raw, mtime=0))
    cfg = json.dumps({"rootfs": {"type": "layers", "diff_ids": [sha(raw)]}}).encode()
    cdig, csz = write_blob(root, cfg)
    o_mt = "application/vnd.oci.image.manifest.v1+json"
    man = json.dumps({
        "schemaVersion": 2, "mediaType": o_mt,
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                   "digest": cdig, "size": csz},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": ldig, "size": lsz}],
    }).encode()
    mdig, msz = write_blob(root, man)
    with open(os.path.join(root, "index.json"), "w", encoding="utf-8") as fobj:
        json.dump({"schemaVersion": 2, "manifests": [
            {"mediaType": o_mt, "digest": mdig, "size": msz,
             "annotations": {"org.opencontainers.image.ref.name": "big"}}]}, fobj)


def build_fixture(root):  # pylint: disable=too-many-locals
    """Build a tiny OCI layout: one docker-schema2 manifest, one oci
    manifest wrapped in an image index (recursion), and one docker-schema2
    manifest wrapped in a docker manifest list (the other recursion path).
    Returns, per leaf manifest keyed by its ref.name annotation, the
    pre-tool config digest (must never change) and the true uncompressed
    layer digest (diffID) that the layer must equal after the tool runs."""
    os.makedirs(os.path.join(root, "blobs", "sha256"))
    with open(os.path.join(root, "oci-layout"), "w", encoding="utf-8") as fobj:
        fobj.write('{"imageLayoutVersion":"1.0.0"}')

    d_mt = "application/vnd.docker.distribution.manifest.v2+json"
    d_lmt = "application/vnd.docker.image.rootfs.diff.tar.gzip"
    o_mt = "application/vnd.oci.image.manifest.v1+json"
    o_lmt = "application/vnd.oci.image.layer.v1.tar+gzip"

    docker_img = make_image(root, d_mt, d_lmt)
    oci_img = make_image(root, o_mt, o_lmt)
    listed_img = make_image(root, d_mt, d_lmt)

    idxb = json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{"mediaType": o_mt, "digest": oci_img["manifest_digest"],
                       "size": oci_img["manifest_size"],
                       "platform": {"os": "linux", "architecture": "amd64"}}],
    }).encode()
    idig, isz = write_blob(root, idxb)

    dlistb = json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
        "manifests": [{"mediaType": d_mt, "digest": listed_img["manifest_digest"],
                       "size": listed_img["manifest_size"],
                       "platform": {"os": "linux", "architecture": "amd64"}}],
    }).encode()
    dlistdig, dlistsz = write_blob(root, dlistb)

    index = {"schemaVersion": 2, "manifests": [
        {"mediaType": d_mt, "digest": docker_img["manifest_digest"],
         "size": docker_img["manifest_size"],
         "annotations": {"org.opencontainers.image.ref.name": "reg_a"}},
        {"mediaType": "application/vnd.oci.image.index.v1+json",
         "digest": idig, "size": isz,
         "annotations": {"org.opencontainers.image.ref.name": "reg_b"}},
        {"mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
         "digest": dlistdig, "size": dlistsz,
         "annotations": {"org.opencontainers.image.ref.name": "reg_c"}},
    ]}
    with open(os.path.join(root, "index.json"), "w", encoding="utf-8") as fobj:
        json.dump(index, fobj)

    # Config digests and diffIDs recorded BEFORE the tool ever runs: the
    # config digest must never change (config blob is never rewritten),
    # and the diffID is the true uncompressed-content digest each layer
    # must equal after decompression.
    return {
        "reg_a": {"config_digest": docker_img["config_digest"], "diff_id": docker_img["diff_id"]},
        "reg_b": {"config_digest": oci_img["config_digest"], "diff_id": oci_img["diff_id"]},
        "reg_c": {"config_digest": listed_img["config_digest"], "diff_id": listed_img["diff_id"]},
    }


class TestUncompressedFormat(unittest.TestCase):
    """The tar path: gzip layers are decompressed and relabelled."""
    def test_decompress_docker_and_oci_and_index(self):
        """Every recursion path yields uncompressed layers matching their diffIDs."""
        with tempfile.TemporaryDirectory() as root:
            pre_info = build_fixture(root)

            subprocess.run(["python3", TOOL, root, "--format", "uncompressed"], check=True)

            idx = json.loads(read_bytes(os.path.join(root, "index.json")))
            ann = "org.opencontainers.image.ref.name"
            names = {entry["annotations"][ann] for entry in idx["manifests"]}
            self.assertEqual(names, {"reg_a", "reg_b", "reg_c"})  # ref-names preserved

            def check(mdesc, ref_name):
                man = read_blob_json(root, mdesc["digest"])
                expected_diffid = pre_info[ref_name]["diff_id"]
                for lyr in man["layers"]:
                    # every layer is now uncompressed tar ...
                    self.assertNotIn("gzip", lyr["mediaType"])
                    # ... and its on-disk content actually hashes to its digest
                    blob = read_bytes(os.path.join(root, "blobs", "sha256",
                                                    lyr["digest"].split(":")[1]))
                    self.assertEqual(sha(blob), lyr["digest"])
                    # ... and that digest is the TRUE uncompressed-content
                    # digest (diffID), not merely self-consistent: a bug that
                    # decompressed to the wrong (but internally consistent)
                    # bytes must fail this.
                    self.assertEqual(lyr["digest"], expected_diffid)
                # The config blob is never rewritten: the digest recorded
                # before the tool ran must be exactly what the manifest
                # still points at.
                self.assertEqual(man["config"]["digest"], pre_info[ref_name]["config_digest"])

            for entry in idx["manifests"]:
                ref_name = entry["annotations"]["org.opencontainers.image.ref.name"]
                if (entry["mediaType"].endswith("index.v1+json")
                        or entry["mediaType"].endswith("manifest.list.v2+json")):
                    sub = read_blob_json(root, entry["digest"])
                    for sub_entry in sub["manifests"]:
                        check(sub_entry, ref_name)
                else:
                    check(entry, ref_name)

    def test_drops_nameless_entries_and_their_blobs(self):
        """Index entries without a ref name are dropped, and their blobs with them."""
        # BuildKit's persistent /oci-cache + skopeo's "strip the old name"
        # supersede behaviour leaves nameless index entries behind. They
        # can't be registered (kube-init keys on the ref name) and they
        # keep the superseded image's blobs reachable, so a bumped upstream
        # image would ship both versions' layers forever.
        with tempfile.TemporaryDirectory() as root:
            build_fixture(root)
            idx = json.loads(read_bytes(os.path.join(root, "index.json")))
            stale = dict(idx["manifests"][0])
            stale.pop("annotations")
            stale_man = read_blob_json(root, stale["digest"])
            idx["manifests"].append(stale)
            with open(os.path.join(root, "index.json"), "w", encoding="utf-8") as fobj:
                json.dump(idx, fobj)

            subprocess.run(["python3", TOOL, root, "--format", "uncompressed"], check=True)

            out = json.loads(read_bytes(os.path.join(root, "index.json")))
            self.assertEqual(len(out["manifests"]), 3)
            self.assertTrue(all(entry.get("annotations", {}).get(
                "org.opencontainers.image.ref.name") for entry in out["manifests"]))
            # the nameless entry's gzip layer is gone, not merely unlisted
            gone = os.path.join(root, "blobs", "sha256",
                                stale_man["layers"][0]["digest"].split(":")[1])
            self.assertFalse(os.path.exists(gone))

    def test_prunes_orphaned_blobs(self):
        """Blobs nothing references are removed."""
        # The tool writes new (uncompressed) layer blobs and new manifest/
        # index blobs alongside the originals it supersedes. Without a
        # prune step every layer would ship twice (gzip + tar) in the
        # final erofs image. Assert the original gzip layer blobs are gone
        # and that nothing left under blobs/sha256/ is orphaned.
        with tempfile.TemporaryDirectory() as root:
            build_fixture(root)
            # collect the pre-run gzip layer blob names by reading index.json
            # before the tool mutates it
            index_path = os.path.join(root, "index.json")
            blobs_dir = os.path.join(root, "blobs", "sha256")
            pre_index = json.loads(read_bytes(index_path))
            pre_gzip_blob_names = set()

            def collect_gzip_layers(desc):
                man_or_idx = read_blob_json(root, desc["digest"])
                media_type = desc["mediaType"]
                if (media_type.endswith("index.v1+json")
                        or media_type.endswith("manifest.list.v2+json")):
                    for sub in man_or_idx["manifests"]:
                        collect_gzip_layers(sub)
                    return
                for lyr in man_or_idx.get("layers", []):
                    if "gzip" in lyr["mediaType"]:
                        pre_gzip_blob_names.add(lyr["digest"].split(":")[1])

            for entry in pre_index["manifests"]:
                collect_gzip_layers(entry)
            self.assertTrue(pre_gzip_blob_names, "fixture must contain gzip layers")

            subprocess.run(["python3", TOOL, root, "--format", "uncompressed"], check=True)

            # (a) the original gzip layer blobs no longer exist on disk
            remaining = set(os.listdir(blobs_dir))
            for name in pre_gzip_blob_names:
                self.assertNotIn(name, remaining,
                                  f"orphaned gzip layer blob {name} was not pruned")

            # (data) every file remaining under blobs/sha256/ is reachable from
            # the post-run index.json (no orphans of any kind: superseded
            # manifest/index blobs must be gone too).
            post_index = json.loads(read_bytes(index_path))
            reachable = set()

            def walk(desc):
                hexdigest = desc["digest"].split(":")[1]
                reachable.add(hexdigest)
                man_or_idx = read_blob_json(root, desc["digest"])
                media_type = desc["mediaType"]
                if (media_type.endswith("index.v1+json")
                        or media_type.endswith("manifest.list.v2+json")):
                    for sub in man_or_idx["manifests"]:
                        walk(sub)
                    return
                reachable.add(man_or_idx["config"]["digest"].split(":")[1])
                for lyr in man_or_idx.get("layers", []):
                    reachable.add(lyr["digest"].split(":")[1])

            for entry in post_index["manifests"]:
                walk(entry)

            on_disk = set(os.listdir(blobs_dir))
            self.assertEqual(on_disk, reachable,
                              "blobs/sha256/ contains orphaned or missing files")

    def test_idempotent(self):
        """A second run over a converted layout changes nothing."""
        # Running the tool twice on the same layout must be a no-op the
        # second time: no gzip layers remain after the first run, so
        # index.json and every blob it (transitively) references must come
        # out byte-for-byte identical after the second run.
        with tempfile.TemporaryDirectory() as root:
            build_fixture(root)

            subprocess.run(["python3", TOOL, root, "--format", "uncompressed"], check=True)
            index_path = os.path.join(root, "index.json")
            blobs_dir = os.path.join(root, "blobs", "sha256")

            index_after_first = read_bytes(index_path)
            blobs_after_first = {
                name: read_bytes(os.path.join(blobs_dir, name))
                for name in os.listdir(blobs_dir)
            }

            subprocess.run(["python3", TOOL, root, "--format", "uncompressed"], check=True)

            index_after_second = read_bytes(index_path)
            blobs_after_second = {
                name: read_bytes(os.path.join(blobs_dir, name))
                for name in os.listdir(blobs_dir)
            }

            self.assertEqual(index_after_first, index_after_second)
            self.assertEqual(blobs_after_first, blobs_after_second)

    def test_mislabeled_uncompressed_layer(self):  # pylint: disable=too-many-locals
        """A plain tar labelled tar.gzip has its label fixed and its blob left alone."""
        # docker-save layers arrive as plain tar but are labeled tar.gzip.
        # The tool must sniff the content (not trust the mediaType): leave
        # the already-uncompressed blob untouched and only fix the label.
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "blobs", "sha256"))
            with open(os.path.join(root, "oci-layout"), "w", encoding="utf-8") as fobj:
                fobj.write('{"imageLayoutVersion":"1.0.0"}')
            raw = tar_bytes()  # NOT gzipped
            ldig, lsz = write_blob(root, raw)
            cfg = json.dumps({"rootfs": {"type": "layers", "diff_ids": [ldig]}}).encode()
            cdig, csz = write_blob(root, cfg)
            d_mt = "application/vnd.docker.distribution.manifest.v2+json"
            man = json.dumps({
                "schemaVersion": 2, "mediaType": d_mt,
                "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                           "digest": cdig, "size": csz},
                # mislabeled: content is plain tar, mediaType says gzip
                "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                            "digest": ldig, "size": lsz}],
            }).encode()
            mdig, msz = write_blob(root, man)
            with open(os.path.join(root, "index.json"), "w", encoding="utf-8") as fobj:
                json.dump({"schemaVersion": 2, "manifests": [
                    {"mediaType": d_mt, "digest": mdig, "size": msz,
                     "annotations": {"org.opencontainers.image.ref.name": "reg"}}]}, fobj)

            # must not crash
            subprocess.run(["python3", TOOL, root, "--format", "uncompressed"],
                           check=True)

            with open(os.path.join(root, "index.json"), encoding="utf-8") as fobj:
                idx = json.load(fobj)
            man2 = read_blob_json(root, idx["manifests"][0]["digest"])
            lyr = man2["layers"][0]
            self.assertNotIn("gzip", lyr["mediaType"])   # label fixed
            self.assertEqual(lyr["digest"], ldig)         # blob NOT decompressed
            self.assertEqual(lyr["size"], lsz)



class TestErofsFormat(unittest.TestCase):
    """The default format: layers arrive as ready-made EROFS filesystems."""

    EROFS_MAGIC = b"\xe2\xe1\xf5\xe0"  # at offset 1024

    def convert(self, root, *extra):
        """Run the tool over a layout."""
        subprocess.run(["python3", TOOL, root, *extra],
                       check=True, capture_output=True)

    def leaf_manifests(self, root):
        """Every leaf manifest in the layout, following both list types."""
        out = []

        def walk(desc):
            doc = read_blob_json(root, desc["digest"])
            if (desc["mediaType"].endswith("index.v1+json")
                    or desc["mediaType"].endswith("manifest.list.v2+json")):
                for sub in doc["manifests"]:
                    walk(sub)
            else:
                out.append(doc)

        for entry in json.loads(read_bytes(os.path.join(root, "index.json")))["manifests"]:
            walk(entry)
        return out

    def test_layers_become_native_erofs_and_config_follows(self):
        """Layers become native erofs and the config diff_ids follow them."""
        with tempfile.TemporaryDirectory() as root:
            build_fixture(root)
            self.convert(root)

            for man in self.leaf_manifests(root):
                layer = man["layers"][0]
                self.assertEqual(layer["mediaType"],
                                 "application/vnd.oci.image.layer.v1.erofs")
                blob = read_bytes(os.path.join(root, "blobs", "sha256",
                                               layer["digest"].split(":")[1]))
                # a real EROFS image whose digest/size describe it
                self.assertEqual(blob[1024:1028], self.EROFS_MAGIC)
                self.assertEqual(sha(blob), layer["digest"])
                self.assertEqual(len(blob), layer["size"])
                # containerd's unpacker compares the applied digest (for a
                # native layer, the layer digest) to the config's diff_id
                cfg = read_blob_json(root, man["config"]["digest"])
                self.assertEqual(cfg["rootfs"]["diff_ids"], [layer["digest"]])

    def test_layers_are_uncompressed_by_default(self):
        """The default leaves layers uncompressed, letting the rootfs compress them."""
        # The payload is read through the squashfs-xz rootfs, so compressing
        # a layer here compresses twice: xz cannot compress lz4hc output
        # (the rootfs grows) and every read pays two decompressions instead
        # of one. Compression stays available for a payload that would ship
        # outside the rootfs, where the reasoning inverts.
        size = {}
        for name, extra in (("default", ()), ("lz4hc", ("--compression", "lz4hc"))):
            with tempfile.TemporaryDirectory() as root:
                build_compressible_fixture(root)
                self.convert(root, *extra)
                layer = self.leaf_manifests(root)[0]["layers"][0]
                blob = read_bytes(os.path.join(root, "blobs", "sha256",
                                               layer["digest"].split(":")[1]))
                self.assertEqual(blob[1024:1028], self.EROFS_MAGIC)
                self.assertEqual(len(blob), layer["size"])
                size[name] = len(blob)
        self.assertGreater(size["default"], 2 * size["lz4hc"])

    def test_shared_layers_convert_once(self):
        """Identical layers converge on one blob."""
        with tempfile.TemporaryDirectory() as root:
            build_fixture(root)
            self.convert(root)
            # the fixture's three images are built from identical content, so
            # a per-unique-digest conversion must land them on one blob
            digests = {entry["layers"][0]["digest"] for entry in self.leaf_manifests(root)}
            self.assertEqual(len(digests), 1)

    def test_file_mtimes_survive_conversion(self):
        """Conversion does not rewrite the mtimes of images we do not own."""
        # The conversion must not change what the image contains. mkfs.erofs
        # can pin its superblock time with -T, which would make the blob
        # reproducible, but that clamps every file's mtime to the same value
        # -- a content change to images we don't own. Parity with the
        # device's own conversion wins; the blob is simply not reproducible.
        with tempfile.TemporaryDirectory() as root:
            build_fixture(root)
            self.convert(root)
            man = self.leaf_manifests(root)[0]
            img = os.path.join(root, "layer.erofs")
            with open(img, "wb") as fobj:
                fobj.write(read_bytes(os.path.join(root, "blobs", "sha256",
                                                man["layers"][0]["digest"].split(":")[1])))
            out = os.path.join(root, "extracted")
            subprocess.run(["fsck.erofs", "--extract=" + out, "--preserve-perms", img],
                           check=True, capture_output=True)
            self.assertEqual(int(os.stat(os.path.join(out, "f")).st_mtime), FIXTURE_MTIME)

    def test_existing_erofs_layers_are_left_alone(self):
        """An already-native layer is not converted again."""
        with tempfile.TemporaryDirectory() as root:
            build_fixture(root)
            self.convert(root)
            before = self.leaf_manifests(root)[0]["layers"][0]["digest"]
            self.convert(root)  # a second pass must be a no-op, not a re-wrap
            after = self.leaf_manifests(root)[0]["layers"][0]["digest"]
            self.assertEqual(before, after)

    def test_zstd_layer_fails_by_name(self):
        """zstd is refused by name rather than handed to mkfs.erofs."""
        # mkfs.erofs would report only a generic conversion error, so the
        # unsupported compression must be named before it gets that far.
        with tempfile.TemporaryDirectory() as root:
            build_fixture(root)
            man = self.leaf_manifests(root)[0]
            blob = os.path.join(root, "blobs", "sha256",
                                man["layers"][0]["digest"].split(":")[1])
            with open(blob, "wb") as fobj:
                fobj.write(b"\x28\xb5\x2f\xfd" + b"\x00" * 64)  # zstd magic
            proc = subprocess.run(["python3", TOOL, root], check=False,
                                  capture_output=True, text=True)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("zstd", proc.stderr)

    def test_keep_unreachable_preserves_the_source_tars(self):
        """--keep-unreachable leaves the tar blobs skopeo reuses next build."""
        with tempfile.TemporaryDirectory() as root:
            build_fixture(root)
            before = set(os.listdir(os.path.join(root, "blobs", "sha256")))
            self.convert(root, "--keep-unreachable")
            after = set(os.listdir(os.path.join(root, "blobs", "sha256")))
            if not before <= after:
                self.fail(f"pruned {before - after} despite --keep-unreachable")
            # and the converted layers were still added
            self.assertGreater(len(after), len(before))

    def test_prune_only_drops_them_without_converting(self):
        """--prune-only cleans the shipped copy and converts nothing."""
        with tempfile.TemporaryDirectory() as root:
            build_fixture(root)
            self.convert(root, "--keep-unreachable")
            layers = {entry["layers"][0]["digest"]
                      for entry in self.leaf_manifests(root)}
            self.convert(root, "--prune-only")
            after = {"sha256:" + h
                     for h in os.listdir(os.path.join(root, "blobs", "sha256"))}
            self.assertTrue(layers <= after, "prune-only removed a live layer")
            for entry in self.leaf_manifests(root):
                self.assertEqual(entry["layers"][0]["mediaType"],
                                 "application/vnd.oci.image.layer.v1.erofs")

    def test_source_blobs_are_pruned(self):
        """The tar blobs a conversion replaces do not stay in the layout."""
        with tempfile.TemporaryDirectory() as root:
            build_fixture(root)
            pre = {entry["layers"][0]["digest"].split(":")[1]
                   for entry in self.leaf_manifests(root)}
            self.convert(root)
            remaining = set(os.listdir(os.path.join(root, "blobs", "sha256")))
            self.assertFalse(pre & remaining, "source layer blobs were not pruned")

if __name__ == "__main__":
    unittest.main()
