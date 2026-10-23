# eve-build-diff

Compares two EVE rootfs builds, typically a release and a rebuild of its tag. It
reports each difference as FLAGGED when a rule in `known-diffs.toml` explains it,
and as ERROR otherwise.

```sh
./eve-build-diff.py RELEASE BUILD            # exit 0: only known differences
./eve-build-diff.py -q A B                   # errors and the summary only
./eve-build-diff.py -v --json out.json A B   # every flagged entry, plus JSON
```

Each input can be one of:

- a `rootfs.img` (squashfs);
- an extracted directory;
- `docker:lfedge/eve@sha256:<digest>`, from which the file named by the
  `org.lfedge.eci.artifact.root` label (`/bits/rootfs.img`) is copied with
  `docker create` and `docker cp`. The image is never run, and a reference
  without a digest is a usage error.

Exit status:

- 0: only flagged differences;
- 1: at least one error;
- 2: bad usage, or an input that cannot be compared.

The tool needs `unsquashfs` and Python 3.11 or later. It does not need root.

## Uses

- **Release gate.** Compare the release image, by the digest that is signed,
  with a rebuild of its tag made on separate infrastructure:

  ```sh
  ./eve-build-diff.py --json report.json \
      docker:lfedge/eve@sha256:<digest> rebuild/rootfs.img
  ```

  The release is attacker-controlled input. Run the tool and
  `known-diffs.toml` from a pinned, reviewed `master` commit, never from the
  tag under test, in a disposable VM without credentials. The report prints
  the sha256 of both (`tool_sha256` and `rules_sha256` in the JSON) so the
  approver can check which ones ran.

  `release-rebuild/release-rebuild.sh` does all of this for a draft release.
  It takes one line of the draft listing in `docs/SIGNING.md` and rebuilds
  the tag in a fresh Multipass VM. It refuses a build user or checkout whose
  group or mode would differ from the release runners, and compares the
  rebuild with the `eve` digest in the draft's `images.txt`:

  ```sh
  release-rebuild/release-rebuild.sh run <tag> <release-id> <release-url>
  ```

  Exit 0 and a `RESULT: every target matches` line mean every difference is
  known. Two tests run everything but the build. `FAKE_BUILD=1` uses the
  release's own rootfs as the rebuild, and must exit 0.
  `release-rebuild/make-test-env.sh` loads a finished build into a VM for
  `release-rebuild.sh finish`. Both label their RESULT `TEST ENV, NOT
  APPROVABLE`.
- **Kernel view of the release.** `unsquashfs` and the kernel are two squashfs
  parsers. To compare what a device's kernel sees, mount the release image
  read-only in the VM, with a kernel close to EVE's, and pass the mount point:

  ```sh
  mount -o loop,ro rootfs.img /mnt/a
  ./eve-build-diff.py /mnt/a rebuild/rootfs.img
  ```

  Run this as root so owners, device nodes and extended attributes read
  correctly.
- **Audit of a published release.** Rebuild an older tag and compare it with
  the published `rootfs.img`. Errors show what is not reproducible or not yet
  covered by a rule.
- **Reproducibility work.** Compare two builds of the same commit; `-v` lists
  every flagged entry and `--workdir` keeps the extracted trees.
- **Rule changes.** After changing `known-diffs.toml`, run both control
  scripts (below); every mutation must still be an error.

## What is compared

- **Entry set:** every path in both trees. A path present on only one side is
  an error.
- **Metadata:** type, mode, uid, gid, device number and symlink target, and
  extended attributes for directory inputs. For squashfs inputs these come
  from `unsquashfs -lln`, so device nodes are compared without root. A
  squashfs image that stores any extended attributes is an error, since the
  listing does not show them. Modification times are not compared.
- **Names:** a name containing a control character is an error, as is a
  listing that does not match the extracted tree; `unsquashfs` prints names
  unescaped, so a name with a newline would otherwise hide a file.
- **Regular files:** byte content.

## Rules

A rule applies to the paths that match its `paths` globs, in which `*` and `?`
stay within one path segment and `**` crosses segments. Its checker must confirm that nothing else differs. A rule that
matches a path but fails its check falls through to the next rule, and finally
to an ERROR that names the rules it tried. An entry present in one tree only is
an ERROR unless a rule with `one_sided = true` matches it and, when the rule
has a checker, the entry is a regular file that the checker accepts.

| Kind | Explains |
|---|---|
| `go-build-version` | Go binaries whose only difference is `-X main.Version` (the build commit) plus the Go and GNU build IDs. Checked by substituting the version and blanking the notes. With `trailing_space`, A's version may end in a space (linuxkit before v1.8.1): the sections must realign after it, with one padding byte per shortened string. A byte may be one lower in B only as the length of a string holding the version: a Go string header's `len` in `.data` or `.noptrdata` whose pointer addresses it, or the varint before the module info in `.go.buildinfo`. |
| `volatile-strings` | Byte differences confined to `patterns` matches at the same offset, plus GNU build-ID notes; `decompress = "gzip"` checks the uncompressed stream. In an ELF file the matches must lie in non-executable sections unless `code_sections = true` (Xen, whose compile date is in `.text`). |
| `cpio-metadata` | newc archives (gzip or not) with identical member names, order and content; allowed `fields` and `mode_mask` may differ, with uid and gid values within `uids` and `gids` when given |
| `apk-db` | `lib/apk/db/installed` records with the same packages, differing only in `fields` (default `C`, `S`, `t`). A record without exactly one `P:` line, or a repeated package, is an error. |
| `tar-metadata` | tar archives with identical member names, order and content; only `fields` (default `mtime`) may differ |
| `pem-public-key` | Two PEM public keys (any key) |
| `line-subst` | Line-for-line equality after masking `patterns`. Capturing groups are kept, so they must still match. |
| `line-set` | The same lines in a different order |
| `known-variant` | Pairs of sha256 sums observed as equivalent builds |
| `spdx` | SPDX SBOMs that are equal after IDs, namespace, creation time and order are ignored, and after build-commit versions are substituted. A file checksum may differ only where the file itself differs. `allow_cpe_drift`, `allow_layer_comment`, `allow_relationship_drift`, `allow_additions` (B may list more packages and files) and `older_syft` (Go purls as `module#subpath`, zero SHA1 for empty files) relax the linuxkit SBOM. |
| `metadata` | Mode bits within `mode_mask`, uids in `uids` and gids in `gids` |

The rules in `known-diffs.toml` cover the differences between 16.0.2-lts and
17.0.0-lts and rebuilds of them that force-built every package except
eve-alpine, except one: in 17.0.0-lts, `vector`'s vendored OpenSSL build date
moved within mold's merged strings, which changes references that cannot be
checked without relocations, so it is an error until that build is
reproducible.

`tests/positive-controls.py` mutates a copy of an extracted build in 27 ways
the rules must not explain, and checks that each is reported as an error.
`tests/input-controls.py` builds small squashfs images, trees and an ELF
binary, and uses a `docker` stub, to check names with a newline, extended
attributes, that `docker:` inputs need a digest and are never run, that a glob
does not reach below its path segment, and that volatile strings are not
accepted in code. It needs `mksquashfs` and `gcc`. Both take another
tool and rules file as optional arguments, to show that a control fails
against them.
