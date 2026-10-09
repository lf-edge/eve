# EVE's QEMU patches

Plain `git format-patch` files against the QEMU release named by `QEMU_VERSION`
in `../Dockerfile`, applied in file-name order with `patch -p1 --fuzz=0`. A patch
that does not apply exactly fails the build.

## Classes

The number range says where a patch stands upstream, and each patch says the same
in an `Upstream-Status:` line, in the format OpenEmbedded uses:

| Range | Class | `Upstream-Status:` | At the next QEMU update |
|---|---|---|---|
| `0xxx` | backport of an upstream commit | `Backport [<commit>]` | drop it if the new release has the commit |
| `1xxx` | meant for upstream | `Submitted [<link>]` or `Pending` | drop it if it was merged, otherwise rebase it |
| `9xxx` | EVE only | `Inappropriate [<reason>]` | rebase it |

Backports also carry git's `(cherry picked from commit <commit>)` line. When a
`1xxx` patch is merged upstream, it becomes a `0xxx` backport until a release
includes it.

## Changing a patch

Keep the patches as a branch on top of the release tag in a QEMU git tree, in
class order, and regenerate the files from it one class at a time:

```sh
git format-patch --zero-commit -N --no-signature --start-number 1    -o <dir> <tag>..<last 0xxx>
git format-patch --zero-commit -N --no-signature --start-number 1001 -o <dir> <last 0xxx>..<last 1xxx>
git format-patch --zero-commit -N --no-signature --start-number 9001 -o <dir> <last 1xxx>..HEAD
```

With no backports, `<last 0xxx>` is the release tag.
