# Package dependency hash tracking

## The problem

EVE packages are built by linuxkit, which uses a **git tree hash** as the
cache key for each package. A package is rebuilt only when the hash of its
source directory changes. This is efficient, but creates a blind spot:
packages whose `Dockerfile` is **generated** (via `tools/parse-pkgs.sh` from
a `Dockerfile.in` template) and therefore **gitignored** — are invisible to
linuxkit's hash calculation.

Consider `pkg/pillar`. Its `Dockerfile.in` contains:

```dockerfile
FROM ZFS_TAG AS zfs
```

`parse-pkgs.sh` resolves `ZFS_TAG` to the real image reference and writes a
`Dockerfile` that linuxkit actually reads. But because `Dockerfile` is
gitignored, linuxkit's tree-hash for `pkg/pillar` does **not** change when
`pkg/zfs` is rebuilt with a new ZFS version. Without intervention, linuxkit
would serve `pkg/pillar` from cache even though its `zfs` stage now pulls a
different image.

The same applies to `pkg/dom0-ztools` and any other consumer of `pkg/zfs`.

### Dependency graph

```text
pkg/alpine  pkg/cross-compilers
     │              │
     └──────┬───────┘
            ▼
         pkg/zfs
            │
     ┌──────┴───────┐
     ▼              ▼
pkg/pillar   pkg/dom0-ztools
```

When `pkg/zfs` is rebuilt (e.g. because `ZFS_VERSION` changed), both
`pkg/pillar` and `pkg/dom0-ztools` must be force-rebuilt even though their
own git content is unchanged.

## The solution

The build system maintains a `.gen-deps/` directory containing one
`<pkg>.hash` file per package. Each hash file stores the linuxkit content tag
of that package (e.g. `lfedge/eve-zfs:f38bd910...-2.3`).

The mechanism has two parts:

### 1. Hash file maintenance (`get-deps -H`)

`tools/get-deps/get-deps -H -d .gen-deps` iterates all `pkg/*/build.yml`
files, computes the linuxkit tag for each package using the same git-tree
logic linuxkit itself uses (via pkglib — no Docker required), and writes
`.gen-deps/<pkg>.hash` with **write-if-changed** semantics: the file's
modification time is only updated when the tag content actually changes.

After a successful linuxkit build, the `eve-%` Makefile recipe **touches**
`.gen-deps/<pkg>.hash` to record "this package was last built at time T".
This dual use of the hash file — content = linuxkit tag, mtime = last build
time — is the basis of the freshness check.

The `EVE_PKG_BUILD_YML_<PKG>` environment variable convention allows the
Makefile to pass version-specific build yml overrides to `get-deps`. For
example, `EVE_PKG_BUILD_YML_ZFS=build-2.3.yml` ensures that `get-deps`
computes `lfedge/eve-zfs:<hash>-2.3` rather than the default `build.yml` tag.

### 2. Makefile dependency rules (`pkg-deps.mk`)

`tools/get-deps/get-deps -m -d .gen-deps pkg-deps.mk` scans all package
`Dockerfile`s, builds the dependency graph, and emits `pkg-deps.mk` — a
generated Makefile fragment included by the root `Makefile`. For each
consumer that has tracked dependencies it emits:

```makefile
# File prerequisite: Make re-runs get-deps -H before the build
# if any dep's hash file is out of date.
pkg/pillar: .gen-deps/zfs.hash
pkg/pillar: .gen-deps/alpine.hash
# ...

# Target-specific variable: passed as --force to linuxkit when any dep
# was rebuilt more recently than pillar itself.
pkg/pillar: DEPS_FORCE = $(if $(shell \
    [ -f .gen-deps/pillar.hash ] && { \
      [ .gen-deps/zfs.hash     -nt .gen-deps/pillar.hash ] || \
      [ .gen-deps/alpine.hash  -nt .gen-deps/pillar.hash ]; \
    } 2>/dev/null && echo y),--force,)
```

The `[ -f .gen-deps/pillar.hash ]` guard ensures that `DEPS_FORCE` is never
set on the very first build — linuxkit's own cache miss handles that case.

### Flow for a ZFS version bump

1. Developer updates `ZFS_VERSION` in `kernel-version.mk`.
2. `make pkg/zfs` rebuilds the ZFS image; `eve-zfs` recipe touches
   `.gen-deps/zfs.hash` (new mtime).
3. `make pkg/pillar`:
   - `.gen-deps/pillar.hash` is a prerequisite → `get-deps -H` runs,
     computes the new `zfs` tag, updates `.gen-deps/zfs.hash` content.
   - `DEPS_FORCE` evaluates: `zfs.hash` is newer than `pillar.hash`
     → expands to `--force`.
   - linuxkit runs with `--force`, bypasses its cache, rebuilds `pkg/pillar`.
   - `eve-pillar` recipe touches `.gen-deps/pillar.hash`.
4. Next `make pkg/pillar`: `pillar.hash` is now newer than `zfs.hash`
   → `DEPS_FORCE` is empty → linuxkit cache hit → no rebuild.

## Files

| Path | Description |
| --- | --- |
| `tools/get-deps/` | `get-deps` tool source |
| `.gen-deps/<pkg>.hash` | Per-package hash file (gitignored) |
| `pkg-deps.mk` | Generated Makefile fragment (gitignored) |
| `kernel-version.mk` | `ZFS_VERSION` and other version pins |

## Adding a new version-driven package

1. Add `pkg/<name>/build-<version>.yml` with a `tag: "{{.Hash}}-<version>"`
   field.
2. In `Makefile`, add:

   ```makefile
   EVE_PKG_BUILD_YML_<NAME> := build-<version>.yml
   export EVE_PKG_BUILD_YML_<NAME_UPPERCASE> := $(EVE_PKG_BUILD_YML_<NAME>)
   ```

3. Consumers reference the package via `FROM <NAME>_TAG` in their
   `Dockerfile.in`; `parse-pkgs.sh` resolves the tag automatically.
