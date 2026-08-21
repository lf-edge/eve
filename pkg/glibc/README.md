# eve-glibc

This package installs the GNU C library (glibc) and its runtime companion
`libgcc-s1` into a directory tree that gets layered into the EVE rootfs
**alongside** the existing Alpine/musl userland. It is an init-style
linuxkit package (no `config:` section in `build.yml`) -- it contributes
files to the rootfs, it does not run as a service.

The files are harvested unmodified from a stock `ubuntu:24.04` image,
pinned by digest (it already has `libc6` and `libgcc-s1` installed), using
`dpkg -L libc6 libgcc-s1`, filtered down to regular files and symlinks
(package-owned directories are skipped), and excluding anything under
`/usr/share` (docs, locales, man pages) to keep the package small. See
the `Dockerfile` for the exact selection logic.

## Why this is needed

EVE's host rootfs is Alpine-based and links against musl libc. NVIDIA's
host-side tooling (`nvidia-ctk`, `nvidia-smi`, `nvidia-persistenced`,
etc.) is distributed as glibc-linked Ubuntu binaries. Those binaries
cannot run against musl, so a glibc runtime has to be present on the
device for them to work at all.

Its only consumer today is the ai-generic variant of `pkg/nvidia`, and
only `PLATFORM=ai-generic` images include it. Any later package that ships
glibc binaries can reuse it rather than bundling its own C runtime.

## Why glibc and musl can coexist without conflict

Installing a second libc into the same rootfs sounds risky, but glibc
and musl do not collide, for a few independent reasons:

- **Different ELF interpreters.** A glibc binary's `PT_INTERP` points at
  `/lib64/ld-linux-x86-64.so.2`; a musl binary's points at
  `/lib/ld-musl-x86_64.so.1`. Each binary carries its own loader path,
  baked in at link time -- there is no shared/ambiguous interpreter to
  fight over.
- **Different sonames.** glibc's C library is `libc.so.6`; musl's is
  `libc.musl-x86_64.so.1`. They are never the same file, and nothing
  resolves one name to the other.
- **Different library directories.** The harvested glibc libraries live
  under `/usr/lib/x86_64-linux-gnu/`, and the loader under `/usr/lib64/`
  (reached through a `/lib64` symlink) -- directories Alpine's toolchain
  and package set never populate or search.
- **Different cache/lookup mechanisms.** glibc's loader consults
  `/etc/ld.so.cache` (built here at image build time via
  `ldconfig -r /staging`); musl's loader consults
  `/etc/ld-musl-x86_64.path`. Each loader only ever reads its own
  mechanism.

Because each binary's `PT_INTERP` is an absolute path resolved once at
link time, a glibc binary always finds glibc's loader and a musl binary
always finds musl's -- automatically, with no wrapper script, `chroot`,
or `LD_PRELOAD` trick required to keep the two apart.

## Scope: amd64 only, for now

This package currently only populates content on `amd64`. The harvested
paths bake in the Debian/Ubuntu multiarch triplet
(`x86_64-linux-gnu`), which is x86_64-specific by construction. On
`arm64`/`riscv64` the package builds but stages nothing (see the
`Dockerfile`'s arch-gated stages), producing an empty layer. Extending
this to `arm64` requires handling the `aarch64-linux-gnu` triplet as its
own case, not just pointing the same Dockerfile logic at a different
base image.

## What is deliberately NOT here

Only the C runtime itself: `libc6` and `libgcc-s1`. Any other library a
glibc consumer needs ships with that consumer, inside its own vendor
directory, so this package stays scoped to the piece that genuinely has to
live at the rootfs level.

## SBOM

Both harvested packages are registered with `register-sbom-pkg.sh`, with
their Ubuntu versions and licences, so they appear in EVE's SBOM. The
registration runs in an `eve-alpine` stage because the helper needs `apk`.
