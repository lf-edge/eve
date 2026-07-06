# QEMU / guest crash debugging

EVE can automatically capture post-mortem state when a KVM guest or its qemu
process crashes, so a rare, hard-to-reproduce fault can be root-caused from a
single occurrence. This document is a usage guide: what the feature captures,
the config knobs, and how to work with the results (including attaching `gdb`
to a live, held VM over its UNIX socket).

## What gets captured

Two crash classes are handled, both **on by default**:

| Crash | What EVE captures | When |
|---|---|---|
| **qemu process died** on a fatal signal (SIGBUS/SIGSEGV/SIGABRT) | a **qemu process core** (qemu's own address space) | `debug.qemu.process.core` (default on) |
| **guest VM entered `internal-error`** (e.g. `KVM_RUN -EFAULT`) — qemu still alive | a **guest core** (guest physical RAM, ELF) | `debug.qemu.guest.core` (default on) |

Both dumps are ELF (the universal, `gdb`-loadable format) and are compressed
with zstd at rest.

### Where dumps live

All artifacts are written to the **encrypted vault**:

```text
/persist/vault/qemu-trace/<app-uuid>/<UTC-timestamp>.qemu-core.zst      # qemu process core
/persist/vault/qemu-trace/<app-uuid>/<UTC-timestamp>.guestmem.elf.zst   # guest core
/persist/vault/qemu-trace/<app-name>.<UTC-timestamp>.trace              # qemu trace (if enabled)
```

- Dumps are **encrypted at rest** (guest RAM can contain customer secrets).
- They are **retained per-app as a small ring** (the newest few) and bounded by
  a global cap and a free-space floor, so diagnostics can never fill `/persist`.
- They are **collected by `collect-info`** (the developer/support bundle) so a
  crash can be analyzed off-device.

## Configuration (controller / `debug.qemu.*`)

| Property | Default | Effect |
|---|---|---|
| `debug.qemu.process.core` | on | capture the qemu process core on a fatal signal |
| `debug.qemu.guest.core` | on | capture the guest core on `internal-error` |
| `debug.qemu.process.core.guest.ram` | off | also include guest RAM in the qemu process core (large; usually unnecessary — the guest core already has it) |
| `debug.qemu.pause.on.crash` | off | on a guest crash, keep qemu **alive** and hold the domain for live inspection (see below) |
| `debug.qemu.gdb` | off | expose a per-domain gdb stub UNIX socket |
| `debug.qemu.trace.events` | "" | enable qemu tracing (see Tracing) |

The controller reports a precise reason on the app instance, e.g.
`QEMU process crashed, core dump saved` or
`guest VM crashed, guest core saved`.

## Scenario 1 — automatic capture (default)

Nothing to configure. After a crash the dump appears under
`/persist/vault/qemu-trace/<app-uuid>/`. Retrieve and analyze it on a dev host
(the on-device `zstd` is minimal — always decompress off-device):

```sh
scp -i <key> root@<node>:/persist/vault/qemu-trace/<uuid>/<ts>.guestmem.elf.zst .
zstd -d --long=31 <ts>.guestmem.elf.zst -o guest.elf
gdb <guest-kernel-vmlinux> guest.elf        # or: crash <vmlinux> guest.elf
```

A qemu process core opens the same way (`gdb $(which qemu-system-x86_64)
qemu.core`). `tools/qemu/analyse-guest-dump.sh` pulls per-vCPU RIPs from a
guest core regardless of guest OS.

## Scenario 2 — hold a crashed VM and attach gdb (live inspection)

Set both knobs, then reproduce the crash:

```text
debug.qemu.pause.on.crash = true
debug.qemu.gdb            = true
```

On a guest `internal-error`, EVE captures the guest core **and** leaves qemu
alive/frozen (the app shows `BROKEN … held for inspection`) for ~30 minutes
(then it auto-recovers). While held, attach `gdb` to the guest's stub over its
UNIX socket — no port forwarding needed, pipe `gdb` through `ssh`+`socat`:

```sh
gdb
(gdb) target remote | ssh -i <key> root@<node> socat - UNIX-CONNECT:/run/hypervisor/kvm/<domain>/gdb
(gdb) info registers
(gdb) x/16xg $rsp
```

`<domain>` is the qemu `-name` (`<uuid>.<version>.<appnum>`; `ls
/run/hypervisor/kvm/` lists live ones). You can also bridge the socket to TCP
if you prefer (`socat TCP-LISTEN:1234,reuseaddr,fork UNIX-CONNECT:<socket>` on
the node + `ssh -L 1234:localhost:1234`, then `target remote :1234`).

To release the hold early, restart the app instance from the controller.

## Scenario 3 — qemu tracing

Set `debug.qemu.trace.events` to a CSV of qemu trace-event names/globs and/or
`@<preset>` macros, then reproduce:

| Preset | Covers |
|---|---|
| `@iommu` | VFIO + intel-iommu DMA-mapping flux (IOTLB invalidations, unmap/replay) |
| `@barmap` | PCI BAR-mapping / PM transitions (vfio-pci ↔ KVM EPT), mmap-fault |
| `@vfio` | device lifecycle: INTx/MSI/MSI-X, reset (FLR/PM/hot-reset), display/EDID |

Example: `debug.qemu.trace.events = "@barmap,@iommu,vfio_pci_write_config"`.
The trace is a **binary simpletrace** log. Retrieve and decode on a host — pull
both the trace and the matching `trace-events-all` (it must come from the same
qemu-xen build, so copy it off the device; it lives in the xen-tools container),
then decode with qemu's `simpletrace.py` from the qemu-xen source tree:

```sh
scp -i <key> root@<node>:/persist/vault/qemu-trace/<name>.<ts>.trace .
scp -i <key> root@<node>:/containers/services/xen-tools/rootfs/usr/share/qemu-xen/qemu/trace-events-all .
<qemu-xen-src>/scripts/simpletrace.py trace-events-all <name>.<ts>.trace
```

## Scenario 4 — fault injection (debug builds only)

For validating the capture path on hardware, a **debug-only** qemu build
(`CONFIG_EVE_CRASH_INJECTOR`, disabled in production) adds the
`x-inject-internal-error` QMP command, which stops the VM into `internal-error`
(emitting the same `STOP` a real crash does). `tools/qemu/inject-crash.sh`
drives both classes on a node:

```sh
tools/qemu/inject-crash.sh guest <domain>   # x-inject-internal-error  -> guest core
tools/qemu/inject-crash.sh qemu  <domain>   # SIGABRT the qemu process -> process core
```

A production build has no injector; a qemu process crash is still exercisable
any time with `kill -ABRT <qemu-pid>`.
