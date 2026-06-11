# Debugging qemu guest crashes

This document covers EVE's host-side instrumentation for diagnosing
qemu guest crashes — primarily the `KVM_RUN → -EFAULT` class that
shows up as `kvm run failed Bad address` and a qemu CPU register dump
on the device's `app.<uuid>.log`, with the domain transitioning to
`BROKEN` state.

It also covers the (much less common) need for live, interactive
Windows-guest debugging with WinDbg.

## What gets captured automatically

When a VM transitions to qemu's `RUN_STATE_INTERNAL_ERROR` (the state
that follows a real `KVM_RUN → -EFAULT`), `pillar`'s QMP event handler
fires automatically and:

- Issues `dump-guest-memory` over QMP, producing
  `/persist/log/qemu-trace/<domain-name>.guestmem.elf`.  This is an
  ELF64 x86-64 core file containing the guest's full physical RAM
  (typically 8–16 GB) and per-vCPU register state (`NT_PRSTATUS` notes
  plus qemu-specific notes for segment selectors / GDT-IDT bases /
  control registers).
- Logs the event via `logrus` (visible in `logread`).

The dump is always taken; there is no toggle to suppress it.  Disk
space is the only constraint — a dump equals the VM's RAM size.

The file lives under `/persist/log/qemu-trace/`, which is already
symlinked into every `collect-info.sh` bundle as `persist-log`.  An
explicit `qemu-trace-manifest` file is also written so the dump is
easy to spot in the bundle.

## Global config knobs

Set via the controller:

```sh
zcli edge-node update <node> --config="<key>:<value>"
```

| Key | Type | What it does |
|---|---|---|
| `debug.qemu.trace.events` | string (CSV) | Comma-separated qemu trace event names (or globs).  When non-empty, pillar passes them to qemu via `-trace events=…,file=/persist/log/qemu-trace/<dom>.trace`.  The output is in qemu's simpletrace binary format.  Empty = tracing disabled.  See "Useful event sets" below. |
| `debug.qemu.dump.guest.core` | bool | Flips `dump-guest-core` in the qemu machine config from `off` (default) to `on`.  When qemu itself coredumps (segfault / SIGABRT), guest RAM is included in qemu's core.  Independent of the auto-dump above. |
| `debug.qemu.gdb` | bool | Adds `-gdb unix:/run/hypervisor/kvm/<dom>/gdb,server=on,wait=off` to qemu's argv.  Operator can attach with `gdb -ex "target remote /run/hypervisor/kvm/<dom>/gdb"` for vCPU register / guest-memory inspection. |
| `debug.qemu.pause.on.crash` | bool | When set, pillar's `qmpEventHandler` logs the pause-on-crash intent on `STOP/internal-error` so an operator knows qemu is held alive (with the gdbstub still answering) for post-mortem.  Pillar still marks the domain `BROKEN`. |

Changes take effect on the next VM start; restart the affected app via
`zcli edge-app-instance restart <name>` to pick them up immediately.

### Useful event sets

For VFIO + intel-iommu issues (the common case on iGPU/USB passthrough):

```
vtd_inv_desc,vtd_iommu_replay,vtd_iotlb_iova,vtd_iommu_translate,vfio_iommu_map,vfio_iommu_unmap
```

For chardev / serial console issues:

```
chardev_*
```

For full IOMMU + paging diagnostics (very high event rate; only enable
briefly):

```
vtd_*,ept_*
```

## Analyzing the guest-memory dump

The dump is a standard x86-64 ELF core file.

### Quick structural sanity check

```sh
readelf -h <dump>.elf            # ELF header, expect "Type: CORE", "Machine: x86_64"
readelf -lW <dump>.elf           # program headers (1× PT_NOTE + N× PT_LOAD)
readelf -n <dump>.elf | head -40 # NT_PRSTATUS notes, one per vCPU
strings -t x <dump>.elf | grep -E "ntoskrnl|MS_DOS|Windows Boot Manager"
```

### With WinDbg

WinDbg doesn't open ELF cores directly.  Convert first:

```sh
qemu-elf2dump <dump>.elf <dump>.dmp
```

`qemu-elf2dump` ships with `qemu-utils` / `qemu-system-*` on most
distros.  Then open `<dump>.dmp` in WinDbg with the public Microsoft
symbol server:

```
.sympath SRV*c:\sym*https://msdl.microsoft.com/download/symbols
.reload /f
!analyze -v
!process 0 0
!devnode 0 1   # iGPU at VEN_8086&DEV_A721, USB at VEN_8086&DEV_…
```

### With crash (Linux)

```sh
crash /path/to/Windows-kernel-symbols <dump>.elf
```

`crash` doesn't really know Windows kernel structures out of the box;
gdb on the ELF is more practical for ad-hoc inspection.

### With gdb

```sh
gdb -ex "set arch i386:x86-64" -ex "core-file <dump>.elf"
(gdb) info registers       # vCPU 0 state
(gdb) info threads         # one thread per vCPU
(gdb) x/16i $rip           # disassembly at the faulting instruction
(gdb) x/16gx 0x100000      # raw guest physical memory
```

## Post-mortem with `debug.qemu.pause.on.crash`

If you want to interrogate qemu *itself* after a crash (e.g. attach
gdb to the gdbstub for live vCPU register reads / page-walks), enable:

```sh
zcli edge-node update <node> --config="debug.qemu.pause.on.crash:true"
zcli edge-node update <node> --config="debug.qemu.gdb:true"
```

After the next crash, qemu stays paused.  From the EVE node:

```sh
gdb -ex "target remote /run/hypervisor/kvm/<dom>/gdb"
```

When done, manually clean up via the controller (`zcli edge-app-instance
restart <name>`).

## Live Windows kernel debugging (rarely needed)

Most root-cause work can be done from the auto-dump + qemu trace.
For the cases where it can't (e.g. you need to interactively walk a
driver's state machine just before the crash), set up WinDbg over the
guest's COM port:

1. **On the Windows guest, once**: run `tools/qemu/enable-windbg.ps1
   -Transport serial` in an elevated PowerShell.  This sets
   `bcdedit /debug on` and `/dbgsettings serial debugport:1
   baudrate:115200`.  Reboot Windows.
2. **On the EVE host**: forward qemu's COM socket to a TCP port so
   WinDbg can reach it from the operator's laptop:
   ```sh
   socat TCP-LISTEN:5555,reuseaddr,fork \
         UNIX-CONNECT:/run/hypervisor/kvm/<dom>/cons
   ```
3. **On the operator's laptop**: `ssh -L 5555:127.0.0.1:5555 root@<eve-node>`,
   then attach WinDbg to `com:port=5555,baud=115200,reconnect`.

For kdnet (UDP) instead, run the same script with `-Transport net
-HostIP <windbg-machine-ip> -Key 1.2.3.4 -Port 50000` — see
`tools/qemu/enable-windbg.ps1` header comment for details.

## Testing the chain (no real crash needed)

For development of the diagnostic chain itself, EVE carries a
debug-only QMP command — `inject-kvm-internal-error` — added by
`pkg/xen-tools/patches-4.21.1/04-qemu--inject-kvm-internal-error-for-testing.patch`.
It drives qemu into byte-identical observable state to a real
`KVM_RUN → -EFAULT`: same CPU register dump on stderr, same
`kvm run failed Bad address` log line, same `STOP` QMP event with
runstate `internal-error`.

To fire it:

```sh
DOM=$(ls /run/hypervisor/kvm/ | head -1)
printf '%s\n%s\n' \
    '{"execute":"qmp_capabilities"}' \
    '{"execute":"inject-kvm-internal-error"}' \
  | socat - UNIX-CONNECT:/run/hypervisor/kvm/$DOM/qmp
```

Expected outcome:

- `kvm run failed Bad address` appears in the app log
- qemu's CPU register dump appears in the app log
- A new `/persist/log/qemu-trace/$DOM.guestmem.elf` exists, size ≈ VM RAM
- `logread | grep qmpEventHandler` shows the auto-dump completing

After the test, restart the VM via the controller:

```sh
zcli edge-app-instance restart <vm-name>
```

Windows will show the post-unclean-shutdown recovery menu on next
boot — pick "Start Windows normally".

## File locations summary

| Path | Contents |
|---|---|
| `/persist/log/qemu-trace/<dom>.guestmem.elf` | Auto-dumped guest RAM (ELF core), one per crash event, overwritten on next crash for same domain |
| `/persist/log/qemu-trace/<dom>.trace` | simpletrace binary trace (only when `debug.qemu.trace.events` is set) |
| `/run/hypervisor/kvm/<dom>/qmp` | QMP control socket |
| `/run/hypervisor/kvm/<dom>/gdb` | gdbstub socket (only when `debug.qemu.gdb` is set) |
| `/run/hypervisor/kvm/<dom>/qemu-trace-events` | newline-separated event list materialized for qemu's `-trace events=…` |
| `/run/hypervisor/kvm/<dom>/cons` | guest's serial console as a unix socket |
