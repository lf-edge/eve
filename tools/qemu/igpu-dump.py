#!/usr/bin/env python3
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Snapshot the passed-through Intel iGPU MMIO register block of a running EVE
guest, by asking qemu (over QMP) to dump the guest-physical BAR0 range to a
binary blob.

Runs INSIDE the EVE `debug` container (which has python3 and sees the host's
/run + /persist):

    eve exec debug python3 /persist/qemu-tools/igpu-dump.py <label>

Why QMP/pmemsave and not a host-side mmap: the iGPU is bound to vfio-pci, so the
sysfs resourceN mmap is refused (EINVAL) and /proc/<qemu>/mem reads of the
vfio BAR vma give EIO (VM_PFNMAP, no .access op). qemu itself holds the BAR
mmap as a ram_device MemoryRegion, so `pmemsave` on the guest-physical BAR0
address reads the live MMIO directly.

The blob's byte offset i corresponds to BAR0 register offset RANGE_START + i,
so blobs are directly comparable across snapshots (see igpu-regdiff.py).
"""
# Terse standalone diagnostic script: relax pylint style checks that
# don't add value here.
# pylint: disable=invalid-name,consider-using-f-string,missing-module-docstring,missing-class-docstring,missing-function-docstring,consider-using-with,unspecified-encoding,broad-exception-caught,multiple-imports,multiple-statements,too-many-locals,too-many-statements,unnecessary-lambda-assignment
import socket, json, glob, sys, os, time, re, argparse

IGPU_PCI_ID = "8086:a7a1"          # RPL-P Iris Xe (adjust per platform)
# Display + power-well + DBUF + CDCLK + transcoder + pipe/plane/DDI/scaler.
# Deliberately excludes GT/render (<0x40000, forcewake-gated, reads as 0 from
# host) and the GTT (upper half of the 16MB BAR).
DEFAULT_RANGE = (0x40000, 0x40000)  # start, length  -> 0x40000..0x80000

def find_qmp_sock():
    # Control "qmp" socket is free; "listener.qmp" is held by the monitor svc.
    for pat in ("/hostfs/run/hypervisor/kvm/*/qmp",
                "/run/hypervisor/kvm/*/qmp"):
        g = glob.glob(pat)
        if g:
            return g[0]
    return None

class Qmp:
    def __init__(self, path, timeout=15):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.settimeout(timeout)
        self.s.connect(path)
        self.f = self.s.makefile("rwb", buffering=0)
        self._readline()                                # greeting ({"QMP":...})
        self._send({"execute": "qmp_capabilities"})
        self._recv()                                    # capabilities ack
    def _send(self, obj):
        self.f.write((json.dumps(obj) + "\n").encode())
    def _readline(self):
        line = self.f.readline()
        return json.loads(line) if line else None
    def _recv(self):
        # Return the next command reply, skipping async events.
        while True:
            r = self._readline()
            if r is None:
                return None
            if "return" in r or "error" in r:
                return r
    def hmp(self, cmd):
        self._send({"execute": "human-monitor-command",
                    "arguments": {"command-line": cmd}})
        r = self._recv()
        if r is None:
            raise RuntimeError("no reply to: %s" % cmd)
        if "error" in r:
            raise RuntimeError("qmp error: %s" % r["error"])
        return r["return"]
    def close(self):
        try: self.s.close()
        except Exception: pass

def find_bar0_base(q, pci_id):
    """Parse `info pci` for the passthrough iGPU's guest-physical BAR0 base.
    Must be rediscovered each run: OVMF can reassign it across reboots."""
    out = q.hmp("info pci")
    dev_re = re.compile(r"PCI device %s" % re.escape(pci_id))
    bar0_re = re.compile(r"BAR0:.*at (0x[0-9a-fA-F]+)")
    in_dev = False
    for line in out.splitlines():
        if dev_re.search(line):
            in_dev = True
            continue
        if in_dev:
            m = bar0_re.search(line)
            if m:
                base = int(m.group(1), 16)
                if base == 0xffffffffffffffff:
                    raise RuntimeError(
                        "iGPU %s BAR0 is unmapped (0xff..ff): the device is "
                        "asleep / memory decode disabled. Wake it and retry."
                        % pci_id)
                return base
            if "device" in line and "function" in line:  # next device block
                in_dev = False
    raise RuntimeError("iGPU %s BAR0 not found in `info pci`" % pci_id)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("label", help="snapshot label, e.g. A1 / B1 / corrupted")
    ap.add_argument("--pci-id", default=IGPU_PCI_ID)
    ap.add_argument("--start", type=lambda x: int(x, 0), default=DEFAULT_RANGE[0])
    ap.add_argument("--len", type=lambda x: int(x, 0), default=DEFAULT_RANGE[1])
    ap.add_argument("--out-dir", default="/persist/qemu-tools/dumps")
    args = ap.parse_args()

    sock = find_qmp_sock()
    if not sock:
        sys.exit("no qmp socket found (guest running?)")
    os.makedirs(args.out_dir, exist_ok=True)

    q = Qmp(sock)
    try:
        base = find_bar0_base(q, args.pci_id)
        gpa = base + args.start
        ts = time.strftime("%Y%m%d-%H%M%S")
        blob = "%s/%s.%s.bin" % (args.out_dir, args.label, ts)
        # qemu HMP parses the filename; a leading '/' is otherwise read as a
        # division operator, so the path MUST be quoted.
        ret = q.hmp('pmemsave 0x%x 0x%x "%s"' % (gpa, args.len, blob))
        if ret.strip():  # pmemsave prints nothing on success; text == error
            raise RuntimeError("pmemsave failed: %s" % ret.strip())
        meta = {"label": args.label, "ts": ts, "pci_id": args.pci_id,
                "bar0_base": base, "range_start": args.start,
                "range_len": args.len, "blob": blob}
        open(blob + ".json", "w").write(json.dumps(meta, indent=2))
        sz = os.path.getsize(blob)
        print("wrote %s (%d bytes)  BAR0_base=0x%x  covers 0x%x..0x%x"
              % (blob, sz, base, args.start, args.start + args.len))
    finally:
        q.close()

if __name__ == "__main__":
    main()
