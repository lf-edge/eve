#!/usr/bin/env python3
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Author: Mikhail Malyshev <mike.malyshev@gmail.com>

"""Decode the iGPU OpRegion bytes dumped by EVE's patched QEMU vfio-igd quirk.

EVE's QEMU carries a passive diagnostic patch
(pkg/qemu/patches/9005-vfio-igd-save-the-host-OpRegion-for-offline-inspecti.patch)
that writes a copy of the host iGPU's OpRegion to a per-domain file at
/run/hypervisor/kvm/<vm-name>/igd-opregion.bin every time
x-igd-opregion=on populates etc/igd-opregion for the guest.  This
script parses those bytes and prints:

  - OpRegion header summary (magic, version, mailboxes, BIOS / driver
    version strings)
  - VBT header (signature, version, BDB offset)
  - BDB block list (id, size, recognised name)

Read-only; runs on a dev box once you've scp'd the dump back.
Designed for cross-node comparison (e.g. TGL vs RPL-P) when
diagnosing GOP / connector init differences.

    tools/igpu-vbt-dump.py <opregion.bin> [<opregion.bin> ...]

References:
  - i915: drivers/gpu/drm/i915/display/intel_bios.c (BDB block IDs)
  - Intel IGD OpRegion Specification 2.1 (OpRegion layout)
"""

# Module filename uses kebab-case ("igpu-vbt-dump") to match the
# tools/*.py kebab-case convention (cf. tools/extract-gop.py).
# Python's snake-case import rule doesn't apply since this is a
# script, not a library — silence pylint's complaint.
# pylint: disable=invalid-name

import argparse
import struct
import sys
from pathlib import Path


OPREGION_HEADER_MAGIC = b"IntelGraphicsMem"

# Mailbox 4 (VBT) starts here in OpRegion 2.x.  For OpRegion 1.x without
# a VBT mailbox, this offset is past the header but inside the 0x400 byte
# Mailbox 3.  We detect VBT by looking for a "$VBT" signature at MBOX4_OFF
# OR by walking from the end of the header if MBOX[4] bit is not set.
MBOX4_OFF = 0x400

# Most BDB block IDs we care about for cross-platform diff.  Source:
# linux/drivers/gpu/drm/i915/display/intel_vbt_defs.h enum bdb_block_id
BDB_BLOCK_NAMES = {
    1:   "GENERAL_FEATURES",
    2:   "GENERAL_DEFINITIONS",
    3:   "OLD_TOGGLE_LIST",
    4:   "DISPLAY_TOGGLE_LIST_BIOS",
    5:   "PANEL_INFO",                  # SDVO_LVDS_OPTIONS in older docs
    6:   "DRIVER_FEATURES",
    7:   "DRIVER_PERSISTENCE",
    8:   "EXT_TABLE_PTRS",
    9:   "DOT_CLOCK_OVERRIDE",
    10:  "DISPLAY_SELECT",
    12:  "DRIVER_ROTATION",
    13:  "DISPLAY_REMOVE",
    14:  "OEM_CUSTOMIZATION",
    20:  "EFP_LIST",
    22:  "SDVO_LVDS_OPTIONS",
    23:  "SDVO_PANEL_DTDS",
    24:  "SDVO_LVDS_PNP_IDS",
    25:  "SDVO_LVDS_POWER_SEQ",
    26:  "TV_OPTIONS",
    27:  "EDP",
    28:  "LFP_OPTIONS",
    29:  "LFP_DATA_PTRS",
    30:  "LFP_DATA",
    32:  "LFP_BACKLIGHT",
    33:  "LFP_POWER",
    38:  "MIPI_CONFIG",
    40:  "DSI_DELAYS",                  # name varies; sometimes DDI port info
    41:  "MIPI_SEQUENCE",
    43:  "RSVD_43",
    52:  "COMPRESSION_PARAMETERS",
    53:  "GENERIC_DTD",
    56:  "PSR",
    57:  "GENERIC_DTD2",
    58:  "MIPI_DSI",
    254: "SKIP",
}


def parse_header(data: bytes) -> dict:
    """Parse the 0x100-byte OpRegion header and return its decoded fields.

    Raises ValueError if the buffer is too small or the magic doesn't match.
    """
    if len(data) < 0x100:
        raise ValueError("OpRegion too small for header")
    if data[:16] != OPREGION_HEADER_MAGIC:
        raise ValueError(f"bad OpRegion magic: {data[:16]!r}")
    size_kb, ver = struct.unpack_from("<II", data, 0x10)
    sver = data[0x18:0x28].rstrip(b"\0").decode("ascii", "replace")
    vver = data[0x28:0x38].rstrip(b"\0").decode("ascii", "replace")
    gver = data[0x38:0x48].rstrip(b"\0").decode("ascii", "replace")
    mbox = struct.unpack_from("<I", data, 0x48)[0]
    dmod = struct.unpack_from("<I", data, 0x4C)[0]
    pcon = struct.unpack_from("<I", data, 0x50)[0]
    return {
        "magic": OPREGION_HEADER_MAGIC,
        "size_kb": size_kb,
        "ver": ver,
        "sbios_ver": sver,
        "vbios_ver": vver,
        "drv_ver": gver,
        "mailboxes_bitmap": mbox,
        "driver_model": dmod,
        "platform_config": pcon,
    }


def find_vbt(data: bytes) -> int | None:
    """Return offset of the VBT '$VBT' signature within the OpRegion, or None."""
    candidates = [MBOX4_OFF, 0x500, 0x600, 0x700, 0x1C00]
    for off in candidates:
        if off + 4 <= len(data) and data[off:off + 4] == b"$VBT":
            return off
    sig = data.find(b"$VBT")
    return sig if sig != -1 else None


def parse_vbt(data: bytes, off: int) -> dict:
    """
    VBT header layout per linux/drivers/gpu/drm/i915/display/intel_vbt_defs.h
    struct vbt_header (48 bytes):

        0x00  signature[20]   "$VBT <PLATFORM-NAME>"
        0x14  version         u16
        0x16  header_size     u16
        0x18  vbt_size        u16
        0x1A  vbt_checksum    u8
        0x1B  reserved0       u8
        0x1C  bdb_offset      u32
        0x20  aim_offset[4]   u32 each
    """
    if off + 0x20 > len(data):
        raise ValueError("VBT header runs past OpRegion")
    name = data[off:off + 20].rstrip(b"\0").decode("ascii", "replace")
    version, header_size, vbt_size = struct.unpack_from("<HHH", data, off + 0x14)
    checksum = data[off + 0x1A]
    bdb_offset = struct.unpack_from("<I", data, off + 0x1C)[0]
    return {
        "vbt_off": off,
        "name": name,
        "version": version,
        "header_size": header_size,
        "vbt_size": vbt_size,
        "checksum": checksum,
        "bdb_offset": bdb_offset,
    }


def walk_bdb(data: bytes, vbt_off: int, bdb_offset: int) -> list[dict]:
    """Walk BDB blocks; return list of {id, size, name, offset}."""
    bdb_start = vbt_off + bdb_offset
    if bdb_start + 16 > len(data):
        raise ValueError("BDB header runs past OpRegion")

    bdb_sig = data[bdb_start:bdb_start + 16]
    bdb_version = struct.unpack_from("<H", data, bdb_start + 16)[0]
    bdb_header_size = struct.unpack_from("<H", data, bdb_start + 18)[0]
    bdb_total_size = struct.unpack_from("<H", data, bdb_start + 20)[0]

    blocks_start = bdb_start + bdb_header_size
    blocks_end = bdb_start + bdb_total_size
    blocks_end = min(blocks_end, len(data))

    pos = blocks_start
    out = []
    while pos + 3 <= blocks_end:
        bid = data[pos]
        bsize = struct.unpack_from("<H", data, pos + 1)[0]
        if bid == 0 and bsize == 0:
            break
        name = BDB_BLOCK_NAMES.get(bid, f"unknown_{bid}")
        out.append({"id": bid, "size": bsize, "name": name, "offset": pos})
        pos += 3 + bsize
        if bsize == 0:
            break

    return [
        {"_bdb_signature": bdb_sig.rstrip(b"\0").decode("ascii", "replace"),
         "_bdb_version": bdb_version,
         "_bdb_header_size": bdb_header_size,
         "_bdb_total_size": bdb_total_size,
         "_blocks_start": blocks_start,
         "_blocks_end": blocks_end},
    ] + out


def hexdump_block(data: bytes, off: int, count: int = 64) -> str:
    """Return a multi-line `xxd`-style hex+ASCII dump of `count` bytes from `off`."""
    chunk = data[off:off + count]
    parts = []
    for i in range(0, len(chunk), 16):
        line = chunk[i:i + 16]
        hexpart = " ".join(f"{byte:02x}" for byte in line).ljust(48)
        ascii_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in line)
        parts.append(f"  {off + i:04x}: {hexpart}  {ascii_part}")
    return "\n".join(parts)


def dump_one(path: Path, hex_blocks: bool) -> None:
    """Decode one OpRegion dump file and print its header / VBT / BDB details."""
    data = path.read_bytes()
    print(f"=== {path}  ({len(data)} bytes) ===")

    try:
        header = parse_header(data)
    except ValueError as exc:
        print(f"  header parse failed: {exc}")
        return
    print(f"  magic            : {header['magic'].decode()}")
    print(f"  size             : {header['size_kb']} KB (header field)")
    print(f"  version          : 0x{header['ver']:08x}")
    print(f"  sbios_ver        : {header['sbios_ver']!r}")
    print(f"  vbios_ver        : {header['vbios_ver']!r}")
    print(f"  drv_ver          : {header['drv_ver']!r}")
    print(f"  mailboxes_bitmap : 0x{header['mailboxes_bitmap']:08x}"
          f" (mbox1={'Y' if header['mailboxes_bitmap'] & 1 else 'N'}"
          f" mbox2={'Y' if header['mailboxes_bitmap'] & 2 else 'N'}"
          f" mbox3={'Y' if header['mailboxes_bitmap'] & 4 else 'N'}"
          f" mbox4={'Y' if header['mailboxes_bitmap'] & 8 else 'N'}"
          f" mbox5={'Y' if header['mailboxes_bitmap'] & 16 else 'N'})")
    print(f"  driver_model     : 0x{header['driver_model']:08x}")
    print(f"  platform_config  : 0x{header['platform_config']:08x}")

    vbt_off = find_vbt(data)
    if vbt_off is None:
        print("  VBT              : NOT FOUND")
        return
    try:
        vbt = parse_vbt(data, vbt_off)
    except ValueError as exc:
        print(f"  VBT parse failed: {exc}")
        return
    print(f"  VBT @ 0x{vbt['vbt_off']:04x}")
    print(f"    name           : {vbt['name']!r}")
    print(f"    vbt_version    : {vbt['version']} (0x{vbt['version']:04x})")
    print(f"    header_size    : {vbt['header_size']}")
    print(f"    vbt_size       : {vbt['vbt_size']}")
    print(f"    checksum       : 0x{vbt['checksum']:02x}")
    print(f"    bdb_offset     : 0x{vbt['bdb_offset']:04x}")

    try:
        walk = walk_bdb(data, vbt_off, vbt["bdb_offset"])
    except ValueError as exc:
        print(f"  BDB walk failed: {exc}")
        return
    meta = walk[0]
    blocks = walk[1:]
    print(f"  BDB '{meta['_bdb_signature']}' "
          f"version={meta['_bdb_version']} "
          f"header={meta['_bdb_header_size']} "
          f"total={meta['_bdb_total_size']}")
    print(f"  blocks: {len(blocks)}")
    for block in blocks:
        print(f"    [{block['id']:3d}] {block['name']:30s} size={block['size']:5d}"
              f" @ 0x{block['offset']:04x}")
        if hex_blocks:
            print(hexdump_block(data, block["offset"] + 3, min(block["size"], 64)))


def main() -> int:
    """CLI entry point: parse argv, dump each input file, return 0."""
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--hex", action="store_true",
                        help="hex-dump first 64 bytes of each BDB block")
    args = parser.parse_args()
    for path in args.files:
        if not path.is_file():
            print(f"skip: {path} (not a regular file)", file=sys.stderr)
            continue
        dump_one(path, args.hex)
    return 0


if __name__ == "__main__":
    sys.exit(main())
