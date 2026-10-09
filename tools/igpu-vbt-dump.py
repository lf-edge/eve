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
x-igd-opregion=on populates etc/igd-opregion for the guest.  QEMU and
OVMF pass these bytes to the guest unchanged, so this is exactly what
the guest's graphics driver reads.  This script parses them and prints:

  - OpRegion header (magic, version, mailbox bitmap, platform
    configuration, BIOS / driver version strings)
  - mailbox 1 (ACPI), 2 (SWSCI), 3 (ASLE) and 5 (ASLE_EXT) fields
  - VBT header (signature, version, BDB offset)
  - BDB block list (id, size, name)
  - the Driver Features block (12), including the Graphics Render
    Standby (RC6) flag the BIOS advertises to the driver

Read-only; runs on a dev box once you've scp'd the dump back.

    tools/igpu-vbt-dump.py [--hex] <opregion.bin> [<opregion.bin> ...]

References:
  - i915: drivers/gpu/drm/i915/display/intel_opregion.c (OpRegion layout)
  - i915: drivers/gpu/drm/i915/display/intel_vbt_defs.h (BDB block IDs,
    struct bdb_driver_features)
  - Intel IGD OpRegion Specification 2.1
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

# Mailbox offsets within the OpRegion (intel_opregion.c)
ACPI_OFF = 0x100
SWSCI_OFF = 0x200
ASLE_OFF = 0x300
MBOX4_OFF = 0x400
ASLE_EXT_OFF = 0x1C00

# Header MBOX bitmap: bit -> mailbox
MAILBOX_BITS = [
    (0, "ACPI (mbox1)"),
    (1, "SWSCI (mbox2)"),
    (2, "ASLE (mbox3)"),
    (3, "VBT (mbox4)"),
    (4, "ASLE_EXT (mbox5)"),
    (5, "BACKLIGHT (mbox2, v3.x+)"),
]

PCON_HEADLESS_SKU = 1 << 13

ASLE_TCHE_BITS = [(0, "ALS"), (1, "BLC"), (2, "PFIT"), (3, "PFMB")]

# Mailbox 1 (struct opregion_acpi): scalar u32 fields and u32 display ID
# lists (offset, count)
ACPI_FIELDS = [
    ("drdy", 0x00), ("csts", 0x04), ("cevt", 0x08), ("aslp", 0xA0),
    ("tidx", 0xA4), ("chpd", 0xA8), ("clid", 0xAC), ("cdck", 0xB0),
    ("sxsw", 0xB4), ("evts", 0xB8), ("cnot", 0xBC), ("nrdy", 0xC0),
]
ACPI_LISTS = [
    ("didl", 0x20, 8), ("cpdl", 0x40, 8), ("cadl", 0x60, 8),
    ("nadl", 0x80, 8), ("did2", 0xC4, 7), ("cpd2", 0xE0, 7),
]

# Mailbox 2 (struct opregion_swsci)
SWSCI_FIELDS = [("scic", 0x00, "I"), ("parm", 0x04, "I"), ("dslp", 0x08, "I")]

# Mailbox 3 (struct opregion_asle); bclm[20] and plut[74] are skipped
ASLE_FIELDS = [
    ("ardy", 0x00, "I"), ("aslc", 0x04, "I"), ("tche", 0x08, "I"),
    ("alsi", 0x0C, "I"), ("bclp", 0x10, "I"), ("pfit", 0x14, "I"),
    ("cblv", 0x18, "I"), ("cpfm", 0x44, "I"), ("epfm", 0x48, "I"),
    ("pfmb", 0x96, "I"), ("cddv", 0x9A, "I"), ("pcft", 0x9E, "I"),
    ("srot", 0xA2, "I"), ("iuer", 0xA6, "I"), ("fdss", 0xAA, "Q"),
    ("fdsp", 0xB2, "I"), ("stat", 0xB6, "I"), ("rvda", 0xBA, "Q"),
    ("rvds", 0xC2, "I"),
]

# enum bdb_block_id in intel_vbt_defs.h.  Block 9 is
# DOT_CLOCK_OVERRIDE_ALM before BDB 165 and PSR from 165 on.
BDB_BLOCK_NAMES = {
    1:   "GENERAL_FEATURES",
    2:   "GENERAL_DEFINITIONS",
    3:   "DISPLAY_TOGGLE",
    4:   "MODE_SUPPORT_LIST",
    5:   "GENERIC_MODE_TABLE",
    6:   "EXT_MMIO_REGS",
    7:   "SWF_IO",
    8:   "SWF_MMIO",
    10:  "MODE_REMOVAL_TABLE",
    11:  "CHILD_DEVICE_TABLE",
    12:  "DRIVER_FEATURES",
    13:  "DRIVER_PERSISTENCE",
    14:  "EXT_TABLE_PTRS",
    15:  "DOT_CLOCK_OVERRIDE",
    16:  "DISPLAY_SELECT_OLD",
    17:  "SV_TEST_FUNCTIONS",
    18:  "DRIVER_ROTATION",
    19:  "DISPLAY_REMOVE_OLD",
    20:  "OEM_CUSTOM",
    21:  "EFP_LIST",
    22:  "SDVO_LVDS_OPTIONS",
    23:  "SDVO_LVDS_DTD",
    24:  "SDVO_LVDS_PNP_ID",
    25:  "SDVO_LVDS_PPS",
    26:  "TV_OPTIONS",
    27:  "EDP",
    28:  "EFP_DTD",
    29:  "DISPLAY_SELECT_IVB",
    30:  "DISPLAY_REMOVE_IVB",
    31:  "DISPLAY_SELECT_HSW",
    32:  "DISPLAY_REMOVE_HSW",
    40:  "LFP_OPTIONS",
    41:  "LFP_DATA_PTRS",
    42:  "LFP_DATA",
    43:  "LFP_BACKLIGHT",
    44:  "LFP_POWER",
    45:  "EDP_BFI",
    46:  "CHROMATICITY",
    50:  "MIPI",
    51:  "FIXED_SET_MODE",
    52:  "MIPI_CONFIG",
    53:  "MIPI_SEQUENCE",
    54:  "RGB_PALETTE",
    55:  "COMPRESSION_PARAMETERS_OLD",
    56:  "COMPRESSION_PARAMETERS",
    57:  "VSWING_PREEMPH",
    58:  "GENERIC_DTD",
    252: "INT15_HOOK",
    253: "PRD_TABLE",
    254: "SKIP",
}

BDB_DRIVER_FEATURES = 12
BDB_MIPI_SEQUENCE = 53

# struct bdb_driver_features up to the feature flags: (offset, format,
# field) where field is a name or a list of (name, bit width) bitfields
DRIVER_FEATURES_LAYOUT = [
    (0, "B", [("boot_dev_algorithm", 1), ("allow_display_switch_dvd", 1),
              ("allow_display_switch_dos", 1), ("hotplug_dvo", 1),
              ("dual_view_zoom", 1), ("int15h_hook", 1),
              ("sprite_in_clone", 1), ("primary_lfp_id", 1)]),
    (1, "H", "boot_mode_x"),
    (3, "H", "boot_mode_y"),
    (5, "B", "boot_mode_bpp"),
    (6, "B", "boot_mode_refresh"),
    (7, "H", [("enable_lfp_primary", 1), ("selective_mode_pruning", 1),
              ("dual_frequency", 1), ("render_clock_freq", 1),
              ("nt_clone_support", 1), ("power_scheme_ui", 1),
              ("sprite_display_assign", 1), ("cui_aspect_scaling", 1),
              ("preserve_aspect_ratio", 1), ("sdvo_device_power_down", 1),
              ("crt_hotplug", 1), ("lvds_config", 2), ("tv_hotplug", 1),
              ("hdmi_config", 2)]),
    (9, "B", [("static_display", 1), ("embedded_platform", 1),
              ("display_subsystem_enable", 1)]),
    (10, "H", "legacy_crt_max_x"),
    (12, "H", "legacy_crt_max_y"),
    (14, "B", "legacy_crt_max_refresh"),
    (15, "B", [("hdmi_termination", 1), ("cea861d_hdmi_support", 1),
               ("self_refresh_enable", 1)]),
    (16, "B", "custom_vbt_version"),
]

# Driver Feature Flags (u16 at offset 17), one bit each in this order:
# (name, first BDB version, last BDB version, description).  None means
# the kernel gives no bound.
DRIVER_FEATURE_FLAGS_OFF = 17
DRIVER_FEATURE_FLAGS = [
    ("rmpm_enabled", 159, None, ""),
    ("s2ddt_enabled", 159, None, ""),
    ("dpst_enabled", 159, 227, "Display Power Saving Technology"),
    ("bltclt_enabled", 159, None, ""),
    ("adb_enabled", 159, 227, ""),
    ("drrs_enabled", 159, 227, "Display Refresh Rate Switching"),
    ("grs_enabled", 159, None, "Graphics Render Standby (RC6)"),
    ("gpmt_enabled", 159, None, "Graphics Power Modulation Technology"),
    ("tbt_enabled", 159, None, ""),
    ("psr_enabled", 165, 227, "Panel Self Refresh"),
    ("ips_enabled", 165, None, ""),
    ("dfps_enabled", 165, None, ""),
    ("dmrrs_enabled", 174, 227, ""),
    ("adt_enabled", None, 228, ""),
    ("hpd_wake", 201, 240, ""),
    ("pc_feature_valid", 159, None, "feature flags are valid"),
]


def u32(data: bytes, off: int) -> int:
    """Return the little-endian u32 at `off`."""
    return struct.unpack_from("<I", data, off)[0]


def ascii_field(data: bytes, start: int, end: int) -> str:
    """Return a NUL-padded byte range as a printable string."""
    return data[start:end].split(b"\0", 1)[0].decode("ascii", "replace").strip()


def set_bits(value: int, names: list[tuple[int, str]]) -> str:
    """Return the names whose bit is set in `value`, comma-separated."""
    hits = [name for bit, name in names if value & (1 << bit)]
    return ", ".join(hits) if hits else "none"


def unpack_bits(value: int, fields: list[tuple[str, int]]) -> list[tuple[str, int]]:
    """Split `value` into consecutive LSB-first bitfields."""
    out, shift = [], 0
    for name, width in fields:
        out.append((name, (value >> shift) & ((1 << width) - 1)))
        shift += width
    return out


def parse_header(data: bytes) -> dict:
    """Parse the 0x100-byte OpRegion header (struct opregion_header).

    Raises ValueError if the buffer is too small or the magic doesn't match.
    """
    if len(data) < 0x100:
        raise ValueError("OpRegion too small for header")
    if data[:16] != OPREGION_HEADER_MAGIC:
        raise ValueError(f"bad OpRegion magic: {data[:16]!r}")
    size_kb = u32(data, 0x10)
    _, revision, minor, major = struct.unpack_from("<BBBB", data, 0x14)
    return {
        "magic": OPREGION_HEADER_MAGIC,
        "size_kb": size_kb,
        "ver": u32(data, 0x14),
        "ver_str": f"{major}.{minor}.{revision}",
        "major": major,
        "minor": minor,
        "sbios_ver": ascii_field(data, 0x18, 0x38),
        "vbios_ver": ascii_field(data, 0x38, 0x48),
        "drv_ver": ascii_field(data, 0x48, 0x58),
        "mailboxes_bitmap": u32(data, 0x58),
        "driver_model": u32(data, 0x5C),
        "platform_config": u32(data, 0x60),
        "dver": ascii_field(data, 0x64, 0x84),
    }


def print_header(header: dict) -> None:
    """Print the decoded OpRegion header."""
    mbox = header["mailboxes_bitmap"]
    pcon = header["platform_config"]
    headless = "yes" if pcon & PCON_HEADLESS_SKU else "no"
    print(f"  magic            : {header['magic'].decode()}")
    print(f"  size             : {header['size_kb']} KB (header field)")
    print(f"  version          : {header['ver_str']} (0x{header['ver']:08x})")
    print(f"  sbios_ver        : {header['sbios_ver']!r}")
    print(f"  vbios_ver        : {header['vbios_ver']!r}")
    print(f"  drv_ver          : {header['drv_ver']!r}")
    print(f"  dver             : {header['dver']!r}")
    print(f"  mailboxes_bitmap : 0x{mbox:08x} ({set_bits(mbox, MAILBOX_BITS)})")
    print(f"  driver_model     : 0x{header['driver_model']:08x}")
    print(f"  platform_config  : 0x{pcon:08x} (headless SKU: {headless})")


def print_mailboxes(data: bytes, mbox: int) -> None:
    """Print the ACPI, SWSCI, ASLE and ASLE_EXT mailboxes the header advertises."""
    if mbox & 1 and len(data) >= ACPI_OFF + 0x100:
        print("  mailbox 1 (ACPI):")
        print("    " + " ".join(f"{name}=0x{u32(data, ACPI_OFF + off):x}"
                                for name, off in ACPI_FIELDS))
        for name, off, count in ACPI_LISTS:
            ids = [u32(data, ACPI_OFF + off + 4 * i) for i in range(count)]
            ids = [f"0x{i:08x}" for i in ids if i]
            print(f"    {name}: {' '.join(ids) if ids else '-'}")
    if mbox & 2 and len(data) >= SWSCI_OFF + 0x100:
        print("  mailbox 2 (SWSCI):")
        print("    " + " ".join(f"{name}=0x{u32(data, SWSCI_OFF + off):x}"
                                for name, off, _ in SWSCI_FIELDS))
    if mbox & 4 and len(data) >= ASLE_OFF + 0x100:
        vals = {name: struct.unpack_from("<" + fmt, data, ASLE_OFF + off)[0]
                for name, off, fmt in ASLE_FIELDS}
        print("  mailbox 3 (ASLE):")
        print("    " + " ".join(f"{name}=0x{vals[name]:x}"
                                for name, _, _ in ASLE_FIELDS))
        print(f"    tche enabled: {set_bits(vals['tche'], ASLE_TCHE_BITS)}")
        print(f"    raw VBT: rvda=0x{vals['rvda']:x} rvds={vals['rvds']}")
    if mbox & 16 and len(data) >= ASLE_EXT_OFF + 4:
        print("  mailbox 5 (ASLE_EXT):")
        print(f"    phed=0x{u32(data, ASLE_EXT_OFF):x}")


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


def block_name(bid: int, bdb_version: int) -> str:
    """Return the kernel's name for a BDB block id at this BDB version."""
    if bid == 9:
        return "PSR" if bdb_version >= 165 else "DOT_CLOCK_OVERRIDE_ALM"
    return BDB_BLOCK_NAMES.get(bid, f"unknown_{bid}")


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
        # MIPI Sequence v3+ keeps its size in a separate u32 (_get_blocksize)
        if bid == BDB_MIPI_SEQUENCE and pos + 8 <= blocks_end and data[pos + 3] >= 3:
            bsize = struct.unpack_from("<I", data, pos + 4)[0]
        if bid == 0 and bsize == 0:
            break
        out.append({"id": bid, "size": bsize, "name": block_name(bid, bdb_version),
                    "offset": pos})
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


def flag_defined(first: int | None, last: int | None, bdb_version: int) -> bool:
    """Return True if a feature flag exists at this BDB version."""
    return (first is None or bdb_version >= first) and \
        (last is None or bdb_version <= last)


def print_driver_features(block: bytes, bdb_version: int) -> None:
    """Decode struct bdb_driver_features, marking flags this BDB version lacks."""
    print(f"  Driver Features (block {BDB_DRIVER_FEATURES}, {len(block)} bytes):")
    for off, fmt, field in DRIVER_FEATURES_LAYOUT:
        if off + struct.calcsize(fmt) > len(block):
            print(f"    (block ends at {len(block)} bytes)")
            return
        value = struct.unpack_from("<" + fmt, block, off)[0]
        if isinstance(field, str):
            print(f"    {field:26s} {value}")
            continue
        for name, bits in unpack_bits(value, field):
            print(f"    {name:26s} {bits}")

    if DRIVER_FEATURE_FLAGS_OFF + 2 > len(block):
        print("    (no Driver Feature Flags in this block)")
        return
    flags = struct.unpack_from("<H", block, DRIVER_FEATURE_FLAGS_OFF)[0]
    print(f"    Driver Feature Flags = 0x{flags:04x}:")
    for bit, (name, first, last, desc) in enumerate(DRIVER_FEATURE_FLAGS):
        value = (flags >> bit) & 1
        note = desc
        if not flag_defined(first, last, bdb_version):
            span = f"{first or '?'}-{last or ''}"
            note = f"not defined at BDB {bdb_version} (valid {span})"
        print(f"      {name:22s} {value}  {note}".rstrip())


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
    """Decode one OpRegion dump file and print its header / mailboxes / VBT."""
    data = path.read_bytes()
    print(f"=== {path}  ({len(data)} bytes) ===")

    try:
        header = parse_header(data)
    except ValueError as exc:
        print(f"  header parse failed: {exc}")
        return
    print_header(header)
    print_mailboxes(data, header["mailboxes_bitmap"])

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

    for block in blocks:
        if block["id"] == BDB_DRIVER_FEATURES:
            start = block["offset"] + 3
            print_driver_features(data[start:start + block["size"]],
                                  meta["_bdb_version"])


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
