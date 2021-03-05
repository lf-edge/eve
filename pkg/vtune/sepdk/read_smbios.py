#!/usr/bin/env python

#     Copyright (C) 2016-2020 Intel Corporation.  All Rights Reserved.

#     This file is part of SEP Development Kit

#     SEP Development Kit is free software; you can redistribute it
#     and/or modify it under the terms of the GNU General Public License
#     version 2 as published by the Free Software Foundation.

#     SEP Development Kit is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.

#     You should have received a copy of the GNU General Public License
#     along with SEP Development Kit; if not, write to the Free Software
#     Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

#     As a special exception, you may use this file as part of a free software
#     library without restriction.  Specifically, if other files instantiate
#     templates or use macros or inline functions from this file, or you compile
#     this file and link it with other files to produce an executable, this
#     file does not by itself cause the resulting executable to be covered by
#     the GNU General Public License.  This exception does not however
#     invalidate any other reasons why the executable file might be covered by
#     the GNU General Public License.

import struct
import os
import sys

EFI_SYSTAB_FILE = "/sys/firmware/efi/systab"
# Traditional way to read the SMBIOS>
MEMDEV_FILENAME = "/dev/mem"
# Recent kernel export the raw DMI table data via sysfs when CONFIG_DMI_SYSFS is set
# This becomes the primary method to capture SMBIOS if sysfs is available
ENTRY_POINT_SYSFS_FILENAME = "/sys/firmware/dmi/tables/smbios_entry_point"
STRUCT_TABLE_SYSFS_FILENAME = "/sys/firmware/dmi/tables/DMI"
STRUCT_HEADER_LEN = 4
STRUCT_HEADER_OFFSET_TYPE = 0
STRUCT_HEADER_OFFSET_LEN = 1
MEM_DEV_OFFSET_TOTAL_WIDTH = 0x8
MEM_DEV_OFFSET_DATA_WIDTH = 0xA
MEM_DEV_OFFSET_SIZE = 0xC
MEM_DEV_OFFSET_EXT_SIZE = 0x1C
MEM_DEV_OFFSET_FORM_FACTOR = 0xE
MEM_DEV_OFFSET_MEM_TYPE = 0x12
MEM_DEV_OFFSET_MEM_TYPE_DETAIL = 0x13
MEM_DEV_OFFSET_SPEED = 0x15
MEM_DEV_OFFSET_RANK = 0x1B
MEM_DEV_MASK_RANK = 0x0F

fd = None
smbios_ver = 0
entry_point = -1
struct_table_add = -1
struct_table_len = 0
num_struct = 0
# figure out python version (major)
python_ver = int(sys.version.split(".")[0])


def unpack_one_byte(data, offset):
    return struct.unpack('1B', data[offset:(offset + 1)])[0]


def unpack_two_byte(data, offset):
    return struct.unpack('1H', data[offset:(offset + 2)])[0]


def unpack_four_byte_int(data, offset):
    return struct.unpack('1I', data[offset:(offset + 4)])[0]


def unpack_four_byte_string(data, offset):
    byte_string = struct.unpack('4s', data[offset:(offset + 4)])[0]
    if (python_ver > 2):
        byte_string = str(byte_string, "utf-8")
    return byte_string


def unpack_five_byte_string(data, offset):
    byte_string = struct.unpack('5s', data[offset:(offset + 5)])[0]
    if (python_ver > 2):
        byte_string = str(byte_string, "utf-8")
    return byte_string


def unpack_eight_byte_int(data, offset):
    return struct.unpack('1Q', data[offset:(offset + 8)])[0]


def get_form_factor(form_factor_value):
    if form_factor_value == 0x01 or form_factor_value == 0x02:
        return "Unknown"
    elif form_factor_value == 0x03:
        return "SIMM"
    elif form_factor_value == 0x04:
        return "SIP"
    elif form_factor_value == 0x05:
        return "Chip"
    elif form_factor_value == 0x06:
        return "DIP"
    elif form_factor_value == 0x07:
        return "ZIP"
    elif form_factor_value == 0x08:
        return "Proprietary Card"
    elif form_factor_value == 0x09:
        return "DIMM"
    elif form_factor_value == 0x0A:
        return "TSOP"
    elif form_factor_value == 0x0B:
        return "Row of chips"
    elif form_factor_value == 0x0C:
        return "RIMM"
    elif form_factor_value == 0x0D:
        return "SODIMM"
    elif form_factor_value == 0x0E:
        return "SRIMM"
    elif form_factor_value == 0x0F:
        return "FB-DIMM"


def get_mem_type(mem_type_value):
    if mem_type_value == 0x01 or mem_type_value == 0x02:
        return "Unknown"
    elif mem_type_value == 0x03:
        return "DRAM"
    elif mem_type_value == 0x04:
        return "EDRAM"
    elif mem_type_value == 0x05:
        return "VRAM"
    elif mem_type_value == 0x06:
        return "SRAM"
    elif mem_type_value == 0x07:
        return "RAM"
    elif mem_type_value == 0x08:
        return "ROM"
    elif mem_type_value == 0x09:
        return "FLASH"
    elif mem_type_value == 0x0A:
        return "EEPROM"
    elif mem_type_value == 0x0B:
        return "FEPROM"
    elif mem_type_value == 0x0C:
        return "EPROM"
    elif mem_type_value == 0x0D:
        return "CDRAM"
    elif mem_type_value == 0x0E:
        return "3DRAM"
    elif mem_type_value == 0x0F:
        return "SDRAM"
    elif mem_type_value == 0x10:
        return "SGRAM"
    elif mem_type_value == 0x11:
        return "RDRAM"
    elif mem_type_value == 0x12:
        return "DDR"
    elif mem_type_value == 0x13:
        return "DDR2"
    elif mem_type_value == 0x14:
        return "DDR2 FB-DIMM"
    elif mem_type_value == 0x18:
        return "DDR3"
    elif mem_type_value == 0x19:
        return "FBD2"
    elif mem_type_value == 0x1A:
        return "DDR4"
    elif mem_type_value == 0x1B:
        return "LPDDR"
    elif mem_type_value == 0x1C:
        return "LPDDR2"
    elif mem_type_value == 0x1D:
        return "LPDDR3"
    elif mem_type_value == 0x1E:
        return "LPDDR4"


def add_delimiter(mem_type_detail):
    mem_type_detail += ", "
    return mem_type_detail


def get_mem_detail_type(mem_type_detail_value):
    mem_type_detail = ""
    if (mem_type_detail_value >> 7) & 1 == 1:
        mem_type_detail = "Synchronous"
    if (mem_type_detail_value >> 10) & 1 == 1:
        mem_type_detail = add_delimiter(mem_type_detail)
        mem_type_detail += "Windows DRAM"
    if (mem_type_detail_value >> 11) & 1 == 1:
        mem_type_detail = add_delimiter(mem_type_detail)
        mem_type_detail += "Cache DRAM"
    if (mem_type_detail_value >> 12) & 1 == 1:
        mem_type_detail = add_delimiter(mem_type_detail)
        mem_type_detail += "Non-volatile"
    if (mem_type_detail_value >> 13) & 1 == 1:
        mem_type_detail = add_delimiter(mem_type_detail)
        mem_type_detail += "Registered (Buffered)"
    if (mem_type_detail_value >> 14) & 1 == 1:
        mem_type_detail = add_delimiter(mem_type_detail)
        mem_type_detail += "Unbuffered (Unregistered)"
    if (mem_type_detail_value >> 15) & 1 == 1:
        mem_type_detail = add_delimiter(mem_type_detail)
        mem_type_detail += "LRDIMM "
    return mem_type_detail


def get_rank(rank_value):
    return rank_value & MEM_DEV_MASK_RANK


# check and get if extended size exists
# also check for unit
def get_if_extended_size(struct_table_buffer, struct_add, size):
    if size == 32767:
        size = unpack_four_byte_int(struct_table_buffer,
                                    struct_add + MEM_DEV_OFFSET_EXT_SIZE)
        #print("size_unit=MB")
        return size
    if (size >> 15) & 1 == 1:
        unit = "KB"
    else:
        unit = "MB"
    #print("size_unit={0}".format(unit))
    return size


# parse through the memory strcutre and print out details
def parse_memory_dev_struct(struct_table_buffer, struct_add, len):

    size = unpack_two_byte(struct_table_buffer,
                           struct_add + MEM_DEV_OFFSET_SIZE)
    print("")
    if size == 0:
        print("Unpopulated DIMM")
        return -1
    size = get_if_extended_size(struct_table_buffer, struct_add, size)
    print("size={0}".format(size))

    total_width = unpack_two_byte(struct_table_buffer,
                                  struct_add + MEM_DEV_OFFSET_TOTAL_WIDTH)
    print("total_width={0}".format(total_width))

    data_width = unpack_two_byte(struct_table_buffer,
                                 struct_add + MEM_DEV_OFFSET_DATA_WIDTH)
    print("data_width={0}".format(data_width))

    form_factor_value = unpack_one_byte(
        struct_table_buffer, struct_add + MEM_DEV_OFFSET_FORM_FACTOR)
    print("form_factor={0}".format(get_form_factor(form_factor_value)))

    mem_type_value = unpack_one_byte(struct_table_buffer,
                                     struct_add + MEM_DEV_OFFSET_MEM_TYPE)
    print("mem_type={0}".format(get_mem_type(mem_type_value)))

    mem_type_detail_value = unpack_two_byte(
        struct_table_buffer, struct_add + MEM_DEV_OFFSET_MEM_TYPE_DETAIL)
    print("mem_type_detail={0}".format(
        get_mem_detail_type(mem_type_detail_value)))

    if smbios_ver > 2.2:  # speed available only from smbios version 2.3
        speed = unpack_two_byte(struct_table_buffer,
                                struct_add + MEM_DEV_OFFSET_SPEED)
        if smbios_ver > 3.0:  # unit is MT/s from smbios version 3.1 onwards
            print("speed={0} MT/s".format(speed))
        else:
            print("speed={0} MHz".format(speed))
    else:
        print("speed=unavailable")

    if smbios_ver > 2.5:  # rank available only from smbios version 2.6
        rank_value = unpack_one_byte(struct_table_buffer,
                                     struct_add + MEM_DEV_OFFSET_RANK)
        print("rank={0}".format(get_rank(rank_value)))
    else:
        print("rank=unavailable")


# parse the smbios structures
def parse_smbios(struct_table_buffer):
    iter = 0
    struct_add = 0

    # struct_table_add + struct_table_len gives the address of the end of the last smbios structure
    # every structure will have a minimum length of 4
    while (iter < num_struct
           or num_struct == 0) and struct_add + 4 <= struct_table_len:
        struct_type = unpack_one_byte(struct_table_buffer,
                                      struct_add + STRUCT_HEADER_OFFSET_TYPE)
        struct_len = unpack_one_byte(struct_table_buffer,
                                     struct_add + STRUCT_HEADER_OFFSET_LEN)

        # smbios structure is broken if length < 4
        if struct_len < 4:
            print("Broken SMBIOS table.")
            return -1

        # parse and output details if DIMM type is 17
        if struct_type == 17:
            parse_memory_dev_struct(struct_table_buffer, struct_add,
                                    struct_len)

        # move to the end of formatted section of the structure
        struct_add += struct_len

        # we have reached the beginning of text strings section
        # iterate through it until the end of the strings section
        first = unpack_one_byte(struct_table_buffer, struct_add)
        struct_add += 1

        while struct_add <= struct_table_len - 1:
            second = unpack_one_byte(struct_table_buffer, struct_add)
            struct_add += 1
            if first == 0 and second == 0:
                break
            first = second
        iter = iter + 1


# obtain the smbios entry point by parsing through /dev/mem
def parse_and_find_entry_point():
    # On non-UEFI systems, the 32-bit smbios Entry Point structure,
    # can be located by searching for the anchor-string on paragraph
    # (16-byte) boundaries within the physical memory address
    # range 0xF0000 to 0xFFFFF
    # 0xF0000 - 0xFFFFF in decimals 983040 - 1048575
    for offset in range(983040, 1048575, 16):
        os.lseek(fd, offset, os.SEEK_SET)
        anchor_str = struct.unpack('5s', os.read(fd, 5))[0]
        # _SM_ or _SM3_ or _SM3 marks the beginning of smbios
        if anchor_str == b"_SM3_" or anchor_str == b"_SM3":
            return offset
        os.lseek(fd, offset, os.SEEK_SET)
        anchor_str = struct.unpack('4s', os.read(fd, 4))[0]
        if anchor_str == b"_SM_":
            return offset

    return -1


# parse the entry point structure to obtain
# address to first smbios structure,
# total number of structures, total length of the structures
# and smbios version
def parse_entry_point_struct(anchor_str):
    global smbios_ver
    global struct_table_add
    global struct_table_len
    global num_struct
    global entry_point_buffer

    if anchor_str == "_SM_":
        len_offset = 5
        maj_ver_offset = 6
        min_ver_offset = 7

        idx = 0

        inter_anchor_str = unpack_five_byte_string(entry_point_buffer, 0x10)
        print("inter_anchor_str={0}".format(inter_anchor_str))

        struct_table_len = unpack_two_byte(entry_point_buffer, 0x16)
        print("struct_table_len={0}".format(struct_table_len))

        struct_table_add = unpack_four_byte_int(entry_point_buffer, 0x18)
        print("struct_table_add={0}".format(struct_table_add))

        num_struct = unpack_two_byte(entry_point_buffer, 0x1c)
        print("num_struct={0}".format(num_struct))
    elif anchor_str == "_SM3_" or anchor_str == "_SM3":
        len_offset = 6
        maj_ver_offset = 7
        min_ver_offset = 8

        struct_table_len = unpack_four_byte_int(entry_point_buffer, 0x0c)
        print("struct_table_len={0}".format(struct_table_len))

        struct_table_add = unpack_eight_byte_int(entry_point_buffer, 0x10)
        print("struct_table_add={0}".format(struct_table_add))
    else:
        return -1

    entry_point_struct_len = unpack_one_byte(entry_point_buffer, len_offset)
    print("entry_point_struct_len={0}".format(entry_point_struct_len))

    maj_ver = unpack_one_byte(entry_point_buffer, maj_ver_offset)
    print("maj_ver={0}".format(maj_ver))

    min_ver = unpack_one_byte(entry_point_buffer, min_ver_offset)
    print("min_ver={0}".format(min_ver))

    # concatenate the max and min version to create single version string
    if min_ver > 9:
        denom = 100
    else:
        denom = 10
    smbios_ver = maj_ver + (min_ver / float(denom))
    print("smbios_ver={0}".format(smbios_ver))


# obtain the smbios entry point from /sys/firmware/efi/systab
def process_efi():
    global entry_point
    try:
        fp = open(EFI_SYSTAB_FILE, 'r')
        for line in fp:
            if "SMBIOS" in line:
                smb_arr = line.split('=')
                entry_pt_arr = smb_arr[1].split('\n')
                entry_pt_hex = entry_pt_arr[0]
        print("entry_pt_hex:{0}".format(entry_pt_hex))

        entry_point = int(entry_pt_hex, 16)

    except IOError as e:
        return -1


def process_smbios():
    global fd
    global entry_point
    global entry_point_buffer

    try:

        sysfile_present = os.path.exists(ENTRY_POINT_SYSFS_FILENAME) \
                          and os.path.exists(STRUCT_TABLE_SYSFS_FILENAME)

        print("sysfile_present={0}".format(sysfile_present))

        if sysfile_present:
            fd = os.open(ENTRY_POINT_SYSFS_FILENAME, os.O_RDONLY)
        else:
            # obtain smbios entry point from EFI
            local_entry_pt = process_efi()

            fd = os.open(MEMDEV_FILENAME, os.O_RDONLY)

            if local_entry_pt == -1:
                # if EFI approach fails, obtain the smbios entry point
                # by parsing through the /dev/mem
                entry_point = parse_and_find_entry_point()
                if entry_point == -1:
                    print("Unable to find SMBIOS entry point.")
                    return -1

            print("entry_point:{0}".format(entry_point))

            os.lseek(fd, entry_point, os.SEEK_SET)

        entry_point_buffer = os.read(fd, 0x20)

        if fd:
            os.close(fd)
            fd = None

        anchor_str = unpack_four_byte_string(entry_point_buffer, 0)

        print("anchor_str={0}".format(anchor_str))

        # obtain address to first smbios structure,
        # total number of structures and total length of the structures
        if parse_entry_point_struct(
                anchor_str) == -1 or struct_table_add == -1:
            print("Unable to find entry point to SMBIOS.")
            return -1

        if sysfile_present:
            fd = os.open(STRUCT_TABLE_SYSFS_FILENAME, os.O_RDONLY)
        else:
            fd = os.open(MEMDEV_FILENAME, os.O_RDONLY)
            os.lseek(fd, struct_table_add, os.SEEK_SET)

        readbuf = []
        while len(readbuf) < struct_table_len:
            buf = os.read(fd, struct_table_len - len(readbuf))
            if len(buf) == 0:
                break
            readbuf += buf

        if len(readbuf) < struct_table_len:
            print("Unable to read the SMBIOS table entries.")
            return -1

        if parse_smbios(bytearray(readbuf)) == -1:
            print("Unable to find memory device struct.")
            return -1

    except OSError as e1:
        sys.stderr.write(
            "OSError detected while getting SMBIOS information: {0}\n".format(
                e1))
        return 2
    except:
        sys.stderr.write(
            "Unknown Error detected while getting SMBIOS information\n")
        return 2
    finally:
        if fd:
            os.close(fd)

    return 0


ret_val = process_smbios()

exit(ret_val)
