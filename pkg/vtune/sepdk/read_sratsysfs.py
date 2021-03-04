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

ACPI_FILENAME = "/sys/firmware/acpi/tables/SRAT"
total_length = 0
prox_domain_low = 0
prev_type = 0
fd = None
# figure out python version (major)
python_ver = int(sys.version.split(".")[0])

def unpack_one_byte():
    return struct.unpack('1B', os.read(fd, 1))[0]

def unpack_two_byte():
    return struct.unpack('1H', os.read(fd, 2))[0]

def unpack_four_byte_int():
    return struct.unpack('1I', os.read(fd, 4))[0]

def unpack_four_byte_string():
    byte_string = struct.unpack('4s', os.read(fd, 4))[0]
    if (python_ver > 2):
        byte_string = str(byte_string, "utf-8")
    return byte_string

def get_type(base, offset):
    os.lseek(fd, base + offset, os.SEEK_SET)
    return unpack_one_byte()

def get_length(base, offset):
    os.lseek(fd, base + offset, os.SEEK_SET)
    return unpack_one_byte()

def get_prox_domain(base, offset, is_apic):
    os.lseek(fd, base + offset, os.SEEK_SET)
    if is_apic == 1:
        return unpack_one_byte()
    return unpack_four_byte_int()

def get_type_name(type):
    switcher = {
        0: "ProcessorLocalAPIC",
        1: "Memory",
        2: "ProcessorLocalx2APIC"
    }
    return switcher.get(type, "None")

def init_op(base, is_x2apic, is_apic, offset):
    if is_not_valid(base, is_x2apic, is_apic) == 1:
        goto_next_struct(base + offset)
        return 1
    if process_header(base, is_x2apic, is_apic) == 1:
        return 1
    return 0

def is_not_valid(base, is_x2apic, is_apic):
    offset = 28
    if is_apic == 1:
        offset = 4
    elif is_x2apic == 1:
        offset = 12
    os.lseek(fd, base + offset, os.SEEK_SET)
    is_valid = unpack_one_byte()
    is_valid = (is_valid) & 1
    if is_valid == 1:
        return 0
    return 1

def goto_next_struct(base):
    global prev_type
    if base == total_length:
        return 1
    os.lseek(fd, base, os.SEEK_SET)
    next_type = unpack_one_byte()
    if prev_type != next_type:
        print ("")
    prev_type = next_type
    if next_type == 0:
        process_proc_apic_data(base)
    elif next_type == 1:
        process_memory_data(base)
    else:
        process_proc_x2apic_data(base)

def process_header(base, is_x2apic, is_apic):
    global prox_domain_low
    type = get_type(base, 0)
    type_name = get_type_name(type)
    print("type={}".format(type_name))
    length = get_length(base, 1)
    if length == 0:
        if base + 2 == total_length:
            return 1
        goto_next_device(base + 2)
        return 1
    offset = 2
    if is_x2apic == 1:
        offset = 4
    prox_domain_low = get_prox_domain(base, offset, is_apic)

def process_proc_x2apic_data(base):
    try:
        if init_op(base, 1, 0, 24) == 1:
            return 1
        os.lseek(fd, base + 8, os.SEEK_SET)
        x2apic_id = unpack_four_byte_int()
        print("x2apic_id={}".format(x2apic_id))
        print("proximity_domain={}".format(prox_domain_low))
        os.lseek(fd, base + 16, os.SEEK_SET)
        clk_domain = unpack_four_byte_int()
        if base + 24 == total_length:
            return 1
        goto_next_struct(base + 24)
    except OSError as e:
        sys.stderr.write("ACPI information for proximity domain is not available on this machine: {0}\n".format(e))
        return 2
    except:
        sys.stderr.write("Unknown Error detected while getting proximity domain info from ACPI SRAT sysfs\n")
        return 2
    return 0

def process_memory_data(base):
    try:
        if init_op(base, 0, 0, 40) == 1:
            return 1
        print("mem_proximity_domain={}".format(prox_domain_low))
        os.lseek(fd, base + 8, os.SEEK_SET)
        base_add_low = unpack_four_byte_int()
        os.lseek(fd, base + 12, os.SEEK_SET)
        base_add_high = unpack_four_byte_int()
        base_add = (base_add_high << 32) | base_add_low
        print("base_address={}".format(base_add))
        os.lseek(fd, base + 16, os.SEEK_SET)
        mem_len_low = unpack_four_byte_int()
        os.lseek(fd, base + 20, os.SEEK_SET)
        mem_len_high = unpack_four_byte_int()
        mem_len = (mem_len_high << 32) | mem_len_low
        print("mem_length={}".format(mem_len))
        end_add = base_add + mem_len - 1
        print("end_address={}".format(end_add))
        if base + 40 == total_length:
            return 1
        goto_next_struct(base + 40)
    except OSError as e:
        sys.stderr.write("ACPI information for proximity domain is not available on this machine: {0}\n".format(e))
        return 2
    except:
        sys.stderr.write("Unknown Error detected while getting proximity domain info from ACPI SRAT sysfs\n")
        return 2
    return 0

def process_proc_apic_data(base):
    try:
        if init_op(base, 0, 1, 16) == 1:
            return 1
        os.lseek(fd, base + 3, os.SEEK_SET)
        apic_id = unpack_one_byte()
        print("apic_id={}".format(apic_id))
        os.lseek(fd, base + 8, os.SEEK_SET)
        sapic_eid = unpack_one_byte()
        os.lseek(fd, base + 9, os.SEEK_SET)
        pd_temp = unpack_two_byte()
        os.lseek(fd, base + 11, os.SEEK_SET)
        prox_domain_high = unpack_one_byte()
        prox_domain = (((prox_domain_high << 8) | pd_temp) << 8) | prox_domain_low
        print("proximity_domain={}".format(prox_domain))
        os.lseek(fd, base + 12, os.SEEK_SET)
        clk_domain = unpack_four_byte_int()
        if base + 16 == total_length:
            return 1
        goto_next_struct(base + 16)
    except OSError as e:
        sys.stderr.write("ACPI information for proximity domain is not available on this machine: {0}\n".format(e))
        return 2
    except:
        sys.stderr.write("Unknown Error detected while getting proximity domain info from ACPI SRAT sysfs\n")
        return 2
    return 0

def process_file(filename):
    global total_length
    global fd
    try:
        fd = os.open(filename, os.O_RDONLY)
        signature = unpack_four_byte_string()
        print("signature={}".format(signature))
        os.lseek(fd, 4, os.SEEK_SET)
        total_length = unpack_four_byte_int()
        if total_length == 0:
            return 1
        goto_next_struct(48)
    except OSError as e:
        sys.stderr.write("ACPI information for proximity domain is not available on this machine: {0}\n".format(e))
        return 2
    except:
        sys.stderr.write("Unknown Error detected while getting proximity domain info from ACPI SRAT sysfs\n")
        return 2
    finally:
        if fd:
            os.close(fd)
    return 0

##print("Reading ACPI (SRAT) Information for KNL Configuration.")
ret_val = process_file(ACPI_FILENAME)

##print("Finishing script.")
exit(ret_val)
