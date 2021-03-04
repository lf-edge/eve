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

FILENAME = "/sys/firmware/acpi/tables/SLIT"
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

def unpack_eight_byte_int():
    return struct.unpack('1Q', os.read(fd, 8))[0]

def process_file(filename):
    global fd
    try:
        fd = os.open(filename, os.O_RDONLY)
        signature = unpack_four_byte_string()
        print("signature={}".format(signature))
        os.lseek(fd, 4, os.SEEK_SET)
        total_length = unpack_four_byte_int()
        os.lseek(fd, 36, os.SEEK_SET)
        num_sys_loc = unpack_eight_byte_int()
        print ("num_proximity_domain={}".format(num_sys_loc))
        # Creates a list of lists, all set to 0
        sys_loc_matrix = [[0 for x in range(num_sys_loc)] for y in range(num_sys_loc)]
        seek_num = 44
        for i in range(num_sys_loc):
            for j in range(num_sys_loc):
                os.lseek(fd, seek_num, os.SEEK_SET)
                sys_loc_matrix[i][j] = unpack_one_byte()
                seek_num += 1

        for i in range(num_sys_loc):
            print( "matrix={}".format("\t".join( repr(e) for e in sys_loc_matrix[i] )) )
    except OSError as e:
        sys.stderr.write("ACPI proximity domain information is not available on this machine: {0}\n".format(e))
        return 2
    except:
        sys.stderr.write("Unknown Error detected while getting proximity domain info from ACPI SLIT sysfs\n")
        return 2
    finally:
        if fd:
            os.close(fd)
    return 0

##print("Reading ACPI (PMTT) Information for KNL Configuration.")
ret_val = process_file(FILENAME)

##print("Finishing script.")
exit(ret_val)
