///////////////////////////////////////////////////////////////////////////////
// COPYRIGHT (c) 2014 Schweitzer Engineering Laboratories, Inc.
//
// This file is provided under a BSD license. The text of the BSD license 
// is provided below.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// 3. The name of the author may not be used to endorse or promote products
// derived from this software without specific prior written permission.
//
// Alternatively, provided that this notice is retained in full, this software
// may be distributed under the terms of the GNU General Public License ("GPL")
// version 2, in which case the provisions of the GPL apply INSTEAD OF those
// given above.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms and conditions of the GNU General Public License,
// version 2, as published by the Free Software Foundation.
//
// This program is distributed in the hope it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
//
// The full GNU General Public License is included in this distribution in
// the file called "COPYING".
//
// Contact Information:
// SEL Opensource <opensource@selinc.com>
// Schweitzer Engineering Laboratories, Inc.
// 2350 NE Hopkins Court, Pullman, WA 99163
///////////////////////////////////////////////////////////////////////////////
// This file defines all flash operations for EFI and WDF.
///////////////////////////////////////////////////////////////////////////////

#ifndef _FLASH_H_
#define _FLASH_H_

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef WDF_NOR_CONTROLLER

#include <ntddk.h>

#endif

#include "sel_driver_status.h"
#include "sel_std_types.h"

/// SEL PCI VENDOR ID
#define PCI_VENDOR_ID_SEL ((UINT32)(0x1AA9))

/// SEL PCI DEVICE ID for initial flash loader
#define PCI_DEVICE_INIT_FLASH_LOADER ((UINT32)(0x0012))

///////////////////////////////////////////////////////////////////////////////
/// NOR Register Definitions
/// Refer to the nor_irb_ctl_cis for more detail
///////////////////////////////////////////////////////////////////////////////

#define DATA_BUFFER_REG ((UINT32)(0x000))
#define STATUS_REG      ((UINT32)(0x800))
#define ADDRESS_REG     ((UINT32)(0x801))
#define LENGTH_REG      ((UINT32)(0x802))
#define CONTROL_REG     ((UINT32)(0x803))
#define CHIP_TIMING_REG ((UINT32)(0x804))
#define PROG_DELAY_REG  ((UINT32)(0x805))
#define INT_CTRL_REG    ((UINT32)(0x806))
#define INT_STATUS_REG  ((UINT32)(0x807))

///////////////////////////////////////////////////////////////////////////////
/// Command Definitions
///////////////////////////////////////////////////////////////////////////////

#define CMD_READ          ((UINT32)(0x0))
#define CMD_WRITE         ((UINT32)(0x1))
#define CMD_PROGRAM       ((UINT32)(0x2))
#define CMD_SECTOR_ERASE  ((UINT32)(0x3))
#define CMD_BLOCK_ERASE   ((UINT32)(0x4))
#define CMD_CHIP_ERASE    ((UINT32)(0x5))
#define CMD_CFI_QUERY     ((UINT32)(0x6))
#define CMD_CFI_ID        ((UINT32)(0x7))
#define CMD_ENABLE        ((UINT32)(0x8))
#define CMD_RESET         ((UINT32)(0x9))

#define SPI_CMD_READ           ((UINT32)(0x0))
#define SPI_CMD_STATUS         ((UINT32)(0x1))
#define SPI_CMD_WRITE          ((UINT32)(0x2))
#define SPI_CMD_SECTOR_ERASE   ((UINT32)(0x3))
#define SPI_CMD_SECTOR_PROTECT ((UINT32)(0x4))
#define SPI_CMD_CHIP_ERASE     ((UINT32)(0x5))
// Reserved 0x6
#define SPI_CMD_CAPACITY_ID    ((UINT32)(0x7))
#define SPI_CMD_DUMMY_CYCLES   ((UINT32)(0x8))
#define SPI_CMD_RESET          ((UINT32)(0x9))


///////////////////////////////////////////////////////////////////////////////
/// Data buffer specific definitions
///////////////////////////////////////////////////////////////////////////////

//
// Number of words the control Command will use from the Databuffer
// NOTE: 0 indicates the max size
//

#define MAX_DATA_BUFFER_LENGTH  ((UINT32)(0x0))

// Keep track of how many PCI devices we know how to handle
#define NUM_KNOWN_DEVICES       ((UINT32)(2))

///////////////////////////////////////////////////////////////////////////////
/// @brief Pair SEL PCI device ID and which BAR has the nor controller
///////////////////////////////////////////////////////////////////////////////
typedef struct {

   /// SEL PCI device ID
   UINT16   device_id;

   /// BAR implementing the nor irb controller
   UINT8    bar_num;

} DEVICE_NOR_CONTROLLER;

/// Choose a reasonable number of defined flash regions
#define MAX_NUM_FLASH_REGIONS ((UINT32)(16))

///////////////////////////////////////////////////////////////////////////////
/// @brief Contains a flash regions' word address and length of data in bytes
///////////////////////////////////////////////////////////////////////////////
typedef struct {

   /// Word address of region
   UINT32   address;

   /// Size of data in region in bytes
   UINT32   length;

} FLASH_REGION;

///////////////////////////////////////////////////////////////////////////////
/// @brief Contains all device attributes. Once the device has been recognized
/// this structure is populated with information from the corresponding
/// m_known_flash_devices[] entry.
///////////////////////////////////////////////////////////////////////////////
typedef struct {

   /// Manufacturer ID
   UINT8    manufacturer_id;

   /// Device ID
   UINT16   device_id;

   /// Erase capability
   UINT32   uniform_erase_bytes;

   /// Erase Command to use
   /// May be sector or block depending on flash geometry
   UINT8    erase_command;

   /// Write command to use
   UINT8    write_command;

   /// Part specific chip_timing parameter
   UINT32   chip_timing;

   /// Number of clock cycles to delay between writes during a program cycle
   UINT32   program_delay;

   /// The total chip capacity in bytes
   UINT32   capacity;

   /// The number of flash regions on the device
   UINT32 number_flash_regions;

   /// Define the flash regions
   FLASH_REGION flash_regions [MAX_NUM_FLASH_REGIONS];

   /// Index of different REQUIRED regions
   UINT8    option_bits;
   UINT8    rw_settings;
   UINT8    read_only_settings;
   UINT8    main_image;

   /// Index of 3390S8 specific regions
   UINT8    functional_image;

   /// Index of 3390e4 specific regions
   UINT8    upgrade_image_a;
   UINT8    upgrade_image_b;
   UINT8    upgrade_image_c;

   /// Native word size of interface, in bytes
   UINT8    native_word_size;

   /// Max buffer (in bytes) the flash interface can handle
   UINT32   max_buffer_size;

} FLASH_DESCRIPTION;

///////////////////////////////////////////////////////////////////////////////
/// @remarks SET_OR_GET Used as an indicator in set_or_get_option_bits(), where
/// "set" and "get" represent replacing or retrieving the option bits to
/// default_address and image_size 
///////////////////////////////////////////////////////////////////////////////
typedef enum {
   GET_OPTION_BITS,
   SET_OPTION_BITS
}SET_OR_GET;

///////////////////////////////////////////////////////////////////////////////
/// @remarks m_known_devices is a table of PCI devices this tool works for and
/// which BAR specific to each device contains the nor_irb_ctrl
///////////////////////////////////////////////////////////////////////////////
static DEVICE_NOR_CONTROLLER const  m_known_devices [] =
{
   /// Serial Expansion card
   {
      0x0Du,   /// Device ID
      3u       /// BAR Number
   },

   /// Ethernet Expansion card
   {
      0x0Eu,   /// device ID
      3u       /// BAR Number
   }
};

///////////////////////////////////////////////////////////////////////////////
/// @brief
/// Grabs or sets the address and image_size the option_bits contain
/// @remarks
/// This function should be called after the flash_find_part()to make
/// sure the correct BAR is used.
/// @param[in] flash_device The description of the device we are manipulating
/// @param[in] base_address Where the NOR controller is
/// @param[in,out] image_size The size of the data we want to read/write
/// @param[in,out] default_address Returns the address stored in the 
/// option_bits if operation == get_option_bits. If operation ==   
/// set_option_bits, the address in default_address is stored in the option  
/// bits with  the image_size provided
/// @param[in] operation (Get or Set) a flag to determine whether the operation
/// is fetching or modifying the option bits
/// @retval SEL_STATUS_INTERNAL_ERROR The image or address given by the user
/// is invalid, or the image or address in the option bits is invalid, and the
/// status value is -3.
/// @retval SEL_STATUS_ERROR_HARDWARE_ERROR The device reported a parity error
/// while executing a wait, and the status value is -1.
/// @retval SEL_STATUS_OUT_OF_RESOURCES Buffer was unable to be allocated, and
/// the status value is -8.
/// @retval SEL_STATUS_INVALID_PARAMETER The buffer or the reference to 
/// bytes_written is NULL, and the status value is -2.
/// @retval SEL_STATUS_UNSUPPORTED The address was not on an erase boundary,
/// and the status value is -7.
/// @retval SEL_STATUS_NOT_FOUND An unknown flash part was found, and the
/// status value is -5.
/// @retval SEL_STATUS_ACCESS_DENIED  The operation overrruns chip range, and
/// the status value is -6.
/// @retval SEL_STATUS_SUCCESS The setting or fetching of the information in 
/// the option bits was successful, and the return value is 0.
/// @remarks The space to store the the flash_option_bits is allocated in 
/// this function and freed by the end.
///////////////////////////////////////////////////////////////////////////////
SEL_STATUS set_or_get_option_bits(
   FLASH_DESCRIPTION const *flash_device,
   UINT32 volatile *base_address,
   UINT32 *image_size,
   UINT32 *default_address,
   SET_OR_GET operation
   );

///////////////////////////////////////////////////////////////////////////////
/// @brief flash_wait delays until flash is no longer busy with a previous
/// command, then checks whether the device has reported any parity errors
/// @param[in] device_bar The device's base address register.
/// @retval SEL_STATUS_ERROR_HARDWARE_ERROR The device reports a parity error,
/// the value of this status is -1.
/// @retval SEL_STATUS_SUCCESS The wait was executed successfully, the value 
/// of this status is 0
///////////////////////////////////////////////////////////////////////////////
SEL_STATUS flash_wait(
   UINT32 volatile* device_bar
   );

///////////////////////////////////////////////////////////////////////////////
/// @brief flash_get_ids uses the CFI ID command of the device to get the 
/// manufacturer and the device ID's
/// @param[in] device_bar The device's base address register.
/// @param[out] manufacturer_id Returns the found manufacturer ID.
/// @param[out] device_id Returns the found device ID.
/// @retval SEL_STATUS_NOT_FOUND The CFI query returned invalid results. The
/// value of this status is -5.
/// @retval SEL_STATUS_SUCCESS The CFI query returned the device and
/// manufacturer ids, and the value of this status is 0.
///////////////////////////////////////////////////////////////////////////////
SEL_STATUS flash_get_ids(
   UINT32 volatile *device_bar,
   UINT8 *manufacturer_id,
   UINT16 *device_id
   );

///////////////////////////////////////////////////////////////////////////////
/// @brief Checks whether the flash device is enabled, enables it, finds which
/// flash part the device has, then sets the chip_timing and program_delay.      
/// @param[in] device_bar The device's base address register, when we set
/// the chip_timing and program delay is modified.
/// @param [out] flash_device The flash device found by the called function
/// flash_find_part() is returned by reference to any calling function
/// @retval SEL_STATUS_ERROR_HARDWARE_ERROR Flash could not be enabled, or
/// the flash device could not be identified, and the return value is -1.
/// @retval SEL_STATUS_SUCCESS The flash was initialized successfully, the 
/// flash_device was returned via reference, and the return value is 0.
///////////////////////////////////////////////////////////////////////////////
SEL_STATUS flash_initialize_chip_timing(
   UINT32 volatile *device_bar,
   FLASH_DESCRIPTION const **flash_device
   );

///////////////////////////////////////////////////////////////////////////////
/// @brief Erases data starting at the address in start_address to the length
/// specified in count.
/// @param[in] device_bar The device's base address register, from which we
/// gather the flash device we are using.
/// @param[in] start_address The address to begin the operation at.
/// @param[in] count The size in bytes the operation will occupy on the chip.
/// @retval SEL_STATUS_UNSUPPORTED The address was not on an erase boundary, 
/// and the return value for this status is -7.
/// @retval SEL_STATUS_NOT_FOUND An unknown flash part was found, with status 
/// value -5.
/// @retval SEL_STATUS_ACCESS_DENIED  The operation overrruns chip range, and
/// the return value for this status is -6.
/// @retval SEL_STATUS_ERROR_HARDWARE_ERROR The device reported a parity error
/// while executing a wait, and the status value is -1.
/// @retval SEL_STATUS_SUCCESS The erase was successful, and the status value 
/// is 0.
/// @remarks The address must be on an erase boundary. After the erase is
/// complete, it checks whether the data has been successfully erased entirely.
/// @remarks A future improvement to this erase function would be to support 
/// erasing sections of a sector, and in order to do this we would need to 
/// read/modify/write back to the sector.
///////////////////////////////////////////////////////////////////////////////
SEL_STATUS flash_erase_data(
   UINT32 volatile *device_bar,
   UINT32 start_address,
   UINT32 count
   );

///////////////////////////////////////////////////////////////////////////////
/// @brief This function checks if the write operation will fit on the chip,
/// then writes the data held in buffer to the NOR flash starting at the
/// address given in start_address for length given in count
/// @param[in] device_bar The base address for the device we are writing to.
/// @param[in] buffer The buffer contains the file image to be written.
/// @param[in] start_address The address to begin writing to.
/// @param[in] count The number of bytes to write.
/// @param[out] bytes_written The number of bytes written to the device,
/// this value should be the same as count.
/// @retval SEL_STATUS_INVALID_PARAMETER The buffer or the reference to 
/// bytes_written is NULL, and the status value is -2.
/// @retval SEL_STATUS_ERROR_HARDWARE_ERROR The device reported a parity error
/// while executing a wait, and the status value is -1.
/// @retval SEL_STATUS_ACCESS_DENIED  The operation overrruns chip range,and the
/// status value is -6.
/// @retval SEL_STATUS_NOT_FOUND The flash device could not be located and the
/// status value is -5
/// @retval SEL_STATUS_SUCCESS Data was successfully written in flash and the 
/// status value is 0.
/// @remarks buffer is allocated in dump_file_to_flash() and freed at the
/// end of the function dump_file_to_flash(). 
///////////////////////////////////////////////////////////////////////////////
SEL_STATUS flash_write_data(
   UINT32 volatile *device_bar,
   UINT8 *buffer,
   UINT32 start_address,
   UINT32 count,
   UINT32 *const bytes_written
   );

///////////////////////////////////////////////////////////////////////////////
/// @brief This function makes sure the read is within range and then issues the
/// read command, and the number of bytes specified in count is read from
/// NOR flash
/// @param[in] device_bar The location of the base address register.
/// @param[out] buffer The buffer to contain the data read from flash.
/// @param[in] start_address The starting address in flash to begin reading 
/// from.
/// @param[in] count The amount in bytes to be read from flash.
/// @param[out] bytes_read The number of bytes successfully read.
/// @retval SEL_STATUS_OUT_OF_RESOURCES Buffer was unable to be allocated, and 
/// the status value is -8.
/// @retval SEL_STATUS_ERROR_HARDWARE_ERROR The device reported a parity error
/// while executing a wait, and the status value is -1.
/// @retval SEL_STATUS_ACCESS_DENIED  The operation overrruns chip range,and the
/// status value is -6.
/// @retval SEL_STATUS_NOT_FOUND The flash device could not be located and the
/// status value is -5
/// @retval SEL_STATUS_SUCCESS Data was successfully read from flash, and the
/// status value is 0.
/// @remarks buffer is allocated in dump_flash_to_file () and freed at the
/// end of the function dump_flash_to_file (). 
///////////////////////////////////////////////////////////////////////////////
SEL_STATUS flash_read_data(
   UINT32 volatile *device_bar,
   UINT8 *buffer,
   UINT32 start_address,
   UINT32 count,
   UINT32 *const bytes_read
   );

#ifdef __cplusplus
}
#endif

#endif // _FLASH_H_
