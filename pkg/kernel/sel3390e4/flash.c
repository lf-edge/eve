///////////////////////////////////////////////////////////////////////////////
// COPYRIGHT (c) 2014 Schweitzer Engineering Laboratories, Inc.
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
// Schweitzer Engineering Laboratories
// 2350 NE Hopkins Court, Pullman, WA 99163
///////////////////////////////////////////////////////////////////////////////
// This file defines all flash operations for EFI and WDF.
///////////////////////////////////////////////////////////////////////////////

#ifdef WDF_NOR_CONTROLLER

   // WDF Framework
   #include <ntddk.h>
   #include <wdf.h>

#elif defined(__KERNEL__)

   #include <linux/slab.h>    // kmalloc
   #include <linux/delay.h>   // msleep

#else

   // EFI Framework
   #include <Library/DebugLib.h>
   #include <Library/MemoryAllocationLib.h>
   #include <Library/BaseMemoryLib.h>
   #include <Library/UefiLib.h>
   #include "hii_handle.h"

#endif

#include "flash.h"
#include "sel_driver_status.h"
#include "sel_std_types.h"

///////////////////////////////////////////////////////////////////////////////
/// Common address offsets within the Option Bits flash region
/// FUTURE IMPROVEMENT: If a device decides to create it's own option bit 
/// definitions this will need to get sucked in to the per-flash-part 
/// definitions. While MAIN_IMAGE_SIZE_OFFSET is currently not used,
/// we would like to keep it to match the CIS format and possibly for
/// future use.
///////////////////////////////////////////////////////////////////////////////

#define FUNCTIONAL_IMAGE_ADDRESS ((UINT32)(0))
#define FUNCTIONAL_IMAGE_SIZE    ((UINT32)(1))
#define MAIN_IMAGE_SIZE_OFFSET   ((UINT32)(2))

///////////////////////////////////////////////////////////////////////////////
/// Status Definitions
///////////////////////////////////////////////////////////////////////////////

#define STA_CMD_BUSY      ((UINT32)(0x1))
#define STA_DATA_ERASED   ((UINT32)(0x2))
#define STA_FLASH_ENABLED ((UINT32)(0x4)) // STA_ILLEGAL_OP for B2077
#define STA_PARITY_ERROR  ((UINT32)(0x8))

// Flash ID for b2077 flash parts 
#define MICRON_CAPACITY_ID 0x18U
#define ATMEL_CAPACITY_ID  0x04U

///////////////////////////////////////////////////////////////////////////////
/// @remarks m_known_flash_parts is a table of known flash parts, keeping
/// track of how many flash part and device combinations there are.
/// The values in m_known_flash parts are directly taken from the 
/// b_2077_top_cis and b_2076_top_cis documents, and the values should also be
/// current to the newest version of each CIS.
///////////////////////////////////////////////////////////////////////////////
static FLASH_DESCRIPTION const m_known_flash_parts [] =
{
   // Micron NOR Flash (b2077)
   {
      MICRON_CAPACITY_ID, /// .manufacturer_id ID (Capacity ID)
      0x00u,              /// .device_id (unused)
      0x10000u,           /// .uniform_erase_bytes - 64KB
      CMD_SECTOR_ERASE,   /// .erase_command
      SPI_CMD_WRITE,      /// .write_command
      0x00u,              /// .chip_timing (unused)
      0x00u,              /// .program delay (unused
      16777216u,          /// .capacity, 128Mb
      2u,                 /// .number_flash_regions

      /// Flash Regions
      {
         // Functional Image
         {
                 0x0000000u, // .address, 0x00000000 - 0x7FFFFF
                 8388608u    // .length
         },

         // R/W User Storage
         {
                 0x00800000u, // .address, 0x00800000 - 0xFFFFFF
                 8388608u     // .length
         }
      },

      /// The following bits are indices to identify where each region
      /// lies within flash(eg. option_bits live at FlashRegion[0])
      /// An index of MAX_NUM_FLASH_REGIONS denotes that this flash part
      /// does not have that region.
      MAX_NUM_FLASH_REGIONS,  /// .option_bits
      1u,                     /// .rw_settings
      MAX_NUM_FLASH_REGIONS,  /// .read_only_settings
      MAX_NUM_FLASH_REGIONS,  /// .main_image
      0u,                     /// .functional_image
      MAX_NUM_FLASH_REGIONS,  /// .upgrade_image_a
      MAX_NUM_FLASH_REGIONS,  /// .upgrade_image_b
      MAX_NUM_FLASH_REGIONS,  /// .upgrade_image_c
      1u,                     /// .native_word_size
      0x0100u                 /// .max_buffer_size, 256 Bytes 
   },

   // Atmel NOR Flash (b2077)
   {
      ATMEL_CAPACITY_ID, /// .manufacturer_id ID (Capacity ID)
      0x00u,             /// .device_id (unused
      0x10000u,          /// .uniform_erase_bytes - 2K word, 4KB
      CMD_SECTOR_ERASE,  /// .erase_command
      SPI_CMD_WRITE,     /// .write_command
      0x00u,             /// .chip_timing (unused)
      0x00u,             /// .program_delay (unused
      524288u,           /// .capacity, 512Kb
      2u,                /// .number_flash_regions

      /// Flash Regions
      {
         // Functional Image
         {
                 0x00000u, // .address, 0x00000 - 0xFFFF
                 65536u    // .length
         },

         // R/W User Storage
         {
                 0x10000, // .address, 0x10000 - 0x7FFFF
                 458752u  // .length
         }
      },

      /// The following bits are indices to identify where each region
      /// lies within flash(eg. option_bits live at FlashRegion[0])
      /// An index of MAX_NUM_FLASH_REGIONS denotes that this flash part
      /// does not have that region.
      MAX_NUM_FLASH_REGIONS,  /// .option_bits
      1u,                     /// .rw_settings
      MAX_NUM_FLASH_REGIONS,  /// .read_only_settings
      MAX_NUM_FLASH_REGIONS,  /// .main_image
      0u,                     /// .functional_image
      MAX_NUM_FLASH_REGIONS,  /// .upgrade_image_a
      MAX_NUM_FLASH_REGIONS,  /// .upgrade_image_b
      MAX_NUM_FLASH_REGIONS,  /// .upgrade_image_c
      1u,                     /// .native_word_size
      0x0100u                 /// .max_buffer_size, 256 Bytes
   },

   // ----- ///
   /// Microchip
   /// SST39VF801C
   /// -- SAMPLE, not for production --
   {
      0xBFu,            /// .manufacturer_id ID
      0x233Bu,          /// .device_id
      0x1000u,          /// .uniform_erase_bytes - 2K word, 4KB
      CMD_SECTOR_ERASE, /// .erase_command
      CMD_PROGRAM,      /// .write_command
      0x05552203u,      /// .chip_timing
      0x3E8u,           /// .program_delay - 16us
      1048576u,         /// .capacity - 1MB
      3u,               /// .number_flash_regions

      /// Flash Regions
      {
         /// Option Bits
         {
            0x00000u,   /// .address
            4096u       /// .length
         },

         /// R/W User Storage
         {
            0x00800u,   /// .address
            94208u      /// .length
         },

         /// Functional Image
         {
            0x0C000u,   /// .address
            950272u     /// .length
         },
      },

      /// The following bits are indices to identify where each region
      /// lies within flash(eg. option_bits live at FlashRegion[0])
      /// An index of MAX_NUM_FLASH_REGIONS denotes that this flash part
      /// does not have that region.
      0u,                     /// .option_bits
      1u,                     /// .rw_settings
      MAX_NUM_FLASH_REGIONS,  /// .read_only_settings
      MAX_NUM_FLASH_REGIONS,  /// .main_image
      2u,                     /// .functional_image
      MAX_NUM_FLASH_REGIONS,  /// .upgrade_image_a
      MAX_NUM_FLASH_REGIONS,  /// .upgrade_image_b
      MAX_NUM_FLASH_REGIONS,  /// .upgrade_image_c
      2u,                     /// .native_word_size
      0x2000u                 /// .max_buffer_size, 8KB
   },

   /// Microchip
   /// SST39VF1601C
   {
      0xBFu,            /// .manufacturer_id
      0x234Fu,          /// .device_id
      0x1000u,          /// .uniform_erase_bytes - 2K word, 4KB
      CMD_SECTOR_ERASE, /// .erase_command
      CMD_PROGRAM,      /// .write_command
      0x05552203u,      /// .chip_timing
      0x3E8u,           /// .program_delay - 16uss
      2097152u,         /// .capacity - 2MB
      5u,               /// .number_flash_regions

      /// Flash Regions
      {
         /// Option Bits
         {
            0x00000u,   /// .address
            4096u       /// .length
         },

         /// R/W User Storage
         {
            0x00800u,   /// .address
            94208u      /// .length
         },

         /// Functional Image
         {
            0x0C000u,   /// .address
            950272u     /// .length
         },

         /// R/O User Settings
         {
            0x80000u,   /// .address
            98304u      /// .length
         },

         /// Main Image
         {
            0x8C000u,   /// .address
            950272u     /// .length
         }
      },

      /// The following bits are indices to identify where each region
      /// lies within flash(eg. option_bits live at FlashRegion[0])
      /// An index of MAX_NUM_FLASH_REGIONS denotes that this flash part
      /// does not have that region.
      0u,                     /// .option_bits
      1u,                     /// .rw_settings
      3u,                     /// .read_only_settings
      4u,                     /// .main_image
      2u,                     /// .functional_image
      MAX_NUM_FLASH_REGIONS,  /// .upgrade_image_a
      MAX_NUM_FLASH_REGIONS,  /// .upgrade_image_b
      MAX_NUM_FLASH_REGIONS,  /// .upgrade_image_c
      2u,                     /// .native_word_size
      0x2000u                 /// .max_buffer_size, 8KB
   },

   /// MXIC - Macronix International Co, LTD.
   /// MX29GL256F
   {
      0xC2u,            /// .manufacturer_id
      0x227Eu,          /// .device_id
      0x20000u,         /// .uniform_erase_bytes - 64K word, 128KB
      CMD_SECTOR_ERASE, /// .erase_command
      CMD_PROGRAM,      /// .write_command
      0x0D662406u,      /// .chip_timing
      0xAFC8u,          /// .program_delay - 360us
      33554432u,        /// .capacity - 32MB
      7u,               /// .number_flash_regions

      /// Flash Regions
      {
         /// Option Bits
         {
            0x000000u,  /// .address
            131072u     /// .length
         },

         /// R/W User Storage
         {
            0x010000u,   /// .address
            1966080u     /// .length
         },

         /// Upgrade Image A
         {
            0x100000u,  /// ,address
            8388608u    /// .length
         },
         /// Upgrade Image B
         {
            0x500000u,  /// .address
            8388608u    /// .length
         },

         /// Upgrade Image C
         {
            0x900000u,  /// .address
            8388608u    /// .length
         },

         /// R/O User Storage
         {
            0xD00000u,  /// .address
            2097152u    /// .length
         },

         /// Main Image
         {
            0xE00000u,  /// .address
            4194304u    /// .length
         },
      },

      /// The following bits are indices to identify where each region
      /// lies within flash(eg. option_bits live at FlashRegion[0])
      /// An index of MAX_NUM_FLASH_REGIONS denotes that this flash part
      /// does not have that region.
      0u,                     /// .option_bits
      1u,                     /// .rw_settings
      5u,                     /// .read_only_settings
      6u,                     /// .main_image
      MAX_NUM_FLASH_REGIONS,  /// .functional_image
      2u,                     /// .upgrade_image_a
      3u,                     /// .upgrade_image_b
      4u,                     /// .upgrade_image_c
      2u,                     /// .native_word_size
      0x2000u                 /// .max_buffer_size, 8KB
   }
};

#define NUM_KNOWN_FLASH_PARTS (UINT8)(sizeof(m_known_flash_parts)/sizeof(m_known_flash_parts[0]))

///////////////////////////////////////////////////////////////////////////////
/// @brief Checks the defined list of known devices, m_known_flash_parts, 
/// against the manufacturer and the device ID's to determine which device
/// specs we will be using.
/// @param[in] device_bar The device's base address register.
/// @param[out] flash_part A structure that contains the addresses of the
/// main/functional images and other defined device information.
/// @retval SEL_STATUS_NOT_FOUND An unknown flash part was found, return value
/// is -5.
/// @retval SEL_STATUS_SUCCESS The device was matched with a device in the
/// known device list, m_known_flash_parts. The return value is 0.
///////////////////////////////////////////////////////////////////////////////
static SEL_STATUS flash_find_part(
   UINT32 volatile *device_bar,
   FLASH_DESCRIPTION const **flash_part
   )
{
   SEL_STATUS status = SEL_STATUS_NOT_FOUND;
   UINT8 index = 0;
   UINT8 manufacturer_id = 0;
   UINT16 device_id = 0;

   // What are the manufacture and device IDs for this device's flash?
   status = flash_get_ids(device_bar, &manufacturer_id, &device_id);
   if (SEL_SUCCESS(status))
   {
      // See if we know about the attached flash part
      for (index = 0; index < NUM_KNOWN_FLASH_PARTS; index++)
      {
         if ((manufacturer_id == m_known_flash_parts[index].manufacturer_id) &&
            (device_id == m_known_flash_parts[index].device_id))
         {
             *flash_part = &(m_known_flash_parts[index]);
             status = SEL_STATUS_SUCCESS;
             break;
         }
      }

      // Unknown flash part found
      if (index == NUM_KNOWN_FLASH_PARTS)
      {
         *flash_part = NULL;
         status = SEL_STATUS_NOT_FOUND;
      }
   }

   return status;
}


///////////////////////////////////////////////////////////////////////////////
/// @brief Uses the base address register to make sure the write operation will
/// not go beyond the chip's capacity.
/// @param[in] device_bar The device's base address register, which is passed 
/// into flash_find_part() to identify the device 
/// @param[in] start_address The address to begin the operation at
/// @param[in] count The size in bytes the operation will need on the chip
/// @retval SEL_SUCCESS The operation can be carried out, and the status value 
/// is 0
/// @retval SEL_STATUS_ACCESS_DENIED  The operation overrruns chip range, and 
/// the return value is -6.
/// @retval SEL_STATUS_NOT_FOUND The flash device could not be located, and the
/// return value is -5.
///////////////////////////////////////////////////////////////////////////////
static SEL_STATUS flash_operation_in_range(
   UINT32 volatile *device_bar,
   UINT32 start_address,
   UINT32 count
   )
{
   SEL_STATUS status = SEL_STATUS_NOT_FOUND;
   FLASH_DESCRIPTION const *flash_device = NULL;

   // Find the flash part
   status = flash_find_part(device_bar, &flash_device);
   if (SEL_SUCCESS(status) && (NULL != flash_device))
   {
      // Make sure we aren't erasing off the end of the device
      // NOTE: start_address is a word address, count and capacity are in bytes
      // Start_address is temporarily promoted to UINT64 to prevent the case of overflow
      // otherwise start_address is never larger then UINT32

      if (((((UINT64)start_address) * flash_device->native_word_size) + count) > flash_device->capacity)
      {
         status = SEL_STATUS_ACCESS_DENIED;
      }

      else
      {
         status = SEL_STATUS_SUCCESS;
      }
   }

   return status;
}

///////////////////////////////////////////////////////////////////////////////
/// @see flash.h for documentation.
///////////////////////////////////////////////////////////////////////////////
SEL_STATUS flash_wait(
   UINT32 volatile * device_bar
   )
{
   SEL_STATUS status = SEL_STATUS_SUCCESS;
   
   while (STA_CMD_BUSY == (*(device_bar+STATUS_REG) & STA_CMD_BUSY)){}

   // Check for any parity errors
   if (STA_PARITY_ERROR == (*(device_bar+STATUS_REG) & STA_PARITY_ERROR))
   {
      status = SEL_STATUS_ERROR_HARDWARE_ERROR;
   }

   return status;
}

///////////////////////////////////////////////////////////////////////////////
/// @see flash.h for documentation.
///////////////////////////////////////////////////////////////////////////////
SEL_STATUS flash_get_ids(
   UINT32 volatile *device_bar,
   UINT8 *manufacturer_id,
   UINT16 *device_id
   )
{
   SEL_STATUS status = SEL_STATUS_SUCCESS;
   UINT32 cfi_data = 0;

   *(device_bar + LENGTH_REG) = 2;
   *(device_bar + CONTROL_REG) = CMD_CFI_ID;

   status = flash_wait(device_bar);

   if (SEL_SUCCESS(status))
   {
      cfi_data = *(device_bar + DATA_BUFFER_REG);

      *manufacturer_id = (UINT8)cfi_data;
      *device_id = (UINT16)(cfi_data >> 16);

      if ((((UINT8)0 == *manufacturer_id) && ((UINT16)0 == *device_id)) ||
         (((UINT8)0xFF == *manufacturer_id) && ((UINT16)0xFFFF == *device_id))
        )
      {
         status = SEL_STATUS_NOT_FOUND;
      }
   }

   return status;
}

///////////////////////////////////////////////////////////////////////////////
/// @see flash.h for documentation.
///////////////////////////////////////////////////////////////////////////////
SEL_STATUS set_or_get_option_bits(
   FLASH_DESCRIPTION const *flash_device,
   UINT32 volatile *base_address,
   UINT32 *image_size,
   UINT32 *default_address,
   SET_OR_GET operation
   )
{
   UINT32 bytes_read = 0;
   UINT8* flash_option_bits = NULL;
   SEL_STATUS status = SEL_STATUS_SUCCESS;

   if ((flash_device->manufacturer_id == MICRON_CAPACITY_ID) 
      || (flash_device->manufacturer_id == ATMEL_CAPACITY_ID))
   {
      // This device does not need option bits updated. There is ONLY one
      // image location to write to.
      return status;
   }

#ifdef WDF_NOR_CONTROLLER

   flash_option_bits = (UINT8*)ExAllocatePoolWithTag(
         NonPagedPool,
         (UINT32)flash_device->flash_regions[flash_device->option_bits].length,
         'LES');

#elif !defined(__KERNEL__)

   flash_option_bits = (UINT8*)AllocateZeroPool(
       flash_device->flash_regions[flash_device->option_bits].length
       );

#endif

   if (flash_option_bits == NULL)
   {
       status = SEL_STATUS_OUT_OF_RESOURCES;
       goto err_free_option_bits;
   }

   // Perform the operation
   if (operation == GET_OPTION_BITS)
   {
      status = flash_read_data(
            base_address,
            flash_option_bits,
            flash_device->flash_regions[flash_device->option_bits].address,
            flash_device->flash_regions[flash_device->option_bits].length,
            &bytes_read
            );

      if (!SEL_SUCCESS(status))
      {
         goto err_free_option_bits;
      }
      // Get the image start address from the option bits
      *default_address = *((UINT32*)(flash_option_bits) + FUNCTIONAL_IMAGE_ADDRESS);

      // Make sure the image location isn't in the space reserved
      // for the option bits
      // Validate the image address we pulled from flash
      if ((*default_address > flash_device->flash_regions[flash_device->option_bits].address) &&
          *default_address < (flash_device->flash_regions[flash_device->option_bits].address +
          (flash_device->flash_regions[flash_device->option_bits].length/flash_device->native_word_size)))
      {
         status = SEL_STATUS_INTERNAL_ERROR;
         goto err_free_option_bits;
      }

      // Get the image size from the option bits, make sure it's valid
      *image_size = *((UINT32*)(flash_option_bits) + FUNCTIONAL_IMAGE_SIZE);

      if ((*image_size == 0xFFFFFFFFu) || (*image_size == 0))
      {
         status = SEL_STATUS_INTERNAL_ERROR;
         goto err_free_option_bits;
      }
   }

   else if (operation == SET_OPTION_BITS)
   {
      // if the address with the option bits range, the address is invalid.
      // for this device, the address is invalid
      if ((*default_address > flash_device->flash_regions[flash_device->option_bits].address) &&
          *default_address < (flash_device->flash_regions[flash_device->option_bits].address +
          (flash_device->flash_regions[flash_device->option_bits].length/flash_device->native_word_size)))
      {
         status = SEL_STATUS_INTERNAL_ERROR;
         goto err_free_option_bits;
      }

      // Validate the image size
      if ((*image_size == 0) || (*image_size == 0xFFFFFFFFu))
      {
         status = SEL_STATUS_INTERNAL_ERROR;
         goto err_free_option_bits;
      }

      // Modify the Option bits
      *((UINT32*)(flash_option_bits)+ FUNCTIONAL_IMAGE_ADDRESS)= *default_address;
      *((UINT32*)(flash_option_bits)+ FUNCTIONAL_IMAGE_SIZE)= *image_size;

      // Read, Modify, Erase, Write
      status = flash_erase_data(
               base_address,
               flash_device->flash_regions[flash_device->option_bits].address,
               flash_device->flash_regions[flash_device->option_bits].length
               );

      if (!SEL_SUCCESS(status))
      {
         goto err_free_option_bits;
      }

      status = flash_write_data(
               base_address,
               flash_option_bits,
               flash_device->flash_regions[flash_device->option_bits].address,
               flash_device->flash_regions[flash_device->option_bits].length,
               &bytes_read
               );
   }
err_free_option_bits:

   if(NULL != flash_option_bits)
   {
      // Free the memory created when reading the option bits data
#ifdef WDF_NOR_CONTROLLER

      ExFreePoolWithTag((VOID*)flash_option_bits, 'LES');

#elif defined(__KERNEL__)

      kfree((VOID*)flash_option_bits);

#else

      FreePool((VOID*) flash_option_bits);

#endif

      flash_option_bits = NULL;
   }
   return status;
}

///////////////////////////////////////////////////////////////////////////////
/// @see flash.h for documentation.
///////////////////////////////////////////////////////////////////////////////
SEL_STATUS flash_initialize_chip_timing(
   UINT32 volatile *device_bar,
   FLASH_DESCRIPTION const **flash_device
   )
{
   SEL_STATUS status = SEL_STATUS_SUCCESS;

   // Force reset the device
   *(device_bar + CONTROL_REG) = CMD_RESET;

   // Enable the device
   *(device_bar+CONTROL_REG) = CMD_ENABLE;
   
   // Wait to see if the device is enabled
   status = flash_wait(device_bar);

   if ((!SEL_SUCCESS(status))) 
      // Here we would normally check whether we were able to succesfully enable
      // the flash. However, not all flash parts support an ENABLED status, so 
      // we assume that it work. It we weren't able to enable the part, the 
      // call to find the part will fail anyway, so this is ok.
      // (STA_FLASH_ENABLED != (*(device_bar+STATUS_REG) & STA_FLASH_ENABLED)))
   {
      status = SEL_STATUS_ERROR_HARDWARE_ERROR;
   }
   else 
   {
       // Figure out which flash part this device has
       status = flash_find_part(device_bar, flash_device);

       if (!SEL_SUCCESS(status) || (NULL == *flash_device))
       {
           status = SEL_STATUS_ERROR_HARDWARE_ERROR;
       }

       else if (((*flash_device)->manufacturer_id == MICRON_CAPACITY_ID) 
          || ((*flash_device)->manufacturer_id == ATMEL_CAPACITY_ID))
       {
          // b2077 nor flash needs to perform dummy cycles

          *(device_bar + CONTROL_REG) = SPI_CMD_DUMMY_CYCLES;
          status = flash_wait(device_bar);

       }
       else
       {
           // Set chip_timing and program delay if the 
           // current chip_timing values are invalid
           
           if ((*(device_bar+CHIP_TIMING_REG) == (UINT32)0x0) || 
               (*(device_bar+CHIP_TIMING_REG) == (UINT32)0xFFFFFFFF))
           {
               *(device_bar+CHIP_TIMING_REG) = (*flash_device)->chip_timing;
           }

           if ((*(device_bar+PROG_DELAY_REG) == (UINT32)0x0) || 
               (*(device_bar+PROG_DELAY_REG) == (UINT32)0xFFFFFFFF))
           {
               *(device_bar+PROG_DELAY_REG) = (*flash_device)->program_delay;
           }
       }
   }

   return status;
}

///////////////////////////////////////////////////////////////////////////////
/// @see flash.h for documentation.
///////////////////////////////////////////////////////////////////////////////
SEL_STATUS flash_erase_data(
      UINT32 volatile *device_bar,
      UINT32 start_address,
      UINT32 count
      )
{
   SEL_STATUS status = SEL_STATUS_NOT_FOUND;
   FLASH_DESCRIPTION const *flash_device = NULL;
   UINT32 num_erases = 0;
   BOOLEAN erase_complete = FALSE;

   if (0 == count)
   {
      status = SEL_STATUS_SUCCESS;
      goto err_flash_read;
   }

   // Find the flash part
   status = flash_find_part(device_bar, &flash_device);
   if (!SEL_SUCCESS(status) || (NULL == flash_device))
   {
      status = SEL_STATUS_NOT_FOUND;
      goto err_flash_read;
   }

   // Make sure the address given is on an erase boundary
   if (0 != (start_address % flash_device->uniform_erase_bytes))
   {
      status = SEL_STATUS_UNSUPPORTED;
      goto err_flash_read;
   }

   // Make sure we aren't erasing off the end of the device
   status = flash_operation_in_range(device_bar, start_address, count);
   if (SEL_SUCCESS(status))
   {
      ASSERT(flash_device->uniform_erase_bytes != 0);

      // Figure out how many erases block/sectors we need
      num_erases = (count / flash_device->uniform_erase_bytes);
      
      if ((count % flash_device->uniform_erase_bytes) > 0)
      {
         ++num_erases;
      }
      ASSERT(num_erases != 0);

      // Do the erasing
      do
      {
         status = flash_wait(device_bar);
         if (!SEL_SUCCESS(status))
         {
            goto err_flash_read;
         }
         // Set address to erase
         *(device_bar+ADDRESS_REG) = start_address;

         // Issue the erase Command
         *(device_bar+CONTROL_REG) = flash_device->erase_command;

#if defined(__KERNEL__)
         /* The subsequent flash_wait takes considerable time following an erase.
          * The CPU needs time available to service other threads.
          * 1/2 second was chosen based on the specified duration of an erase.
          */

         /* .5 s delay */
         msleep(500);
#endif      
         erase_complete = FALSE;

         // Make sure everything got erased
         do
         {
            // Wait for device not busy
            status = flash_wait(device_bar);
            if (!SEL_SUCCESS(status))
            {
               goto err_flash_read;
            }

            // Set length to match size of erase
            *(device_bar+LENGTH_REG) =
               (flash_device->uniform_erase_bytes / flash_device->native_word_size);

            // Read back the erased data
            *(device_bar+CONTROL_REG) = CMD_READ;

            // Wait for device not busy
            status = flash_wait(device_bar);
            if (!SEL_SUCCESS(status))
            {
               goto err_flash_read;
            }

            // Check to see if the all the bytes read are 0xFF
            if ((*(device_bar + STATUS_REG) 
               & STA_DATA_ERASED) == STA_DATA_ERASED)
            {
               erase_complete = TRUE;
            }

         } while (!erase_complete);

         // Update the _word_ address to erase
         start_address += 
            (flash_device->uniform_erase_bytes / flash_device->native_word_size);

      } while (--num_erases > 0);
   } // operation_in_range

err_flash_read:

   return status;
}

///////////////////////////////////////////////////////////////////////////////
/// @see flash.h for documentation.
///////////////////////////////////////////////////////////////////////////////
SEL_STATUS flash_write_data(
      UINT32 volatile *device_bar,
      UINT8           *buffer,
      UINT32          start_address,
      UINT32          count,
      UINT32          *const bytes_written
      )
{
   SEL_STATUS  status       = SEL_STATUS_SUCCESS;
   UINT32      write_length = 0;
   UINT32      error_count  = 0;
   UINT32      index        = 0;
   UINT32      last_bytes   = 0;
   FLASH_DESCRIPTION const *flash_device = NULL;

#if defined(__KERNEL__)
   UINT32      total_writes = 0;
#endif

   if ((NULL == buffer) || (NULL == bytes_written))
   {
      status = SEL_STATUS_INVALID_PARAMETER;
      return status;
   }

   *bytes_written = 0;

   // Find the flash part
   status = flash_find_part(device_bar, &flash_device);
   if (!SEL_SUCCESS(status) || (NULL == flash_device))
   {
      return SEL_STATUS_NOT_FOUND;
   }

   // Make sure we aren't erasing off the end of the device
   status = flash_operation_in_range(device_bar, start_address, count);
   if (SEL_SUCCESS(status))
   {

      while (*bytes_written < count)
      {
         if ((count - *bytes_written) >= flash_device->max_buffer_size)
         {
            write_length = flash_device->max_buffer_size;
         }
         else
         {
            write_length = count - *bytes_written;
         }

         // Set the address to write to
         *(device_bar+ADDRESS_REG) = start_address +
            (*bytes_written / flash_device->native_word_size);
         
         // Set the amount to write
         if (flash_device->max_buffer_size == write_length)
         {
            *(device_bar+LENGTH_REG) = MAX_DATA_BUFFER_LENGTH;
         }
         else
         {
            *(device_bar+LENGTH_REG) = 
               (write_length / flash_device->native_word_size) + 
               (write_length % flash_device->native_word_size);
         }

         // Fill the Databuffer
         if (error_count == 0)
         {
            index = 0;
            while (write_length > 0)
            {
               if (write_length >= sizeof(UINT32))
               {
                  *(device_bar+DATA_BUFFER_REG+index++) =
                     *((UINT32*)(buffer + *bytes_written));

                  write_length -= sizeof(UINT32);
                  *bytes_written += sizeof(UINT32);
               }
               else
               {
                   // We can take a UINT32* size part of the buffer because
                   // we allocated extra space to prevent reading past the
                   // end of the buffer.

                   last_bytes = *((UINT32*)(buffer + *bytes_written));

                   // The buffer was allocated with extra space, and we need
                   // to set that space to FF values
                   last_bytes |= ((0xFFFFFFFFu) << ((count % 4 )*8));

                  // Set the bytes
                  *(device_bar+DATA_BUFFER_REG+index) = last_bytes;

                  // Update bytes_written
                  (*bytes_written) += write_length;
                  write_length = 0;
               }
            }
         }

         // Wait until the flash is ready
         // Disregard any error status, we just want to make sure it's not busy
         status = flash_wait(device_bar);
         if (!SEL_SUCCESS(status))
         {
             break;
         }
         // Issue WRITE Command
         *(device_bar + CONTROL_REG) = flash_device->write_command;

#if defined(__KERNEL__)
         /* The subsequent flash_wait takes considerable time following a write.
          * The CPU needs time available to service other threads,
          * so we sleep every 250 iterations.  250 was chosen based on the
          * specified write speed of the flash part.
          */
         if ((++total_writes % 250) == 0) {
            /* 1 ms delay */
            msleep(1);
         }
#endif      

         // Check for errors
         status = flash_wait(device_bar);
         if (!SEL_SUCCESS(status))
         {
            // Don't update bytes_written, we want to WRITE same location again
            // Only give it 3 attempts to WRITE from flash
            if (++error_count >= 3)
            {
               break;
            }
         }
         else
         {
            error_count = 0;
         }

      }  // bytes_written < count
   }  // operationInRange
   
   return status;
}

///////////////////////////////////////////////////////////////////////////////
/// @see flash.h for documentation.
///////////////////////////////////////////////////////////////////////////////
SEL_STATUS flash_read_data(
      UINT32  volatile *device_bar,
      UINT8             *buffer,
      UINT32            start_address,
      UINT32            count,
      UINT32            *const bytes_read
      )
{
   SEL_STATUS  status = SEL_STATUS_SUCCESS;
   UINT32      read_length = 0;
   UINT32      error_count = 0;
   UINT32      index = 0;
   UINT32      last_bytes = 0;
   FLASH_DESCRIPTION const *flash_device = NULL;

   *bytes_read = 0;

   if (NULL == buffer)
   {
      status = SEL_STATUS_OUT_OF_RESOURCES;
      return status;
   }

   // Find the flash part
   status = flash_find_part(device_bar, &flash_device);
   if (!SEL_SUCCESS(status) || (NULL == flash_device))
   {
      return SEL_STATUS_NOT_FOUND;
   }

   else
   {
      // Make sure we aren't reading off the end of the device
      status = flash_operation_in_range(device_bar, start_address, count);
      if(SEL_SUCCESS(status))
      {
         while (*bytes_read < count)
         {
            if ((count - *bytes_read) >= flash_device->max_buffer_size)
            {
               read_length = flash_device->max_buffer_size;
            }
            else
            {
               read_length = count - *bytes_read;
            }

            // Set the address to read from
            *(device_bar+ADDRESS_REG) = start_address +
               (*bytes_read / flash_device->native_word_size) + 
               (*bytes_read % flash_device->native_word_size);
           
            // Set the amount to read
            if (flash_device->max_buffer_size == read_length)
            {
               *(device_bar+LENGTH_REG)= MAX_DATA_BUFFER_LENGTH;
            }
            else
            {
               *(device_bar+LENGTH_REG) =
                  (read_length / flash_device->native_word_size)+
                  (read_length % flash_device->native_word_size);
            }

            //
            // Disregard any error status, we just want to make sure it's
            // not busy
            //

            status = flash_wait(device_bar);
            if (!SEL_SUCCESS(status))
            {
                break;
            }
            // Issue READ Command
            *(device_bar+CONTROL_REG)= CMD_READ;

            // Wait until the flash is ready
            status = flash_wait(device_bar);
            if (!SEL_SUCCESS(status))
            {
               // Don't update bytes_read, we want to READ same location again
               // Only give it 3 attempts to READ from flash
               if(++error_count >= 3)
               {
                  break;
               }
            }
            else
            {
               error_count = 0;
               index = 0;
               while (read_length > 0)
               {
                  if (read_length >= sizeof(UINT32))
                  {
                     *((UINT32*)(buffer + *bytes_read)) =
                        *(device_bar+DATA_BUFFER_REG+index++);

                     read_length -= sizeof(UINT32);
                     *bytes_read += sizeof(UINT32);
                  }
                  else
                  {
                     last_bytes = *(device_bar+DATA_BUFFER_REG+index);

                     // Copy over only the remaining bytes
                     while (read_length > 0)
                     {
                        *(buffer + *bytes_read) = (UINT8)last_bytes;

                        last_bytes >>= 8;
                        --read_length;
                        ++(*bytes_read);
                     }
                  }
               }
            }
         }  // bytes_read < count
      }  // operationInRange
   }
   return status;
}
