// Copyright (c) 2025-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;

// Variant names follow the UEFI LoadOption attribute spec constants.
#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
enum LoadOptionAttributesBits {
    LoadOptionActive = 0x00000001,
    LoadOptionForceReconnect = 0x00000002,
    LoadOptionHidden = 0x00000008,
    LoadOptionCategory = 0x00001F00,
    LoadOptionCategoryApp = 0x000000100,
    LoadOptionCategoryBoot = 0x000000000,
}

// according to UEFI spec all other bits must be set to 0
const LOAD_OPTION_ATTRIBUTES_ALLOWED_BITS: u32 = LoadOptionAttributesBits::LoadOptionActive as u32
    | LoadOptionAttributesBits::LoadOptionForceReconnect as u32
    | LoadOptionAttributesBits::LoadOptionHidden as u32
    | LoadOptionAttributesBits::LoadOptionCategoryApp as u32;

#[derive(Debug, PartialEq, Clone)]
pub struct LoadOptionAttributes(u32);

impl TryFrom<u32> for LoadOptionAttributes {
    type Error = anyhow::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value & !LOAD_OPTION_ATTRIBUTES_ALLOWED_BITS != 0 {
            return Err(anyhow::anyhow!("UnsupportedAttributes: {}", value));
        }
        Ok(LoadOptionAttributes(value))
    }
}

impl LoadOptionAttributes {
    pub fn is_active(&self) -> bool {
        self.0 & LoadOptionAttributesBits::LoadOptionActive as u32 != 0
    }
    pub fn is_force_reconnect(&self) -> bool {
        self.0 & LoadOptionAttributesBits::LoadOptionForceReconnect as u32 != 0
    }
    pub fn is_hidden(&self) -> bool {
        self.0 & LoadOptionAttributesBits::LoadOptionHidden as u32 != 0
    }
    pub fn category(&self) -> u32 {
        self.0 & LoadOptionAttributesBits::LoadOptionCategory as u32
    }
    pub fn is_category_app(&self) -> bool {
        self.category() == LoadOptionAttributesBits::LoadOptionCategoryApp as u32
    }
    pub fn is_category_boot(&self) -> bool {
        self.category() == LoadOptionAttributesBits::LoadOptionCategoryBoot as u32
    }
}

impl From<LoadOptionAttributes> for u32 {
    fn from(data: LoadOptionAttributes) -> Self {
        data.0
    }
}

impl std::fmt::Display for LoadOptionAttributes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "LoadOptionAttributes {{ active: {}, force_reconnect: {}, hidden: {}, category: {}, category_app: {}, category_boot: {} }}",
            self.is_active(),
            self.is_force_reconnect(),
            self.is_hidden(),
            self.category(),
            self.is_category_app(),
            self.is_category_boot()
        )
    }
}

// see https://uefi.org/sites/default/files/resources/UEFI%20Spec%202_6.pdf
// section "3.1.3 Load Options"
#[derive(Debug, PartialEq)]
pub struct EfiLoadOption {
    pub attributes: LoadOptionAttributes,
    pub description: String,
    pub device_path_list: DevicePath,
    pub optional_data: Option<Vec<u8>>,
}

use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read};

use super::device_path::{traits::DevicePathReadEx, DevicePath};

impl TryFrom<&[u8]> for EfiLoadOption {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::parse_linux_efi_var(value)
    }
}

impl EfiLoadOption {
    pub fn parse_linux_efi_var(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);

        // read 32 bits UEFI variable attributes we do not care about
        // reade WARNING at https://docs.kernel.org/filesystems/efivarfs.html
        let _ = cursor.read_u32::<LittleEndian>()?;

        let attributes = cursor.read_u32::<LittleEndian>()?;
        let attributes = LoadOptionAttributes::try_from(attributes)?;
        let file_path_list_length = cursor.read_u16::<LittleEndian>()?;
        let description = cursor.read_null_terminated_ucs16_to_string()?;

        let mut device_path_list = vec![0; file_path_list_length as usize];
        cursor.read_exact(&mut device_path_list)?;

        // Remaining data is optional
        let mut optional_data = Vec::new();
        cursor.read_to_end(&mut optional_data)?;

        let optional_data = if optional_data.is_empty() {
            None
        } else {
            Some(optional_data)
        };

        Ok(Self {
            attributes,
            description,
            device_path_list: DevicePath::try_from(device_path_list.as_slice())?,
            optional_data,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct EfiBootOrder {
    pub boot_order: Vec<u16>,
}

impl TryFrom<&[u8]> for EfiBootOrder {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        Self::parse_linux_efi_var(data)
    }
}

impl EfiBootOrder {
    pub fn parse_linux_efi_var(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);

        // read 32 bits UEFI variable attributes we do not care about
        // reade WARNING at https://docs.kernel.org/filesystems/efivarfs.html
        let _ = cursor.read_u32::<LittleEndian>()?;

        let mut boot_order = Vec::new();
        while cursor.position() < data.len() as u64 {
            let entry = cursor.read_u16::<LittleEndian>()?;
            boot_order.push(entry);
        }

        Ok(Self { boot_order })
    }
}
