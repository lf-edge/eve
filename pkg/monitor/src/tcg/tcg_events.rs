// Copyright (c) 2025-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::efi::device_path::traits::DevicePathReadEx as _;

use super::tcg_tpmlog::{TcgRawTpmEvent, TcgTpmEventType};
use anyhow::{Context, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read};
use uuid::Uuid;

pub struct TcgUefiImageLoadEvent {
    pub image_location_in_memory: u64,
    pub image_length_in_memory: u64,
    pub image_link_time_address: u64,
    pub length_of_device_path: u64,
    pub device_path: Vec<u8>,
}

#[derive(Debug)]
pub struct TcgEfiVariableEvent {
    pub vendor_guid: Uuid,
    pub unicode_name: String,
    pub variable_data: Vec<u8>,
}

impl TryFrom<TcgRawTpmEvent> for TcgUefiImageLoadEvent {
    type Error = anyhow::Error;

    fn try_from(value: TcgRawTpmEvent) -> std::result::Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&TcgRawTpmEvent> for TcgUefiImageLoadEvent {
    type Error = anyhow::Error;

    fn try_from(value: &TcgRawTpmEvent) -> std::result::Result<Self, Self::Error> {
        // the event is valid for PCR 2,4 only
        if value.pcr_index != 2 && value.pcr_index != 4 {
            return Err(anyhow::anyhow!(
                "Invalid PCR index for UEFI image load event {}",
                value.pcr_index
            ));
        }

        // FIXME: other events also use this sctructure but for now it is OK
        if value.event_type != TcgTpmEventType::EfiBootServicesApplication {
            return Err(anyhow::anyhow!(
                "Invalid event type for UEFI image load event {}",
                value.event_type
            ));
        }

        let mut cursor = Cursor::new(&value.event_data);

        let image_location_in_memory = cursor.read_u64::<LittleEndian>()?;
        let image_length_in_memory = cursor.read_u64::<LittleEndian>()?;
        let image_link_time_address = cursor.read_u64::<LittleEndian>()?;
        let length_of_device_path = cursor.read_u64::<LittleEndian>()?;

        let mut device_path = vec![0u8; length_of_device_path as usize];
        cursor.read_exact(&mut device_path)?;

        Ok(TcgUefiImageLoadEvent {
            image_location_in_memory,
            image_length_in_memory,
            image_link_time_address,
            length_of_device_path,
            device_path,
        })
    }
}

// corresponds to EV_IPL event
pub struct TcgIPLEvent(String);

impl TcgIPLEvent {
    pub fn get(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&TcgRawTpmEvent> for TcgIPLEvent {
    type Error = anyhow::Error;

    fn try_from(value: &TcgRawTpmEvent) -> std::result::Result<Self, Self::Error> {
        if value.event_type != TcgTpmEventType::IPL {
            return Err(anyhow::anyhow!(
                "Invalid event type for IPL event {}",
                value.event_type
            ));
        }

        let mut cursor = Cursor::new(&value.event_data);
        let event_data = cursor
            .read_null_terminated_ascii_to_string()
            .context("Error converting event data to null-terminated string")?;

        Ok(TcgIPLEvent(event_data.to_string()))
    }
}

pub struct TcgEfiActionEvent(String);

impl TcgEfiActionEvent {
    pub fn get(&self) -> &str {
        &self.0
    }
}

impl TryFrom<TcgRawTpmEvent> for TcgEfiActionEvent {
    type Error = anyhow::Error;

    fn try_from(value: TcgRawTpmEvent) -> std::result::Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&TcgRawTpmEvent> for TcgEfiActionEvent {
    type Error = anyhow::Error;

    fn try_from(value: &TcgRawTpmEvent) -> Result<Self> {
        if value.event_type != TcgTpmEventType::EfiAction {
            return Err(anyhow::anyhow!(
                "Invalid event type for action event {}",
                value.event_type
            ));
        }

        let evetnt_value = std::str::from_utf8(&value.event_data)
            .context("Error converting event data to utf-8 string")?;

        Ok(TcgEfiActionEvent(evetnt_value.to_string()))
    }
}

impl TryFrom<TcgRawTpmEvent> for TcgEfiVariableEvent {
    type Error = anyhow::Error;

    fn try_from(value: TcgRawTpmEvent) -> std::result::Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&TcgRawTpmEvent> for TcgEfiVariableEvent {
    type Error = anyhow::Error;

    fn try_from(value: &TcgRawTpmEvent) -> std::result::Result<Self, Self::Error> {
        if !value.event_type.is_efi_boot_variable() {
            return Err(anyhow::anyhow!(
                "Invalid event type for EFI variable boot event {}",
                value.event_type
            ));
        }

        let event_data = TcgEfiVariableEvent::parse(&value.event_data)?;

        Ok(event_data)
    }
}

impl TcgEfiVariableEvent {
    fn parse(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);

        // Read vendor GUID (16 bytes)
        let mut vendor_guid = [0u8; 16];
        cursor.read_exact(&mut vendor_guid)?;

        // convert to GUID
        let vendor_guid = Uuid::from_bytes_le(vendor_guid);

        // Read the UTF-16LE encoded name length in characters (4 bytes)
        let name_length_bytes = cursor.read_u64::<LittleEndian>()? * 2;
        // Read the variable data length in bytes (4 bytes)
        let data_length_bytes = cursor.read_u64::<LittleEndian>()?;

        // Read the UTF-16LE encoded name
        let mut name_bytes = vec![0u8; name_length_bytes as usize];
        cursor
            .read_exact(&mut name_bytes)
            .context("reading variable name")?;

        let name_utf16: Vec<u16> = name_bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();

        let unicode_name =
            String::from_utf16(&name_utf16).context("Error converting UTF-16 to String")?;

        let mut variable_data = vec![0u8; data_length_bytes as usize];
        cursor.read_exact(&mut variable_data)?;

        Ok(Self {
            vendor_guid,
            unicode_name,
            variable_data,
        })
    }

    // function to serialize the data to [u8]
    // used only for test
    #[cfg(test)]
    pub fn serialize(&self) -> Vec<u8> {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&self.vendor_guid.to_bytes_le());
        data.extend_from_slice(&(self.unicode_name.len() as u64).to_le_bytes());
        data.extend_from_slice(&(self.variable_data.len() as u64).to_le_bytes());
        data.extend_from_slice(
            &self
                .unicode_name
                .encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<u8>>(),
        );
        data.extend_from_slice(&self.variable_data);
        data
    }
}
