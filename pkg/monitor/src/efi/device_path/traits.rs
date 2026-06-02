// Copyright (c) 2025-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Context, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};

pub enum NodeExpectedLength {
    Exact(u16),
    Min(u16),
}

pub(crate) trait NodeTypeValidator {
    fn expected_length(&self) -> NodeExpectedLength;
    fn validate_length(&self, length: u16) -> Result<()> {
        match self.expected_length() {
            NodeExpectedLength::Exact(expected) => {
                if length != expected {
                    return Err(anyhow!(
                        "invalid length for device path sub type {}: expected {}, got {}",
                        std::any::type_name_of_val(self),
                        expected,
                        length
                    ));
                }
            }
            NodeExpectedLength::Min(min) => {
                if length < min {
                    return Err(anyhow!(
                        "invalid length for device path sub type {}: expected at least {}, got {}",
                        std::any::type_name_of_val(self),
                        min,
                        length
                    ));
                }
            }
        }
        Ok(())
    }
}

pub trait DevicePathReadEx: ReadBytesExt {
    fn read_null_terminated_ascii_to_string(&mut self) -> Result<String> {
        let mut chars = Vec::new();
        loop {
            match self.read_u8() {
                Ok(0) => break,
                Ok(c) => {
                    if !c.is_ascii() {
                        return Err(anyhow!("invalid ascii control character: {}", c));
                    }
                    chars.push(c)
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Err(anyhow!("missing null terminator"))
                }
                Err(e) => return Err(anyhow!("error reading null terminated string: {}", e)),
            }
        }
        String::from_utf8(chars).context("error converting ascii string")
    }

    fn read_efi_guid(&mut self) -> Result<uuid::Uuid> {
        let d1: u32 = self.read_u32::<LittleEndian>()?;
        let d2: u16 = self.read_u16::<LittleEndian>()?;
        let d3: u16 = self.read_u16::<LittleEndian>()?;

        let mut d4: [u8; 8] = [0; 8];
        self.read_exact(&mut d4)?;
        Ok(uuid::Uuid::from_fields(d1, d2, d3, &d4))
    }
    fn read_null_terminated_ucs16_to_string(&mut self) -> Result<String> {
        let mut chars = Vec::new();
        loop {
            match self.read_u16::<LittleEndian>() {
                Ok(0) => break,
                Ok(c) => chars.push(c),
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Err(anyhow!("missing null terminator"))
                }
                Err(e) => return Err(anyhow!("error reading null terminated ucs16 string: {}", e)),
            }
        }
        Ok(String::from_utf16(&chars)?)
    }
}

pub trait DevicePathWriteEx: WriteBytesExt {
    fn write_as_null_terminated_ucs16(&mut self, s: &str) -> Result<()> {
        for c in s.encode_utf16() {
            self.write_u16::<LittleEndian>(c)?;
        }
        self.write_u16::<LittleEndian>(0)?;
        Ok(())
    }

    fn write_as_null_terminated_ascii(&mut self, s: &str) -> Result<()> {
        if !s.is_ascii() {
            return Err(anyhow!("string is not ascii"));
        }
        self.write_all(s.as_bytes())?;
        self.write_u8(0)?;
        Ok(())
    }

    fn write_efi_guid(&mut self, guid: &uuid::Uuid) -> Result<()> {
        self.write_u32::<LittleEndian>(guid.as_fields().0)?;
        self.write_u16::<LittleEndian>(guid.as_fields().1)?;
        self.write_u16::<LittleEndian>(guid.as_fields().2)?;
        self.write_all(guid.as_fields().3)?;
        Ok(())
    }
}

impl<W: WriteBytesExt + Write + ?Sized> DevicePathWriteEx for W {}
impl<W: ReadBytesExt + Read + ?Sized> DevicePathReadEx for W {}
