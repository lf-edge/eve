// Copyright (c) 2025-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

pub mod acpi;
pub mod hardware;
pub mod media;
pub mod messaging;

pub mod traits;

use acpi::AcpiNode;
use hardware::HardwareNode;
use media::MediaNode;
use messaging::MessagingNode;
use traits::{NodeExpectedLength, NodeTypeValidator};

use byteorder::{LittleEndian, ReadBytesExt};
use num_enum::{FromPrimitive, IntoPrimitive, TryFromPrimitive};
use std::io::{Cursor, Read};
use strum::Display;

#[cfg(test)]
mod tests;
#[cfg(test)]
use macaddr::MacAddr;
#[cfg(test)]
use media::{PartitionSignature, PartitionType};
#[cfg(test)]
use std::net::Ipv4Addr;

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct Node {
    node_type: u8,
    node_sub_type: u8,
    node_length: u16,
    data: Option<Vec<u8>>,
}

impl Node {
    fn is_end(&self) -> bool {
        DevicePathType::from_primitive(self.node_type) == DevicePathType::End
            && self.node_sub_type == DevicePathSubTypeEnd::EndEntire as u8
    }
}

#[derive(Debug, Display, PartialEq)]
#[repr(u8)]
enum DevicePathType {
    Hardware = 0x1,
    Acpi = 0x2,
    Messaging = 0x3,
    Media = 0x4,
    Bios = 0x5,
    End = 0x7f,
    Unknown(u8),
}

impl Into<u8> for DevicePathType {
    fn into(self) -> u8 {
        match self {
            DevicePathType::Hardware => 0x1,
            DevicePathType::Acpi => 0x2,
            DevicePathType::Messaging => 0x3,
            DevicePathType::Media => 0x4,
            DevicePathType::Bios => 0x5,
            DevicePathType::End => 0x7f,
            DevicePathType::Unknown(number) => number,
        }
    }
}

impl FromPrimitive for DevicePathType {
    type Primitive = u8;

    fn from_primitive(number: Self::Primitive) -> Self {
        match number {
            0x1 => DevicePathType::Hardware,
            0x2 => DevicePathType::Acpi,
            0x3 => DevicePathType::Messaging,
            0x4 => DevicePathType::Media,
            0x5 => DevicePathType::Bios,
            0x7f => DevicePathType::End,
            _ => DevicePathType::Unknown(number),
        }
    }
}

#[derive(Debug, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
enum DevicePathSubTypeEnd {
    EndInstance = 0x1,
    EndEntire = 0xff,
}

impl NodeTypeValidator for DevicePathSubTypeEnd {
    fn expected_length(&self) -> NodeExpectedLength {
        match self {
            DevicePathSubTypeEnd::EndInstance => NodeExpectedLength::Exact(4),
            DevicePathSubTypeEnd::EndEntire => NodeExpectedLength::Exact(4),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) enum PathNodeT<A, H, M, MSG>
where
    A: PathNodeTrait,
    H: PathNodeTrait,
    M: PathNodeTrait,
    MSG: PathNodeTrait,
{
    Acpi(A),
    Hardware(H),
    Media(M),
    Messaging(MSG),
    EndInstance,
    EndEntire,
    Unknown(Node),
}

trait PathNodeTrait {
    type Subtype: NodeTypeValidator + FromPrimitive + Into<u8>;
    fn get_generic_name(&self) -> &'static str;
    fn get_efi_sub_type(&self) -> Self::Subtype;
    fn get_data(&self) -> Option<Vec<u8>>;
    fn display(&self, display_only: bool) -> String {
        let _ = display_only;
        self.display_as_unknown()
    }

    #[cfg(test)]
    fn get_efi_type(&self) -> DevicePathType;

    #[cfg(test)]
    fn as_node(&self) -> Node {
        let data = self.get_data();
        let node_length = data.as_ref().map(|d| d.len()).unwrap_or(0) as u16 + 4;
        Node {
            node_type: self.get_efi_type().into(),
            node_sub_type: self.get_efi_sub_type().into(),
            node_length,
            data,
        }
    }

    fn display_as_unknown(&self) -> String {
        let subtype: u8 = self.get_efi_sub_type().into();
        if let Some(data) = &self.get_data() {
            format!(
                "{}({},{})",
                self.get_generic_name(),
                subtype,
                hex::encode(data),
            )
        } else {
            format!("{}({})", self.get_generic_name(), subtype)
        }
    }
}

pub type PathNode =
    PathNodeT<acpi::AcpiNode, hardware::HardwareNode, media::MediaNode, messaging::MessagingNode>;

impl PathNode {
    fn is_end(&self) -> bool {
        match self {
            PathNode::Unknown(node) => node.is_end(),
            _ => false,
        }
    }

    #[cfg(test)]
    fn as_node(&self) -> Node {
        match self {
            PathNode::Acpi(acpi) => acpi.as_node(),
            PathNode::Hardware(hw) => hw.as_node(),
            PathNode::Media(media) => media.as_node(),
            PathNode::Messaging(msg) => msg.as_node(),
            PathNode::EndInstance => Node {
                node_type: DevicePathType::End.into(),
                node_sub_type: DevicePathSubTypeEnd::EndInstance.into(),
                node_length: 4,
                data: None,
            },
            PathNode::EndEntire => Node {
                node_type: DevicePathType::End.into(),
                node_sub_type: DevicePathSubTypeEnd::EndEntire.into(),
                node_length: 4,
                data: None,
            },
            PathNode::Unknown(node) => node.clone(),
        }
    }
}

impl TryFrom<Node> for PathNode {
    type Error = anyhow::Error;

    fn try_from(value: Node) -> std::result::Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&Node> for PathNode {
    type Error = anyhow::Error;

    fn try_from(value: &Node) -> std::result::Result<Self, Self::Error> {
        let node_type = DevicePathType::from_primitive(value.node_type);
        match node_type {
            DevicePathType::End => {
                let subtype = DevicePathSubTypeEnd::try_from(value.node_sub_type)?;
                subtype.validate_length(value.node_length)?;
                match subtype {
                    DevicePathSubTypeEnd::EndInstance => Ok(PathNode::EndInstance),
                    DevicePathSubTypeEnd::EndEntire => Ok(PathNode::EndEntire),
                }
            }
            DevicePathType::Acpi => Ok(PathNode::Acpi(AcpiNode::try_from(value)?)),
            DevicePathType::Hardware => Ok(PathNode::Hardware(HardwareNode::try_from(value)?)),
            DevicePathType::Media => Ok(PathNode::Media(MediaNode::try_from(value)?)),
            DevicePathType::Messaging => Ok(PathNode::Messaging(MessagingNode::try_from(value)?)),
            DevicePathType::Unknown(_) => Ok(PathNode::Unknown(value.clone())),
            DevicePathType::Bios => Ok(PathNode::Unknown(value.clone())),
        }
    }
}

impl PathNode {
    fn display(&self, display_only: bool) -> String {
        match self {
            PathNode::Acpi(acpi) => acpi.display(display_only),
            PathNode::Hardware(hardware) => hardware.display(display_only),
            PathNode::Media(media) => media.display(display_only),
            PathNode::Messaging(messaging_node) => messaging_node.display(display_only),
            PathNode::EndInstance => "".to_string(),
            PathNode::EndEntire => "".to_string(),
            PathNode::Unknown(node) => format!(
                "Path({},{},{})",
                node.node_type,
                node.node_sub_type,
                node.data.as_ref().map_or("null".to_string(), hex::encode)
            ),
        }
    }

    #[cfg(test)]
    fn to_bytes(&self) -> Vec<u8> {
        let node = self.as_node();
        let mut bytes = Vec::new();
        bytes.push(node.node_type);
        bytes.push(node.node_sub_type);
        bytes.extend_from_slice(&node.node_length.to_le_bytes());
        if let Some(data) = &node.data {
            bytes.extend_from_slice(data);
        }
        bytes
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct DevicePath {
    pub nodes: Vec<PathNode>,
}

impl DevicePath {
    pub fn is_usb_device_path(&self) -> bool {
        self.nodes.iter().any(|n| match n {
            PathNode::Messaging(m) => match m {
                MessagingNode::Usb { .. } => true,
                MessagingNode::UsbWwid { .. } => true,
                MessagingNode::UsbClass { .. } => true,
                _ => false,
            },
            _ => false,
        })
    }

    pub fn display(&self, display_only: bool) -> String {
        self.nodes
            .iter()
            .map(|node| node.display(display_only))
            .collect::<Vec<String>>()
            .join("/")
    }

    #[cfg(test)]
    pub fn new() -> Self {
        DevicePath { nodes: Vec::new() }
    }

    #[cfg(test)]
    pub fn acpi_acpi(mut self, pnp_id: u16, uid: u32) -> Self {
        let hid = (pnp_id as u32) << 16 | 0x41D0;
        let node = PathNode::Acpi(AcpiNode::Acpi(hid, uid));
        self.nodes.push(node);
        self
    }

    #[cfg(test)]
    pub fn msg_mac_addr(mut self, mac_addr: MacAddr, if_type: u8) -> Self {
        let node = PathNode::Messaging(MessagingNode::MacAddr { mac_addr, if_type });
        self.nodes.push(node);
        self
    }

    #[cfg(test)]
    pub fn end_instance(mut self) -> Self {
        self.nodes.push(PathNode::EndInstance);
        self
    }

    #[cfg(test)]
    pub fn end(mut self) -> Self {
        self.nodes.push(PathNode::EndEntire);
        self
    }

    #[cfg(test)]
    pub fn hw_pci(mut self, function: u8, device: u8) -> Self {
        self.nodes
            .push(PathNode::Hardware(HardwareNode::Pci { function, device }));
        self
    }

    #[cfg(test)]
    pub fn msg_ipv4(
        mut self,
        local_ip: Ipv4Addr,
        remote_ip: Ipv4Addr,
        local_port: u16,
        remote_port: u16,
        is_static: bool,
        protocol: u16,
        gw: Ipv4Addr,
        net_mask: Ipv4Addr,
    ) -> Self {
        self.nodes.push(PathNode::Messaging(MessagingNode::IpV4 {
            local_ip,
            remote_ip,
            local_port,
            remote_port,
            protocol,
            is_static,
            gw,
            mask: net_mask,
        }));
        self
    }

    #[cfg(test)]
    pub fn msg_i_scsi(
        mut self,
        options: u16,
        target_port_gropup: u16,
        lun: u64,
        target: &str,
    ) -> Self {
        self.nodes.push(PathNode::Messaging(MessagingNode::IScsi {
            protocol: 0, // 0 = TCP, 1+ reserved
            options,
            lun,
            group_tag: target_port_gropup,
            target: target.to_string(),
        }));
        self
    }

    #[cfg(test)]
    pub fn msg_uri(mut self, uri: &str) -> Self {
        self.nodes.push(PathNode::Messaging(MessagingNode::Uri {
            uri: uri.to_string(),
        }));
        self
    }

    #[cfg(test)]
    pub fn media_hdd(
        mut self,
        partition_number: u32,
        partition_start: u64,
        partition_size: u64,
        signature: PartitionSignature,
        partition_format: PartitionType,
    ) -> Self {
        self.nodes.push(PathNode::Media(MediaNode::HardDrive {
            partition_number,
            partition_start,
            partition_size,
            signature,
            partition_format,
        }));
        self
    }

    #[cfg(test)]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for node in &self.nodes {
            bytes.extend_from_slice(&node.to_bytes());
        }
        bytes
    }

    #[cfg(test)]
    pub fn msg_sas(
        mut self,
        sas_address: [u8; 8],
        lun: [u8; 8],
        device_topology: u16,
        drive_topology: u16,
    ) -> Self {
        self.nodes.push(PathNode::Messaging(MessagingNode::Sas {
            sas_address,
            lun,
            device_topology,
            drive_topology,
        }));
        self
    }

    #[cfg(test)]
    pub fn msg_sas_ex(
        mut self,
        sas_address: [u8; 8],
        lun: [u8; 8],
        device_topology_info: u16,
        rtp: u16,
    ) -> Self {
        self.nodes.push(PathNode::Messaging(MessagingNode::SasEx {
            sas_address,
            reserved: [0u8; 8],
            lun,
            device_topology_info,
            rtp,
        }));
        self
    }
}

impl TryFrom<&[u8]> for DevicePath {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let mut nodes = Vec::new();
        let mut cursor = Cursor::new(data);
        loop {
            let node_type = cursor.read_u8()?;
            let node_sub_type = cursor.read_u8()?;
            let node_length = cursor.read_u16::<LittleEndian>()?;
            let node_data = if node_length > 4 {
                let mut data = vec![0; node_length as usize - 4];
                cursor.read_exact(&mut data)?;
                Some(data)
            } else {
                None
            };
            let node = Node {
                node_type,
                node_sub_type,
                node_length,
                data: node_data,
            };
            let is_end_node = node.is_end();

            let node = PathNode::try_from(node)?;
            nodes.push(node);

            if is_end_node {
                break;
            }
        }

        Ok(DevicePath { nodes })
    }
}
