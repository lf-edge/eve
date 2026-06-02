// Copyright (c) 2025-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Ok, Result};
use log::debug;
use regex::Regex;
use uuid::Uuid;

use crate::{
    diff::semantic::LcsSemanticKey,
    efi::{
        device_path::DevicePath,
        vars::{EfiBootOrder, EfiLoadOption, LoadOptionAttributes},
    },
    ipc::eve_types::EveEfiVariable,
    tcg::{
        tcg_events::{TcgEfiActionEvent, TcgEfiVariableEvent, TcgIPLEvent, TcgUefiImageLoadEvent},
        tcg_tpmlog::{TcgRawTpmEvent, TcgTpmEventType, TcgTpmLog},
    },
};

#[derive(Debug)]
pub struct EveTpmLog {
    log: TcgTpmLog,
    pub efi_vars: Vec<EveEfiVariable>,
}

impl EveTpmLog {
    pub fn new(log: TcgTpmLog, efi_vars: Vec<EveEfiVariable>) -> Self {
        Self { log, efi_vars }
    }

    // ONLY FOR TESTING
    // pub fn from_events(events: Vec<TcgTpmEvent>) -> Self {
    //     let log = TPMLog::from_events(events);
    //     Self {
    //         log,
    //         efi_vars: None,
    //     }
    // }
    // pub fn get_events_for_pcr_ref(&self, pcr: u32) -> Vec<TcgTpmEventRef> {
    //     self.log.events_for_pcr_ref(pcr)
    // }

    pub fn tcg_tpm_log_translate(&self) -> Result<Vec<TpmEventRef>> {
        let mut events = Vec::new();

        for event_ref in self.log.events.iter().enumerate() {
            let pcr = event_ref.1.pcr_index;
            let tpm_event = TpmEvent::try_from_tcg_event(event_ref.1, &self.efi_vars)
                .context("try_from_tcg_event failed")?;
            events.push(TpmEventRef {
                original_index: event_ref.0,
                event: tpm_event,
                pcr,
            });
        }

        Ok(events)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TpmEvent {
    EfiAction(String),
    ActionEnterBiosSetup,
    CallingEfiAppFromBootOption,
    FailedToStartEfiAppFromBootOption,
    BootEntry {
        boot_num: u16,
        description: String,
        device_path: DevicePath,
        attributes: LoadOptionAttributes,
        tcg_type: TcgTpmEventType,
    },
    BootOrder(Vec<u16>),
    EfiVariable {
        name: String,
        guid: Uuid,
        value: Vec<u8>,
        tcg_type: TcgTpmEventType,
    },
    MeasureRoot {
        rootfs: String,
        hash: String,
    },
    MeasureConfig {
        file: String,
        hash: String,
        exists: bool,
    },
    GrubCmd {
        cmd: String,
        params: String,
    },
    GrubKernelCmdline(String),
    GrubLinuxEfi(String),
    GrubGenericEvent(String, String),
    GrubPcr9Event(String),
    BootApplication(DevicePath),
    RawEvent(TcgTpmEventType),
}

#[derive(Debug, Clone)]
pub struct TpmEventRef {
    pub original_index: usize,
    pub pcr: u32,
    pub event: TpmEvent,
}

impl PartialEq for TpmEventRef {
    fn eq(&self, other: &Self) -> bool {
        self.event == other.event
    }
}

impl std::fmt::Display for TpmEventRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: pcr={} {}",
            self.original_index,
            self.pcr,
            self.event.semantic_key()
        )
    }
}

impl<'a> LcsSemanticKey<'a, String> for TpmEventRef {
    fn semantic_key(&'a self) -> String {
        self.event.semantic_key()
    }
}

impl<'a> LcsSemanticKey<'a, String> for &TpmEventRef {
    fn semantic_key(&'a self) -> String {
        self.event.semantic_key()
    }
}

impl TpmEvent {
    pub fn tcg_event_type(&self) -> TcgTpmEventType {
        match self {
            TpmEvent::EfiAction(_) => TcgTpmEventType::EfiAction,
            TpmEvent::ActionEnterBiosSetup => TcgTpmEventType::Action,
            TpmEvent::CallingEfiAppFromBootOption => TcgTpmEventType::EfiAction,
            TpmEvent::FailedToStartEfiAppFromBootOption => TcgTpmEventType::EfiAction,
            TpmEvent::BootEntry { tcg_type, .. } => tcg_type.clone(),
            TpmEvent::BootOrder(_) => TcgTpmEventType::EfiVariableBoot,
            TpmEvent::EfiVariable { tcg_type, .. } => tcg_type.clone(),
            TpmEvent::MeasureRoot { .. } => TcgTpmEventType::IPL,
            TpmEvent::MeasureConfig { .. } => TcgTpmEventType::EfiAction,
            TpmEvent::GrubCmd { .. } => TcgTpmEventType::IPL,
            TpmEvent::GrubKernelCmdline(_) => TcgTpmEventType::IPL,
            TpmEvent::GrubLinuxEfi(_) => TcgTpmEventType::IPL,
            TpmEvent::GrubGenericEvent(_, _) => TcgTpmEventType::IPL,
            TpmEvent::BootApplication(_) => TcgTpmEventType::EfiBootServicesApplication,
            TpmEvent::RawEvent(tcg_type) => tcg_type.clone(),
            TpmEvent::GrubPcr9Event(_) => TcgTpmEventType::IPL,
        }
    }
    pub fn semantic_key(&self) -> String {
        match self {
            TpmEvent::EfiAction(s) => s.clone(),
            TpmEvent::BootEntry {
                boot_num,
                description,
                ..
            } => format!("BootEntry-{}-{}", boot_num, description),
            TpmEvent::BootOrder(_items) => "BootOrder".to_string(),
            TpmEvent::GrubCmd { cmd, params: _ } => cmd.clone(),
            TpmEvent::GrubKernelCmdline(_) => "GrubKernelCmdLine".to_string(),
            TpmEvent::GrubLinuxEfi(_) => "GrubLinuxEfi".to_string(),
            TpmEvent::GrubGenericEvent(cmd, _params) => cmd.clone(),
            TpmEvent::MeasureConfig { file, .. } => file.clone(),
            TpmEvent::ActionEnterBiosSetup => "EnterBiosSetupAction".to_string(),
            TpmEvent::MeasureRoot { rootfs: _, hash: _ } => "MeasureRootFs".to_string(),
            TpmEvent::BootApplication(dp) => format!("BootApplication: {}", dp.display(false)),
            TpmEvent::CallingEfiAppFromBootOption => "Calling app from boot option".to_string(),
            TpmEvent::FailedToStartEfiAppFromBootOption => {
                "Failed to start app from boot option".to_string()
            }
            TpmEvent::EfiVariable { name, guid, .. } => {
                format!("EfiVariable-{}-{}", name, guid)
            }
            TpmEvent::RawEvent(name) => {
                format!("UnparsedEvent-{}", name)
            }
            TpmEvent::GrubPcr9Event(_) => "GrubPcr9".to_string(),
        }
    }
    pub fn display(&self) -> String {
        match self {
            TpmEvent::EfiAction(s) => s.to_string(),
            TpmEvent::ActionEnterBiosSetup => "ActionEnterBiosSetup".to_string(),
            TpmEvent::CallingEfiAppFromBootOption => "CallingEfiAppFromBootOption".to_string(),
            TpmEvent::FailedToStartEfiAppFromBootOption => {
                "FailedToStartEfiAppFromBootOption".to_string()
            }
            TpmEvent::BootEntry {
                boot_num,
                description,
                ..
            } => format!("Boot{:04X} {}", boot_num, description,),
            TpmEvent::BootOrder(items) => format!("BootOrder: {:?}", items),
            TpmEvent::EfiVariable {
                name, guid, value, ..
            } => {
                format!("{} guid={}: {:?}", name, guid, value)
            }
            TpmEvent::MeasureRoot { rootfs, hash } => {
                format!("rootfs={} hash={}", rootfs, hash)
            }
            TpmEvent::MeasureConfig { file, hash, exists } => {
                if *exists {
                    format!("file={} hash={}", file, hash)
                } else {
                    format!("file={} hash={} exists={}", file, hash, exists)
                }
            }
            TpmEvent::GrubCmd { cmd, params } => format!("{}={}", cmd, params),
            TpmEvent::GrubKernelCmdline(s) => s.to_string(),
            TpmEvent::GrubLinuxEfi(s) => format!("GrubLinuxEfi: {}", s),
            TpmEvent::GrubGenericEvent(cmd, params) => {
                format!("{}={}", cmd, params)
            }
            TpmEvent::BootApplication(dp) => format!("BootApplication: {}", dp.display(false)),
            TpmEvent::RawEvent(name) => match name {
                TcgTpmEventType::Separator => "".to_string(),
                TcgTpmEventType::SCRTMContents => "".to_string(),
                TcgTpmEventType::SCRTMVersion => "".to_string(),
                TcgTpmEventType::CPUMicrocode => "".to_string(),
                _ => format!("{:?}", name),
            },
            TpmEvent::GrubPcr9Event(s) => s.clone(),
        }
    }
}

fn parse_efi_boot_variable(
    event: &TcgRawTpmEvent,
    efi_vars: &[EveEfiVariable],
) -> Result<TpmEvent> {
    let var_event = TcgEfiVariableEvent::try_from(event)?;
    let name_from_event = var_event.unicode_name;
    let guid_from_event = var_event.vendor_guid;
    let efi_var = efi_vars.iter().find(|v| v.name == name_from_event);

    if let Some(efi_var) = efi_var {
        let re = Regex::new(r"Boot[0-9A-F]{4}").unwrap();

        if name_from_event == "BootOrder" {
            let efi_boot_order = EfiBootOrder::try_from(efi_var.value.as_slice())
                .context("cannot parse BootOrder")?;
            Ok(TpmEvent::BootOrder(efi_boot_order.boot_order))
        } else if re.is_match(&name_from_event) {
            let efi_load_options = EfiLoadOption::try_from(efi_var.value.as_slice())
                .context(format!("cannot parse {}", name_from_event))?;
            debug!(
                "{}: dp={}",
                name_from_event,
                efi_load_options.device_path_list.display(false)
            );
            Ok(TpmEvent::BootEntry {
                boot_num: u16::from_str_radix(&name_from_event[4..], 16)?,
                description: efi_load_options.description,
                device_path: efi_load_options.device_path_list,
                attributes: efi_load_options.attributes,
                tcg_type: event.event_type.clone(),
            })
        } else {
            // this may happen if and only if we have not implemented support
            // for this specific variable in rust code but eve is sending it
            Ok(TpmEvent::EfiVariable {
                name: name_from_event,
                guid: guid_from_event,
                value: efi_var.value.clone(),
                tcg_type: event.event_type.clone(),
            })
        }
    } else {
        Ok(TpmEvent::EfiVariable {
            name: name_from_event,
            guid: guid_from_event,
            value: var_event.variable_data.clone(),
            tcg_type: event.event_type.clone(),
        })
    }
}

// IPL event may appear in several PCRs: 8 and 13
fn parse_grub_event(event: &TcgRawTpmEvent) -> Result<TpmEvent> {
    let efi_grub_event = TcgIPLEvent::try_from(event)?;

    if event.pcr_index == 9 {
        let event_data = efi_grub_event.get();
        return Ok(TpmEvent::GrubPcr9Event(event_data.to_string()));
    }
    // split by first space and keep both parts
    let event_data = efi_grub_event.get().splitn(2, ' ').collect::<Vec<&str>>();

    if event_data.len() != 2 {
        return Err(anyhow::anyhow!("Invalid event data for grub event"));
    }

    let event_type = event_data.first().unwrap().to_string();
    let event_data = event_data.get(1).unwrap().to_string();

    match event_type.as_str() {
        "grub_cmd" => {
            // split again and try to get params
            let event_data = event_data.splitn(2, ' ').collect::<Vec<&str>>();
            let cmd = event_data.first().unwrap().to_string();
            let params = event_data.get(1).unwrap_or(&"").to_string();
            Ok(TpmEvent::GrubCmd { cmd, params })
        }
        "grub_kernel_cmdline" => Ok(TpmEvent::GrubKernelCmdline(event_data)),
        "grub_linuxefi" => Ok(TpmEvent::GrubLinuxEfi(event_data)),
        _ => Ok(TpmEvent::GrubGenericEvent(event_type, event_data)),
    }
}

fn parse_efi_action_event(event: &TcgRawTpmEvent) -> Result<TpmEvent> {
    let action_event = TcgEfiActionEvent::try_from(event)?;
    let action_value = action_event.get();

    match event.pcr_index {
        4 => match action_value {
            "Calling EFI Application from Boot Option" => Ok(TpmEvent::CallingEfiAppFromBootOption),
            "Returning from EFI Application from Boot Option" => {
                Ok(TpmEvent::FailedToStartEfiAppFromBootOption)
            }
            _ => Ok(TpmEvent::EfiAction(action_value.to_string())),
        },
        1 | 3 if action_value == "Entering ROM Based Setup" => Ok(TpmEvent::ActionEnterBiosSetup),
        1 | 5 | 7 => Ok(TpmEvent::EfiAction(action_value.to_string())),
        _ => Err(anyhow::anyhow!(
            "Invalid PCR index for TpmEventType::EfiAction {}",
            event.pcr_index
        )),
    }
}

fn parse_action_event(event: &TcgRawTpmEvent) -> Result<TpmEvent> {
    let action_event = TcgEfiActionEvent::try_from(event)?;
    let action_value = action_event.get();

    match event.pcr_index {
        1 | 3 if action_value == "Entering ROM Based Setup" => Ok(TpmEvent::ActionEnterBiosSetup),
        1 | 3 | 4 | 5 | 7 => Ok(TpmEvent::EfiAction(action_value.to_string())),
        _ => Err(anyhow::anyhow!(
            "Invalid PCR index for TpmEventType::Action {}",
            event.pcr_index
        )),
    }
}

fn parse_measure_config_event(event: &TcgRawTpmEvent) -> Result<TpmEvent> {
    if event.pcr_index != 14 {
        return Err(anyhow::anyhow!(
            "Invalid PCR index for measure config event"
        ));
    }

    let action_event = TcgEfiActionEvent::try_from(event)?;
    let action_value = action_event.get();

    let re = regex::Regex::new(r"file:(\S+) exist:(true|false)(?: content-hash:(\S+))?")?;
    let captures = re.captures(action_value).context(format!(
        "Error parsing TpmEvent::MeasureConfig with regexp for '{}`",
        action_value
    ))?;
    let file = captures.get(1).context("Error parsing 'file:'")?.as_str();
    let exists = captures.get(2).context("Error parsing 'exists:'")?.as_str() == "true";
    let hash = captures.get(3).map(|m| m.as_str()).unwrap_or_default();
    if !exists && !hash.is_empty() {
        return Err(anyhow::anyhow!(
            "Invalid TpmEvent::MeasureConfig: hash is not empty for exist:false"
        ));
    }
    Ok(TpmEvent::MeasureConfig {
        file: file.to_string(),
        hash: hash.to_string(),
        exists,
    })
}

fn parse_rootfs_measurement_event(event: &TcgRawTpmEvent) -> Result<TpmEvent> {
    if event.pcr_index != 13 {
        return Err(anyhow::anyhow!(
            "Invalid PCR index for rootfs measurement event"
        ));
    }

    let efi_grub_event = TcgIPLEvent::try_from(event)?;

    // split by space. exactly 2 parts are expected
    let parts = efi_grub_event
        .get()
        .split_whitespace()
        .collect::<Vec<&str>>();

    if parts.len() != 2 {
        return Err(anyhow::anyhow!(
            "Invalid event data for rootfs measurement event"
        ));
    }

    Ok(TpmEvent::MeasureRoot {
        rootfs: parts[0].to_string(),
        hash: parts[1].to_string(),
    })
}

impl TpmEvent {
    pub fn try_from_tcg_event(
        event: &TcgRawTpmEvent,
        efi_vars: &[EveEfiVariable],
    ) -> Result<Self> {
        match event.event_type {
            TcgTpmEventType::EfiAction if event.pcr_index == 14 => {
                parse_measure_config_event(event)
            }
            TcgTpmEventType::EfiAction => parse_efi_action_event(event),
            TcgTpmEventType::EfiVariableBoot | TcgTpmEventType::EfiVariableBoot2 => {
                parse_efi_boot_variable(event, efi_vars).context("parse_efi_boot_variable failed")
            }
            TcgTpmEventType::IPL if (event.pcr_index == 8 || event.pcr_index == 9) => {
                parse_grub_event(event)
            }
            TcgTpmEventType::IPL if event.pcr_index == 13 => parse_rootfs_measurement_event(event),
            TcgTpmEventType::EfiBootServicesApplication => {
                let image_load_event = TcgUefiImageLoadEvent::try_from(event)?;
                let device_path = DevicePath::try_from(image_load_event.device_path.as_slice())?;
                debug!(
                    "TcgTpmEventType::EfiBootServicesApplication: dp={}",
                    device_path.display(false)
                );
                Ok(TpmEvent::BootApplication(device_path))
            }
            TcgTpmEventType::Action => parse_action_event(event),
            _ => Ok(TpmEvent::RawEvent(event.event_type.clone())),
        }
    }
}
