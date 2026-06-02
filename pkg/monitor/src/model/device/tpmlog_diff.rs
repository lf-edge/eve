// Copyright (c) 2025-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Context, Result};
use log::{info, trace, warn};
use regex::Regex;
use std::collections::HashMap;
use strum::Display;
use uuid::uuid;

use crate::{
    diff::{
        lcs::{collect_diff, compute_lcs, produce_diff_ops, DiffOp},
        semantic::diff_semantic,
    },
    efi::{
        device_path::{media::MediaNode, PathNode},
        vars::{EfiBootOrder, EfiLoadOption},
    },
    ipc::eve_types::{EveEfiVariable, TpmLogs},
    tcg::tcg_tpmlog::TcgTpmLog,
};

use super::tpmlog::{EveTpmLog, TpmEvent, TpmEventRef};

// Parse-result payloads are intended API even when not yet read.
#[allow(dead_code)]
#[derive(Debug)]
pub enum ParsedEfiVariable {
    BoorOrder(EfiBootOrder),
    BootEntry { num: u16, lo: EfiLoadOption },
    Unparsed(EveEfiVariable),
}

#[derive(Debug)]
pub struct ParsingResults {
    pub parsed_old: Vec<TpmEventRef>,
    pub parsed_new: Vec<TpmEventRef>,
    pub parsed_efi_vars_old: HashMap<String, ParsedEfiVariable>,
    pub parsed_efi_vars_new: HashMap<String, ParsedEfiVariable>,
    pub diff_ops_old: Vec<DiffOp>,
    pub diff_ops_new: Vec<DiffOp>,
    pub tpm_log_parse_result: Vec<InterpretedTpmEventRef>,
}

impl ParsingResults {
    pub fn get_boot_entry_description(&self, entry: u16, new: bool) -> Option<String> {
        let var_name = format!("Boot{:04X}", entry);
        if new {
            match self.parsed_efi_vars_new.get(&var_name) {
                Some(ParsedEfiVariable::BootEntry { num: _, lo }) => Some(lo.description.clone()),
                _ => None,
            }
        } else {
            match self.parsed_efi_vars_old.get(&var_name) {
                Some(ParsedEfiVariable::BootEntry { num: _, lo }) => Some(lo.description.clone()),
                _ => None,
            }
        }
    }
}

#[derive(Debug)]
pub struct TpmLogDiff {
    old_good_tpm_log: EveTpmLog,
    new_tpm_log: EveTpmLog,
    affected_pcrs: Vec<u32>,
    pub result: Option<ParsingResults>,
}

impl TpmLogDiff {
    pub fn set_affected_pcrs(&mut self, pcrs: &[u32]) {
        self.affected_pcrs = pcrs.to_vec();
    }
    fn get_logs_pair(raw_logs: TpmLogs) -> Result<(EveTpmLog, EveTpmLog)> {
        if raw_logs.efi_vars_success.is_none() || raw_logs.efi_vars_failed.is_none() {
            return Err(anyhow!("EFI vars are missing in TPM logs from EVE"));
        }
        let good = raw_logs
            .last_good_log
            .or(raw_logs.backup_good_log)
            .ok_or(anyhow!("'goog' log is missing"))
            .map(|raw_log| -> Result<EveTpmLog> {
                Ok(EveTpmLog::new(
                    TcgTpmLog::from_slice(&raw_log)?,
                    raw_logs.efi_vars_success.unwrap(),
                ))
            })??;

        let bad = raw_logs
            .last_failed_log
            .or(raw_logs.backup_failed_log)
            .ok_or(anyhow!("'bad' log is missing"))
            .map(|raw_log| -> Result<EveTpmLog> {
                Ok(EveTpmLog::new(
                    TcgTpmLog::from_slice(&raw_log)?,
                    raw_logs.efi_vars_failed.unwrap(),
                ))
            })??;

        Ok((good, bad))
    }

    fn parse_efi_vars(
        &self,
        vars: &Vec<EveEfiVariable>,
    ) -> Result<HashMap<String, ParsedEfiVariable>> {
        let re = Regex::new(r"Boot[0-9A-F]{4}").unwrap();

        let mut efi_vars = HashMap::new();

        for var in vars {
            let var_name = var.name.clone();
            if var_name == "BootOrder" {
                let efi_boot_order = EfiBootOrder::try_from(var.value.as_slice())
                    .context("cannot parse EfiBootOrder")?;
                efi_vars.insert(var_name, ParsedEfiVariable::BoorOrder(efi_boot_order));
            } else if re.is_match(&var_name) {
                let efi_load_options = EfiLoadOption::try_from(var.value.as_slice())
                    .context(format!("cannot parse EfiLoadOption for {}", var_name))?;
                // get boot number from var_name
                let boot_num = u16::from_str_radix(&var_name[4..], 16)?;
                efi_vars.insert(
                    var_name,
                    ParsedEfiVariable::BootEntry {
                        num: boot_num,
                        lo: efi_load_options,
                    },
                );
            } else {
                efi_vars.insert(var_name, ParsedEfiVariable::Unparsed(var.clone()));
            }
        }
        Ok(efi_vars)
    }

    pub fn parse(&self) -> Result<ParsingResults> {
        let parsed_old = self.old_good_tpm_log.tcg_tpm_log_translate()?;
        let parsed_new = self.new_tpm_log.tcg_tpm_log_translate()?;
        let parsed_efi_vars_old = self.parse_efi_vars(&self.old_good_tpm_log.efi_vars)?;
        let parsed_efi_vars_new = self.parse_efi_vars(&self.new_tpm_log.efi_vars)?;
        let lcs = compute_lcs(&parsed_old, &parsed_new);
        let (del, ins) = collect_diff(&parsed_old, &parsed_new, &lcs);
        let (del, new, mods) = diff_semantic(&parsed_old, &parsed_new, &del, &ins);
        let (diff_ops_old, diff_ops_new) =
            produce_diff_ops(&lcs, &new, &del, &mods, parsed_old.len(), parsed_new.len());
        let tpm_log_parse_result = self.interpret(
            &parsed_old,
            &parsed_new,
            &parsed_efi_vars_old,
            &parsed_efi_vars_new,
        )?;
        Ok(ParsingResults {
            parsed_old,
            parsed_new,
            parsed_efi_vars_old,
            parsed_efi_vars_new,
            diff_ops_old,
            diff_ops_new,
            tpm_log_parse_result,
        })
    }

    fn diff_for_pcr<'b>(
        &self,
        old: &'b [TpmEventRef],
        new: &'b [TpmEventRef],
        pcr: u32,
    ) -> (
        Vec<&'b TpmEventRef>,
        Vec<&'b TpmEventRef>,
        Vec<(&'b TpmEventRef, &'b TpmEventRef)>,
    ) {
        let old_filtered = old.iter().filter(|e| e.pcr == pcr).collect::<Vec<_>>();
        let new_filtered = new.iter().filter(|e| e.pcr == pcr).collect::<Vec<_>>();
        // all indexes are for subset of events for pcr
        let lcs =
            compute_lcs::<TpmEventRef, &TpmEventRef, &TpmEventRef>(&old_filtered, &new_filtered);
        let (del, ins) = collect_diff(&old_filtered, &new_filtered, &lcs);
        let (del, ins, mods) = diff_semantic(&old_filtered, &new_filtered, &del, &ins);
        // collect original references
        let del = del.iter().map(|i| old_filtered[*i]).collect::<Vec<_>>();
        let ins = ins.iter().map(|i| new_filtered[*i]).collect::<Vec<_>>();
        let mods = mods
            .iter()
            .map(|(i1, i2)| (old_filtered[*i1], new_filtered[*i2]))
            .collect::<Vec<_>>();
        (del, ins, mods)
    }

    pub fn interpret(
        &self,
        old: &[TpmEventRef],
        new: &[TpmEventRef],
        vars_old: &HashMap<String, ParsedEfiVariable>,
        vars_new: &HashMap<String, ParsedEfiVariable>,
    ) -> Result<Vec<InterpretedTpmEventRef>> {
        trace!("interpret");
        let mut interpretations: Vec<InterpretedTpmEventRef> = Vec::new();

        for pcr in self.affected_pcrs.iter() {
            let (deleted, added, mods) = self.diff_for_pcr(old, new, *pcr);

            match pcr {
                13 => {
                    interpretations.extend(interpret_pcr14(deleted, added, mods));
                }
                8 => {
                    interpretations.extend(interpret_pcr8(deleted, added, mods));
                }
                1 => {
                    interpretations
                        .extend(interpret_pcr1(deleted, added, mods, vars_old, vars_new));
                }
                14 => {
                    interpretations.extend(interpret_pcr14(deleted, added, mods));
                }
                4 => {
                    interpretations.extend(interpret_pcr4(deleted, added, mods));
                }
                _ => {
                    // log as worning all uninterepreted events
                    // log deleted events for this PCR
                    for e in deleted {
                        warn!("Uninterpreted deleted event for PCR {}: {:?}", pcr, e);
                    }
                    // log added events for this PCR
                    for e in added {
                        warn!("Uninterpreted added event for PCR {}: {:?}", pcr, e);
                    }
                    // log modified events for this PCR
                    for (e1, e2) in mods {
                        warn!(
                            "Uninterpreted modified event for PCR {}: {:?} -> {:?}",
                            pcr, e1, e2
                        );
                    }
                }
            }
        }

        Ok(interpretations)
    }
}

impl TryFrom<TpmLogs> for TpmLogDiff {
    type Error = anyhow::Error;

    fn try_from(value: TpmLogs) -> std::result::Result<Self, Self::Error> {
        let (old_good_tpm_log, new_tpm_log) = Self::get_logs_pair(value)?;

        Ok(TpmLogDiff {
            old_good_tpm_log,
            new_tpm_log,
            affected_pcrs: Vec::new(),
            result: None,
        })
    }
}

#[derive(Debug, PartialEq, Display, Clone)]
pub enum ConfigFileStatus {
    Added,
    Deleted,
    Modified,
}

#[derive(Debug, Clone)]
pub struct InterpretedBootEntry {
    pub boot_num: u16,
    pub description: String,
    pub from_usb: bool,
}

#[derive(Debug, Display, Clone)]
pub enum InterpretedTpmEvent {
    ConfigFileModified {
        file: String,
        status: ConfigFileStatus,
    },
    KernelCmdLineModified {
        old: String,
        new: String,
    },
    GrubCfgModified,
    BootOrderModified {
        old: Vec<u16>,
        new: Vec<u16>,
    },
    BootOptionsModified {
        old: Vec<InterpretedBootEntry>,
        new: Vec<InterpretedBootEntry>,
    },
    EnterBios,
    Unparsed,
}

#[derive(Debug, Clone)]
pub struct InterpretedTpmEventRef {
    pub pcr: u32,
    pub old_original_index: usize,
    pub new_original_index: usize,
    pub event: InterpretedTpmEvent,
}

impl Default for InterpretedTpmEventRef {
    fn default() -> Self {
        Self {
            pcr: u32::MAX,
            old_original_index: 0,
            new_original_index: 0,
            event: InterpretedTpmEvent::Unparsed,
        }
    }
}

// a pair of events represents a single file.
// 1. file may be deleted (exists true->false)
// 2. file may be added (exists false->true)
// 3. file may be modified (exists true->true) and hash is different
// if we cannot decode the event we record the original event. in theory it must not happen
// because we interpret events that were already decoded in get_event_key
// detions and insertions are impossible. Only files measure-config cares about are recoded in PCR14
// if an arbitrary file appears on /config partition it is not recorded in PCR14
// Fields are set incrementally across match arms; default + reassign is clearer
// here than threading a struct literal through every branch.
#[allow(clippy::field_reassign_with_default)]
pub(super) fn interpret_pcr14(
    _deleted_events: Vec<&TpmEventRef>,
    _added_events: Vec<&TpmEventRef>,
    mods: Vec<(&TpmEventRef, &TpmEventRef)>,
) -> Vec<InterpretedTpmEventRef> {
    let mut results = Vec::new();

    for (e1, e2) in mods.into_iter() {
        let mut event_ref = InterpretedTpmEventRef::default();

        event_ref.pcr = 14;
        event_ref.old_original_index = e1.original_index;
        event_ref.new_original_index = e2.original_index;
        match (&e1.event, &e2.event) {
            (
                TpmEvent::MeasureConfig {
                    file: file1,
                    hash: hash1,
                    exists: exists1,
                },
                TpmEvent::MeasureConfig {
                    file: file2,
                    hash: hash2,
                    exists: exists2,
                },
            ) => {
                if file1 != file2 {
                    event_ref.event = InterpretedTpmEvent::Unparsed;
                } else if *exists1 && !*exists2 {
                    event_ref.event = InterpretedTpmEvent::ConfigFileModified {
                        file: file1.clone(),
                        status: ConfigFileStatus::Deleted,
                    };
                } else if !*exists1 && *exists2 {
                    event_ref.event = InterpretedTpmEvent::ConfigFileModified {
                        file: file1.clone(),
                        status: ConfigFileStatus::Added,
                    };
                } else if *exists1 && *exists2 && hash1 != hash2 {
                    event_ref.event = InterpretedTpmEvent::ConfigFileModified {
                        file: file1.clone(),
                        status: ConfigFileStatus::Modified,
                    };
                }
            }
            (_, _) => {
                event_ref.event = InterpretedTpmEvent::Unparsed;
            }
        }
        results.push(event_ref);
    }

    results
}

// Fields are set incrementally across branches; default + reassign is clearer.
#[allow(clippy::field_reassign_with_default)]
fn interpret_pcr1(
    deleted_events: Vec<&TpmEventRef>,
    new_events: Vec<&TpmEventRef>,
    mods: Vec<(&TpmEventRef, &TpmEventRef)>,
    vars_old: &HashMap<String, ParsedEfiVariable>,
    vars_new: &HashMap<String, ParsedEfiVariable>,
) -> Vec<InterpretedTpmEventRef> {
    let mut boot_options_changed = false;

    let mut result = Vec::new();

    for e in deleted_events {
        match e.event {
            TpmEvent::BootEntry { .. } => {
                boot_options_changed = true;
            }
            TpmEvent::ActionEnterBiosSetup => {
                result.push(InterpretedTpmEventRef {
                    pcr: 1,
                    old_original_index: e.original_index,
                    new_original_index: 0,
                    event: InterpretedTpmEvent::EnterBios,
                });
            }
            _ => {
                let mut event_ref = InterpretedTpmEventRef::default();
                event_ref.pcr = 1;
                event_ref.old_original_index = e.original_index;
                result.push(event_ref);
            }
        }
    }

    for e in new_events {
        match e.event {
            TpmEvent::BootEntry { .. } => {
                boot_options_changed = true;
            }
            TpmEvent::ActionEnterBiosSetup => {
                result.push(InterpretedTpmEventRef {
                    pcr: 1,
                    old_original_index: e.original_index,
                    new_original_index: 0,
                    event: InterpretedTpmEvent::EnterBios,
                });
            }
            _ => {
                let mut event_ref = InterpretedTpmEventRef::default();
                event_ref.new_original_index = e.original_index;
                event_ref.pcr = 1;
                result.push(event_ref);
            }
        }
    }

    let mut old_boot_option_indexes = Vec::new();
    let mut new_boot_option_indexes = Vec::new();

    // modified events
    for (e1, e2) in mods.iter() {
        let mut event_ref = InterpretedTpmEventRef::default();
        event_ref.pcr = 1;
        event_ref.old_original_index = e1.original_index;
        event_ref.new_original_index = e2.original_index;
        match (&e1.event, &e2.event) {
            (TpmEvent::BootEntry { .. }, TpmEvent::BootEntry { .. }) => {
                boot_options_changed = true;
                old_boot_option_indexes.push(e1.original_index);
                new_boot_option_indexes.push(e2.original_index);
            }
            (TpmEvent::BootOrder(o1), TpmEvent::BootOrder(o2)) => {
                event_ref.event = InterpretedTpmEvent::BootOrderModified {
                    old: o1.clone(),
                    new: o2.clone(),
                };
            }
            _ => {
                event_ref.event = InterpretedTpmEvent::Unparsed;
            }
        }
        result.push(event_ref);
    }

    if boot_options_changed {
        let old_boot_entries = vars_old.values().filter_map(|v| match v {
                ParsedEfiVariable::BootEntry { num, lo } => Some(InterpretedBootEntry {
                    boot_num: *num,
                    description: lo.description.clone(),
                    from_usb: lo.device_path_list.is_usb_device_path(),
                }),
                _ => None,
            })
            .collect();

        let new_boot_entries = vars_new.values().filter_map(|v| match v {
                ParsedEfiVariable::BootEntry { num, lo } => Some(InterpretedBootEntry {
                    boot_num: *num,
                    description: lo.description.clone(),
                    from_usb: lo.device_path_list.is_usb_device_path(),
                }),
                _ => None,
            })
            .collect();

        let min_old_index = old_boot_option_indexes.iter().min().unwrap_or(&0);
        let min_new_index = new_boot_option_indexes.iter().min().unwrap_or(&0);

        result.push(InterpretedTpmEventRef {
            pcr: 1,
            old_original_index: *min_old_index,
            new_original_index: *min_new_index,
            event: InterpretedTpmEvent::BootOptionsModified {
                old: old_boot_entries,
                new: new_boot_entries,
            },
        });
    }

    result
}

// new events may appear only if
// 1. grub.cfg updated due to EVE update
//  - we can detect this fact by looking at eve version
// 2. user typed commands in grub shell. in this case 'shell:' prefix will be appended to TPM event data
// 3. grub.cfg was modified on /config partition. this can be detected through PCR14
//
// events may disappear only if
// 1. grub.cfg updated due to EVE update
// 2. grub.cfg was modified on /config partition
//
// events are modified if
// 1. user select menu item in grub or manually edit command line
// 2. grub.cfg was modified on /config partition
//
// there is no way to tell from TPM log without parsing grub.cfg what exactly caused changes in kernel command line
// but parsing grub.cfg is too complex
//
// when eve is updated this evet is updated
// - EV_IPL grub_cmd setparams Boot 0.0.0-rucoder_monitor-tpm-log-15ec5037-dirty-2025-03-04.10.17-kvm-amd64
// Fields are set incrementally across branches; default + reassign is clearer.
#[allow(clippy::field_reassign_with_default)]
fn interpret_pcr8(
    _deletions: Vec<&TpmEventRef>,
    _insertions: Vec<&TpmEventRef>,
    mods: Vec<(&TpmEventRef, &TpmEventRef)>,
) -> Vec<InterpretedTpmEventRef> {
    let mut results = Vec::new();

    let mut grub_cfg_changed = false;

    for (e1, e2) in mods {
        let mut event_ref = InterpretedTpmEventRef::default();
        event_ref.pcr = 8;
        event_ref.old_original_index = e1.original_index;
        event_ref.new_original_index = e2.original_index;
        match (&e1.event, &e2.event) {
            (TpmEvent::GrubKernelCmdline(d1), TpmEvent::GrubKernelCmdline(d2)) => {
                event_ref.event = InterpretedTpmEvent::KernelCmdLineModified {
                    old: d1.clone(),
                    new: d2.clone(),
                };
                results.push(event_ref);
            }
            (TpmEvent::GrubCmd { cmd: _, params: _ }, TpmEvent::GrubCmd { cmd: _, params: _ }) => {
                grub_cfg_changed = true;
            }
            (TpmEvent::GrubLinuxEfi(_), TpmEvent::GrubLinuxEfi(_)) => {
                grub_cfg_changed = true;
            }
            (_, _) => {
                event_ref.event = InterpretedTpmEvent::Unparsed;
            }
        }
    }

    if grub_cfg_changed {
        let mut event_ref = InterpretedTpmEventRef::default();
        event_ref.pcr = 8;
        event_ref.event = InterpretedTpmEvent::GrubCfgModified;
        results.push(event_ref);
    }

    results
}

// Fields are set incrementally across branches; default + reassign is clearer.
#[allow(clippy::field_reassign_with_default)]
fn interpret_pcr4(
    _deletions: Vec<&TpmEventRef>,
    insertions: Vec<&TpmEventRef>,
    _mods: Vec<(&TpmEventRef, &TpmEventRef)>,
) -> Vec<InterpretedTpmEventRef> {
    let mut result = Vec::new();
    for e in insertions {
        let mut event_ref = InterpretedTpmEventRef::default();
        event_ref.new_original_index = e.original_index;
        event_ref.pcr = 4;

        match e.event {
            TpmEvent::CallingEfiAppFromBootOption | TpmEvent::FailedToStartEfiAppFromBootOption => {
                // just skip it. there is no easy way to know which app exactly so we cannot
                // reliably distinguish between two identical events
            }
            TpmEvent::BootApplication(ref dp) => {
                info!("BootApplication dp {}", dp.display(false));
                let bios_uuids = [uuid!("462CAA21-7614-4503-836E-8AB6F4662331"),
                    uuid!("D89A7D8B-D016-4D26-93E3-EAB6B4D3B0A2"),
                    uuid!("EEC25BDC-67F2-4D95-B1D5-F81B2039D11D")];
                let is_bios = dp.nodes.iter().any(|e| -> bool {
                    match e {
                        PathNode::Media(MediaNode::FvFile(uuid)) => bios_uuids.contains(uuid),
                        _ => false,
                    }
                });
                if is_bios {
                    event_ref.event = InterpretedTpmEvent::EnterBios;
                } else {
                    event_ref.event = InterpretedTpmEvent::Unparsed;
                }
            }
            _ => {
                info!("I {:?}", e);
                event_ref.event = InterpretedTpmEvent::Unparsed;
            }
        }
        result.push(event_ref);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    fn moc_tpm_log(path: &str) -> TcgTpmLog {
        let data = std::fs::read(path).unwrap();
        TcgTpmLog::from_slice(&data).unwrap()
    }

    fn get_test_data_path(data: &str) -> std::path::PathBuf {
        let manifest_dir =
            std::env::var("CARGO_MANIFEST_DIR").expect("Failed to find CARGO_MANIFEST_DIR");
        let test_data_path = std::path::Path::new(&manifest_dir).join("test_data");
        test_data_path.join(data)
    }

    #[test]
    fn test_decode_tpm_logs_message_load() -> Result<()> {
        // init logger
        let _ = env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Trace)
            .try_init();

        let message = std::fs::read(get_test_data_path("eve-tpm/TpmLogs.json")).unwrap();

        let mut json_data: serde_json::Value = serde_json::from_slice(&message).unwrap();

        let _raw_logs: TpmLogs = serde_json::from_value::<TpmLogs>(json_data["message"].take())?;

        Ok(())
    }
    #[test]
    fn test_decode_tpm_logs_message_parse() -> Result<()> {
        // init logger
        let _ = env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Trace)
            .try_init();

        let message = std::fs::read(get_test_data_path("eve-tpm/empty_uri.json")).unwrap();

        let mut json_data: serde_json::Value = serde_json::from_slice(&message).unwrap();

        let raw_logs: TpmLogs = serde_json::from_value::<TpmLogs>(json_data["message"].take())?;
        let diff = TpmLogDiff::try_from(raw_logs)?;
        diff.parse()?;

        Ok(())
    }
}
