// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{cell::RefCell, collections::HashMap};

use log::{error, info};
use uuid::Uuid;

use crate::{
    ipc::eve_types::TpmLogs,
    ipc::monitorapi::{
        AppInstance as ContractAppInstance, AppsList, AttestState, DownloaderStatus, SwState,
    },
    model::device::tpmlog_diff::TpmLogDiff,
};

use super::device::network::NetworkInterfaceStatus;

#[derive(Debug, Clone, Default)]
pub enum OnboardingStatus {
    #[default]
    Unknown,
    Onboarding,
    Onboarded(Uuid),
    Error(String),
}

#[derive(Debug, Default)]
pub struct NodeStatus {
    pub server: Option<String>,
    pub onboarding_status: OnboardingStatus,
    pub node_name: String,
    pub serial: String,
}

impl NodeStatus {
    pub fn is_onboarded(&self) -> bool {
        matches!(self.onboarding_status, OnboardingStatus::Onboarded(_))
    }
}

#[derive(Debug)]
pub enum AppInstanceState {
    Normal(SwState),
    Error(SwState, String),
}

#[derive(Debug)]
pub struct AppInstance {
    pub name: String,
    pub uuid: Uuid,
    pub version: String,
    pub state: AppInstanceState,
}

/// Application instance counts grouped by lifecycle bucket, computed on demand
/// from the model's current app set.
#[derive(Debug, Default, Clone, Copy)]
pub struct AppCounts {
    pub running: usize,
    pub starting: usize,
    pub stopping: usize,
    pub stopped: usize,
    pub error: usize,
}

// `time` is populated from EVE error reports; kept as intended API.
#[derive(Debug)]
pub enum VaultStatus {
    Unknown,
    EncryptionDisabled(String, bool),
    Unlocked(bool),
    Locked(String, Option<Vec<u32>>),
}

impl VaultStatus {
    pub fn is_vault_locked(&self) -> bool {
        matches!(self, VaultStatus::Locked(_, _))
    }
}

pub type Model = RefCell<MonitorModel>;
#[derive(Debug)]
pub struct MonitorModel {
    pub app_version: String,
    pub dmesg: Vec<rmesg::entry::Entry>,
    pub network: Vec<NetworkInterfaceStatus>,
    pub downloader: Option<DownloaderStatus>,
    pub node_status: NodeStatus,
    pub apps: HashMap<Uuid, AppInstance>,
    pub vault_status: VaultStatus,
    pub dpc_key: Option<String>,
    pub attest_state: Option<AttestState>,
    pub attest_error: String,
    pub tpm: Option<TpmLogDiff>,
    pub error_log: Vec<String>,
    pub status_bar_tips: Option<String>,
    /// Whether the IPC connection to EVE is currently established
    pub ipc_connected: bool,
}

impl From<crate::ipc::monitorapi::VaultStatus> for VaultStatus {
    fn from(v: crate::ipc::monitorapi::VaultStatus) -> Self {
        use crate::ipc::monitorapi::VaultStatus as V;
        match v {
            V::Unknown => Self::Unknown,
            V::Disabled { tpm_used, error } => Self::EncryptionDisabled(error, tpm_used),
            V::Unlocked { tpm_used } => Self::Unlocked(tpm_used),
            V::Locked {
                error,
                mismatching_pcrs,
            } => {
                let pcrs = (!mismatching_pcrs.is_empty()).then_some(mismatching_pcrs);
                Self::Locked(error, pcrs)
            }
        }
    }
}

impl From<ContractAppInstance> for AppInstance {
    fn from(app: ContractAppInstance) -> Self {
        let state = if app.error.is_empty() {
            AppInstanceState::Normal(app.state)
        } else {
            AppInstanceState::Error(app.state, app.error)
        };

        AppInstance {
            name: app.name,
            uuid: app.uuid,
            version: app.version,
            state,
        }
    }
}

impl From<AppsList> for HashMap<Uuid, AppInstance> {
    fn from(apps_list: AppsList) -> Self {
        apps_list
            .instances
            .into_iter()
            .map(|app| (app.uuid, AppInstance::from(app)))
            .collect()
    }
}

fn onboarding_status_from(onboarded: bool, node_uuid: Uuid) -> OnboardingStatus {
    if !node_uuid.is_nil() {
        OnboardingStatus::Onboarded(node_uuid)
    } else if onboarded {
        OnboardingStatus::Error("Node UUID is missing".to_string())
    } else {
        OnboardingStatus::Onboarding
    }
}

impl MonitorModel {
    pub fn update_app_list(&mut self, apps_list: AppsList) {
        self.apps = HashMap::from(apps_list);
    }

    pub fn update_downloader_status(&mut self, status: DownloaderStatus) {
        self.downloader = Some(status);
    }

    pub fn update_device_status(&mut self, status: crate::ipc::monitorapi::DeviceStatus) {
        let ns = &mut self.node_status;
        ns.server = (!status.server.is_empty()).then_some(status.server);
        ns.onboarding_status = onboarding_status_from(status.onboarded, status.node_uuid);
        ns.node_name = status.node_name;
        ns.serial = status.serial;
        self.vault_status = VaultStatus::from(status.vault);
        self.attest_state = Some(status.attest_state);
        self.attest_error = status.attest_error;
    }

    /// Aggregate application instance counts by lifecycle bucket, derived from
    /// the current app set (the TUI no longer receives a separate summary).
    pub fn app_counts(&self) -> AppCounts {
        let mut c = AppCounts::default();
        for app in self.apps.values() {
            let (sw, reported_error) = match &app.state {
                AppInstanceState::Normal(s) => (*s, false),
                AppInstanceState::Error(s, _) => (*s, true),
            };
            if reported_error || matches!(sw, SwState::Broken | SwState::Failed | SwState::Unknown)
            {
                c.error += 1;
            } else {
                match sw {
                    SwState::Running => c.running += 1,
                    SwState::Halting | SwState::Pausing => c.stopping += 1,
                    SwState::Halted | SwState::Paused => c.stopped += 1,
                    _ => c.starting += 1,
                }
            }
        }
        c
    }

    pub fn update_network_status(&mut self, net_status: crate::ipc::monitorapi::NetworkStatus) {
        self.dpc_key = (!net_status.dpc_key.is_empty()).then(|| net_status.dpc_key.clone());
        self.network = crate::model::device::network::interfaces_from(&net_status);
    }

    pub fn update_tpm_logs(&mut self, logs: TpmLogs) {
        info!("Got TPM logs from EVE");

        match &self.vault_status {
            VaultStatus::Locked(_, Some(pcrs)) => {
                let diff = TpmLogDiff::try_from(logs);
                match diff {
                    Ok(mut diff) => {
                        diff.set_affected_pcrs(pcrs);
                        // TODO: start async parsing
                        match diff.parse() {
                            Ok(result) => {
                                diff.result = Some(result);
                            }
                            Err(e) => {
                                error!("Error parsing TPM logs: {:?}", e);
                                self.error_log
                                    .push(format!("Error parsing TPM logs: {:?}", e));
                            }
                        }
                        //FIXME: should I set it at all if parsing fails?
                        self.tpm = Some(diff);
                    }
                    Err(e) => {
                        error!("Error getting TPM logs from IPC event: {:?}", e);
                        self.error_log
                            .push(format!("Error parsing TPM logs: {:?}", e));
                    }
                }
            }
            _ => {
                error!("TPM logs received while vault is not locked");
                self.error_log
                    .push("TPM logs received while vault is not locked".to_string());
            }
        }
    }
}

impl Default for MonitorModel {
    fn default() -> Self {
        let app_version = option_env!("GIT_VERSION")
            .map(|v| v.to_string())
            .or(option_env!("CARGO_PKG_VERSION").map(|v| v.to_string()))
            .unwrap_or("unknown".to_string());

        MonitorModel {
            app_version,
            dmesg: Vec::with_capacity(1000),
            network: Vec::new(),
            downloader: None,
            node_status: NodeStatus::default(),
            apps: HashMap::new(),
            vault_status: VaultStatus::Unknown,
            dpc_key: None,
            attest_state: None,
            attest_error: String::new(),
            tpm: None,
            error_log: Vec::new(),
            status_bar_tips: None,
            ipc_connected: false,
        }
    }
}
