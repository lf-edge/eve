// Copyright (c) 2024-2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use anyhow::Result;
use eve_types::AppInstanceStatus;
use eve_types::AppInstanceSummary;
use eve_types::DeviceNetworkStatus;
use eve_types::DevicePortConfigList;
use eve_types::DownloaderStatus;
use eve_types::EveNodeStatus;
use eve_types::EveOnboardingStatus;
use eve_types::EveVaultStatus;
use eve_types::LedBlinkCounter;
use eve_types::PhysicalIOAdapterList;
use eve_types::TpmLogs;
use eve_types::TuiEveConfig;
use eve_types::ZedAgentStatus;
use format_serde_error::SerdeError;
use std::path::PathBuf;

// Common considerations for the tests:
// 1. Date and Time
// DateTime<UTC> and go date.Date are a bit different when it comes to serialization to a string
// in go trailing zeros are omitted. HEre is the snippet from the go code:
// ----------------------------------------------------------------------
// fmtFrac formats the fraction of v/10**prec (e.g., ".12345") into the
// tail of buf, omitting trailing zeros. It omits the decimal
// point too when the fraction is 0. It returns the index where the
// output bytes begin and the value v/10**prec.
// ----------------------------------------------------------------------
// so some test data is fixed by hand to add the trailing zeros

// Global HashMap to store the test data. Key is TestMessageType and value is the raw json data

enum TestMessageType {
    ZedAgentStatus,
    NetworkStatus,
    DPCList,
    NodeStatus,
    OnboardingStatus,
    VaultStatus,
    IOAdapters,
    LedBlinkCounter,
    DownloaderStatus,
    AppSummary,
    AppStatus,
    Response,
    TUIConfig,
    TpmLogs,
    Unknown(String),
}

// create TestMessageType from string
impl From<&str> for TestMessageType {
    fn from(s: &str) -> Self {
        match s {
            "ZedAgentStatus" => TestMessageType::ZedAgentStatus,
            "NetworkStatus" => TestMessageType::NetworkStatus,
            "DPCList" => TestMessageType::DPCList,
            "NodeStatus" => TestMessageType::NodeStatus,
            "OnboardingStatus" => TestMessageType::OnboardingStatus,
            "VaultStatus" => TestMessageType::VaultStatus,
            "IOAdapters" => TestMessageType::IOAdapters,
            "LedBlinkCounter" => TestMessageType::LedBlinkCounter,
            "DownloaderStatus" => TestMessageType::DownloaderStatus,
            "AppSummary" => TestMessageType::AppSummary,
            "AppStatus" => TestMessageType::AppStatus,
            "Response" => TestMessageType::Response,
            "TUIConfig" => TestMessageType::TUIConfig,
            "TpmLogs" => TestMessageType::TpmLogs,
            _ => TestMessageType::Unknown(s.to_string()),
        }
    }
}

fn get_test_data_path(data: &str) -> PathBuf {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("Failed to find CARGO_MANIFEST_DIR");
    let test_data_path = std::path::Path::new(&manifest_dir).join("test_data");
    test_data_path.join(data)
}

// the function loads one JSON file and returns message type
// e.g {"type":"ZedAgentStatus","message":  where 'message' is the raw json data
// return message type and the raw json data
fn load_json_test_data<P: Into<PathBuf>>(path: P) -> Result<(TestMessageType, String, PathBuf)> {
    let path = path.into();
    let data = std::fs::read_to_string(&path).unwrap();
    let json_data: serde_json::Value = serde_json::from_str(&data).unwrap();
    let message_type = json_data["type"].as_str().unwrap();
    let data = json_data["message"].to_string();
    Ok((TestMessageType::from(message_type), data, path))
}

fn load_all_files<P: Into<PathBuf>>(path: P) -> Result<Vec<(TestMessageType, String, PathBuf)>> {
    let mut result = Vec::new();
    let path = path.into();
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();
        let extension = path.extension();
        if extension != Some("json".as_ref()) {
            continue;
        }
        let (message_type, data, path) = load_json_test_data(path)?;
        result.push((message_type, data, path));
    }
    Ok(result)
}

#[test]
fn test_from_device_files() -> Result<()> {
    // load all files from the specified directory
    let data = load_all_files(get_test_data_path("ipc-tests")).unwrap();
    for (message_type, data, path) in data {
        // print file name
        println!("Testing JSON file: {:?}", path);
        match message_type {
            TestMessageType::ZedAgentStatus => {
                let _ = serde_json::from_str::<ZedAgentStatus>(&data)
                    .map_err(|err| SerdeError::new(data.to_string(), err))?;
            }
            TestMessageType::NetworkStatus => {
                let _ = serde_json::from_str::<DeviceNetworkStatus>(&data)
                    .map_err(|err| SerdeError::new(data.to_string(), err))?;
            }
            TestMessageType::DPCList => {
                let _ = serde_json::from_str::<DevicePortConfigList>(&data)
                    .map_err(|err| SerdeError::new(data.to_string(), err))?;
            }
            TestMessageType::NodeStatus => {
                let _ = serde_json::from_str::<EveNodeStatus>(&data)
                    .map_err(|err| SerdeError::new(data.to_string(), err))?;
            }
            TestMessageType::OnboardingStatus => {
                let _ = serde_json::from_str::<EveOnboardingStatus>(&data)
                    .map_err(|err| SerdeError::new(data.to_string(), err))?;
            }
            TestMessageType::VaultStatus => {
                let _ = serde_json::from_str::<EveVaultStatus>(&data)
                    .map_err(|err| SerdeError::new(data.to_string(), err))?;
            }
            TestMessageType::IOAdapters => {
                let _ = serde_json::from_str::<PhysicalIOAdapterList>(&data)
                    .map_err(|err| SerdeError::new(data.to_string(), err))?;
            }
            TestMessageType::LedBlinkCounter => {
                let _ = serde_json::from_str::<LedBlinkCounter>(&data)
                    .map_err(|err| SerdeError::new(data.to_string(), err))?;
            }
            TestMessageType::DownloaderStatus => {
                let _ = serde_json::from_str::<DownloaderStatus>(&data)
                    .map_err(|err| SerdeError::new(data.to_string(), err))?;
            }
            TestMessageType::AppSummary => {
                let _ = serde_json::from_str::<AppInstanceSummary>(&data)
                    .map_err(|err| SerdeError::new(data.to_string(), err))?;
            }
            TestMessageType::AppStatus => {
                let _ = serde_json::from_str::<AppInstanceStatus>(&data)
                    .map_err(|err| SerdeError::new(data.to_string(), err))?;
            }
            TestMessageType::TUIConfig => {
                let _ = serde_json::from_str::<TuiEveConfig>(&data)
                    .map_err(|err| SerdeError::new(data.to_string(), err))?;
            }
            TestMessageType::TpmLogs => {
                let _ = serde_json::from_str::<TpmLogs>(&data)
                    .map_err(|err| SerdeError::new(data.to_string(), err))?;
            }
            TestMessageType::Response => {}
            TestMessageType::Unknown(s) => {
                println!("Unknown message type: {}", s);
                panic!("Deserialization is not implemented!!!");
            }
        }
    }
    Ok(())
}
