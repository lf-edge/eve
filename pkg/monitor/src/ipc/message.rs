// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

// TODO: uncomment to use with serde_json::from_reader
// use bytes::Buf;
use bytes::Bytes;
use bytes::BytesMut;
use log::error;
use serde::Deserialize;
use serde::Serialize;

use super::monitorapi::AppsList;
use super::monitorapi::DeviceStatus;
use super::monitorapi::SetInterfaceConfig;
use super::monitorapi::TpmLogs;
use super::monitorapi::DownloaderStatus;
use super::monitorapi::NetworkStatus;
use super::monitorapi::TuiConfig;

pub type RequestId = u64;

struct AtomicIdGenerator(AtomicU64);
impl AtomicIdGenerator {
    fn next(&self) -> RequestId {
        self.0.fetch_add(1, Ordering::SeqCst)
    }
}

static REQ_ID: AtomicIdGenerator = AtomicIdGenerator(AtomicU64::new(1));
static MSG_INDEX: AtomicIdGenerator = AtomicIdGenerator(AtomicU64::new(1));

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "RequestType", content = "RequestData")]
pub enum Request {
    SetInterfaceConfig(SetInterfaceConfig),
    SetServer(String),
}

// This is the IPC wire type; variant shapes mirror EVE messages and must not
// be boxed, so accept the size difference.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "message")]
pub enum IpcMessage {
    Connecting,
    Ready,
    /// The initial IPC connection could not be established (e.g. socket not ready).
    ConnectionFailed,
    /// A previously established IPC connection was lost
    /// (e.g. pillar crashed or socket closed).
    ConnectionLost,
    DeviceStatus(DeviceStatus),
    NetworkStatus(NetworkStatus),
    DownloaderStatus(DownloaderStatus),
    AppsList(AppsList),
    TUIConfig(TuiConfig),
    TpmLogs(TpmLogs),
    Response {
        #[serde(flatten)]
        result: core::result::Result<String, String>,
        id: u64,
    },
    #[serde(untagged)]
    Request {
        #[serde(flatten)]
        request: Request,
        id: u64,
    },
}

fn dump_to_file(message: &str, is_error: bool) {
    use std::fs::OpenOptions;
    use std::io::Write;

    let msg_id = MSG_INDEX.next();

    // dump all message only for debug. they may consume a lot of disk space
    if !is_error && log::max_level() < log::LevelFilter::Debug {
        return;
    }

    if let Ok(log_dir) = std::env::var("EVE_MONITOR_LOG_DIR") {
        let log_file_name = format!(
            "eve_ipc_message{}-{}.json",
            if is_error { "-err" } else { "" },
            msg_id
        );
        let log_file_name = std::path::Path::new(log_dir.as_str()).join(log_file_name);

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file_name)
            .unwrap();
        file.write_all(message.as_bytes()).unwrap();
    }
}

impl IpcMessage {
    fn from_reader(bytes: Bytes) -> Self {
        // TODO: it is faster to call serde_json::from_reader directly
        // TODO: move dump_to_file to upper level
        // but I want to log the message if it fails to parse
        if let Ok(s) = String::from_utf8(bytes.to_vec()) {
            match serde_json::from_str(s.as_str()) {
                Ok(message) => {
                    dump_to_file(s.as_str(), false);
                    // dumpt raw binary TPM logs to file
                    if let Self::TpmLogs(logs) = &message {
                        if let Ok(log_dir) = std::env::var("EVE_MONITOR_LOG_DIR") {
                            match logs.save_raw_binary_logs(&log_dir) {
                                Ok(_) => {}
                                Err(e) => {
                                    error!("Failed to save raw binary logs: {}", e);
                                }
                            }
                        }
                    }
                    message
                }
                Err(e) => {
                    error!("Failed to parse message: {}", e);
                    error!("MESSAGE: {}", s);
                    dump_to_file(s.as_str(), true);
                    Self::Response {
                        id: 0,
                        result: Err("Failed to parse message".to_string()),
                    }
                }
            }
        } else {
            Self::Response {
                id: 0,
                result: Err("Failed to parse message to utf8".to_string()),
            }
        }
    }

    pub fn new_request(request: Request) -> Self {
        let id = REQ_ID.next();
        Self::Request { request, id }
    }
}

impl From<Bytes> for IpcMessage {
    fn from(bytes: Bytes) -> Self {
        Self::from_reader(bytes)
    }
}

impl From<IpcMessage> for Bytes {
    fn from(message: IpcMessage) -> Self {
        let message = serde_json::to_string(&message).unwrap();
        Bytes::from(message)
    }
}

impl From<BytesMut> for IpcMessage {
    fn from(bytes: BytesMut) -> Self {
        Self::from_reader(bytes.freeze())
    }
}
