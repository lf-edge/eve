// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use async_inotify::Watcher;
use inotify::EventMask;
use log::{debug, info, warn};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::{net::UnixStream, task::JoinHandle};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

/// Default timeout for establishing an IPC connection (socket appear + connect).
const IPC_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

pub struct IpcClient {}
impl IpcClient {
    async fn try_connect(path: &str, attempts: u32) -> Result<UnixStream> {
        for i in 0..attempts {
            match UnixStream::connect(path).await {
                Ok(unix_stream) => {
                    return Ok(unix_stream);
                }
                Err(e) => {
                    warn!(
                        "Failed to connect to socket: {}. Retrying {}/{}",
                        e,
                        i + 1,
                        attempts
                    );
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        Err(anyhow!(
            "Failed to connect to socket after {} attempts",
            attempts
        ))
    }
    pub async fn connect(path: &str) -> Result<Framed<UnixStream, LengthDelimitedCodec>> {
        Self::connect_with_timeout(path, IPC_CONNECT_TIMEOUT).await
    }

    pub async fn connect_with_timeout(
        path: &str,
        timeout: Duration,
    ) -> Result<Framed<UnixStream, LengthDelimitedCodec>> {
        match tokio::time::timeout(timeout, Self::connect_inner(path)).await {
            Ok(result) => result,
            Err(_) => Err(anyhow!(
                "Timed out after {:?} waiting for IPC connection at {}",
                timeout,
                path
            )),
        }
    }

    async fn connect_inner(path: &str) -> Result<Framed<UnixStream, LengthDelimitedCodec>> {
        //spawn a task to wait for the socket file to be created
        let socket_path = PathBuf::from(path);

        // check if the socket file exists and return if it does
        // TODO: there is a small chance that the file is created after this check
        // TODO 2: get rid of it and just keep retrying?
        if !socket_path.exists() {
            let socket_task: JoinHandle<Result<(), anyhow::Error>> =
                tokio::spawn(async move { Self::wait_for_socket_file(&socket_path).await });

            info!("Waiting for socket file {} to be created", path);
            socket_task.await??;
        }

        let unix_stream = Self::try_connect(path, 30).await?;

        let stream = LengthDelimitedCodec::builder()
            .little_endian()
            // go module github.com/getlantern/framed expects 4-byte in little-endian format as length field
            .length_field_type::<u32>()
            .new_framed(unix_stream);
        Ok(stream)
    }
    async fn wait_for_socket_file(path: &Path) -> Result<(), anyhow::Error> {
        let dir = Path::new(path).parent().unwrap();
        let mut watcher = Watcher::init();
        let wd = watcher.add(dir, &async_inotify::WatchMask::CREATE);
        if let Ok(wd) = wd {
            loop {
                if let Some(event) = watcher.next().await {
                    debug!("{:?}: {:?}", event.mask(), event.path());
                    if *event.mask() == EventMask::CREATE && event.path() == path {
                        info!("Socket file {} created", path.display());
                        break;
                    }
                }
            }
            if let Err(e) = watcher.remove(wd) {
                return Err(anyhow!("Failed to remove watch: {}", e));
            }
        }
        Ok(())
    }
}
