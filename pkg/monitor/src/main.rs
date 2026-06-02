// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

mod actions;
mod application;
mod diff;
mod efi;
mod events;
mod ipc;
mod model;
mod tcg;
mod terminal;
mod traits;
mod ui;

use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::Result;
use application::{AppConfig, Application};
use libc::{EXIT_FAILURE, EXIT_SUCCESS};
use log::{info, warn, LevelFilter};
use terminal::TerminalWrapper;

const EVE_MONITOR_BASE_DIR_EVE: &str = "/persist/monitor/";
const EVE_MONITOR_BASE_DIR_PC: &str = "./persist/monitor/";

fn get_base_dir() -> PathBuf {
    // we use XDG_RUNTIME_DIR to detect the fact that we are running on desktop linux
    // FIXME: is there a better way?
    if let Ok(_dir) = std::env::var("XDG_RUNTIME_DIR") {
        EVE_MONITOR_BASE_DIR_PC.into()
    } else {
        EVE_MONITOR_BASE_DIR_EVE.into()
    }
}

fn get_base_log_dir() -> PathBuf {
    let base_dir = get_base_dir();
    base_dir.join("log")
}

fn remove_old_log_sessions<T: AsRef<Path>>(log_dir: T, rotate_count: usize) -> Result<()> {
    // go over log directory and remove old sessions
    // starting from the oldest one while we do not reach rotate_count
    // subdirectories in format %Y-%m-%d-%H-%M-%S

    // use walkdir to go over all subdirectories. get directory name and convert to date time object
    let mut dirs = std::fs::read_dir(log_dir.as_ref())?
        // ignot not directories
        .filter(|entry| entry.as_ref().map(|e| e.path().is_dir()).unwrap_or(false))
        .filter_map(|entry| {
            entry.ok().and_then(|entry| {
                entry
                    .file_name()
                    .into_string()
                    .ok()
                    .and_then(|name| {
                        chrono::NaiveDateTime::parse_from_str(&name, "%Y-%m-%d-%H-%M-%S").ok()
                    })
                    .map(|dt| (entry.path(), dt))
            })
        })
        .collect::<Vec<_>>();
    // then sort by date time and remove oldest directories
    dirs.sort_by_key(|(_, dt)| *dt);
    while dirs.len() > rotate_count - 1 {
        let (dir, _) = dirs.remove(0);
        std::fs::remove_dir_all(dir)?;
    }
    Ok(())
}

fn init_logging(log_level: &str) -> log2::Handle {
    let base_log_dir = get_base_log_dir();

    let log_level = LevelFilter::from_str(log_level).unwrap_or(LevelFilter::Info);

    // remove old log directories. store result until we initialize logging
    let remove_result = remove_old_log_sessions(&base_log_dir, 3);

    // get current data and time and use it as a subdirectory name for logs
    let current_dir = chrono::Local::now().format("%Y-%m-%d-%H-%M-%S").to_string();
    let log_dir = base_log_dir.join(current_dir);
    std::fs::create_dir_all(&log_dir).expect("Failed to create log directory");
    // set EVE_MONITOR_LOG_DIR to the created folder. it is used later in panic handler
    std::env::set_var("EVE_MONITOR_LOG_DIR", log_dir.to_string_lossy().to_string());

    let log_file = log_dir.join("monitor.log").to_string_lossy().to_string();

    let handle = log2::open(&log_file)
        .size(1024 * 1024)
        .rotate(10)
        .tee(false) // no console output
        .module(true)
        .level(log_level)
        .start();

    info!("Logging initialized: [{}] {:?}", log_level, log_file);

    if let Err(e) = remove_result {
        warn!("Failed to remove old log sessions: {}", e);
    }

    handle
}

pub fn initialize_panic_handler() -> Result<()> {
    let (panic_hook, eyre_hook) = color_eyre::config::HookBuilder::default()
        .panic_section(format!(
            "This is a bug. Consider reporting it at {}",
            env!("CARGO_PKG_REPOSITORY")
        ))
        .display_location_section(true)
        .display_env_section(true)
        .into_hooks();
    eyre_hook.install()?;
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = TerminalWrapper::close_terminal();

        let msg = format!("{}", panic_hook.panic_report(panic_info));

        eprintln!("{msg}");
        use human_panic::{handle_dump, print_msg, Metadata};
        let support = format!(
            "You can open a bug report at {}",
            env!("CARGO_PKG_REPOSITORY")
        );
        let meta = Metadata::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
            .authors("LF-EDGE EVE OS project")
            .support(support);

        // FIXME: set TMPDIR to value of EVE_MONITOR_LOG_DIR before calling handle_dump
        // or panic report won't be saved on EVE
        // we can remove it when human-panic is fixed
        // see https://github.com/rust-cli/human-panic/issues/167
        let _ = std::env::var("EVE_MONITOR_LOG_DIR").map(|log_dir| {
            std::env::set_var("TMPDIR", log_dir);

        });

        let file_path = handle_dump(&meta, panic_info);
        print_msg(file_path, &meta).expect("human-panic: printing error message to console failed");

        log::error!("Error: {}", strip_ansi_escapes::strip_str(msg));

        #[cfg(debug_assertions)]
        {
            // Better Panic stacktrace that is only enabled when debugging.
            // we do not have space on real TTY to display it
            better_panic::Settings::auto()
                .most_recent_first(false)
                .lineno_suffix(true)
                .verbosity(better_panic::Verbosity::Full)
                .create_panic_handler()(panic_info);
        }

        std::process::exit(EXIT_FAILURE);
    }));
    Ok(())
}

fn log_system_info() {
    // log monitor version
    info!("Starting monitor version: {}", env!("CARGO_PKG_VERSION"));
    info!(
        "Git version: {}",
        option_env!("GIT_VERSION")
            .unwrap_or("GIT_VERSION is not set, no .git directory or git is not installed?")
    );

    // get current user UID and GID
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self")
        .map(|m| {
            info!("Current process UID: {}, GID: {}", m.uid(), m.gid());

        })
        .unwrap_or_else(|e| {
            info!("Failed to get current process UID and GID: {}", e);
        });
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = AppConfig::load_or_create_app_config(&get_base_dir());
    let _log2 = init_logging(&config.log_level);
    initialize_panic_handler()?;
    log_system_info();

    let mut app = Application::new(config)?;
    let result = app.run().await;
    if let Err(e) = &result {
        log::error!("Application error: {}", e);
    }
    // FIXME: this is a workaround for malfunctioning terminal event stream
    // Terminal must be dropped and restored automatically but one of the threads doesn't exit
    // and await? on a main function never finishes. Drops are executed later.
    TerminalWrapper::close_terminal()?;
    std::process::exit(EXIT_SUCCESS);
}
