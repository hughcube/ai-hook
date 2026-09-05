//! Home / data-directory resolution via environment variables.
//!
//! Replaces the `dirs` crate (2026-09-05): on Windows dirs-sys pulls in
//! `Win32_UI_Shell` (shell32.dll) and `Win32_System_Com` (ole32.dll) just to
//! read USERPROFILE/LOCALAPPDATA — two large system DLLs that the loader then
//! initializes serially inside every CreateProcess, costing 1-3ms of startup
//! that a plain environment lookup avoids entirely. ai-hook runs inside agent
//! hosts where these variables are always present.

use std::path::PathBuf;

/// User home directory: `$USERPROFILE` (Windows) or `$HOME` (Unix), with a
/// `HOMEDRIVE`+`HOMEPATH` fallback on Windows.
pub fn home_dir() -> Option<PathBuf> {
    if let Some(h) = std::env::var_os("USERPROFILE") {
        return Some(PathBuf::from(h));
    }
    if let Some(h) = std::env::var_os("HOME") {
        return Some(PathBuf::from(h));
    }
    #[cfg(windows)]
    if let (Some(d), Some(p)) = (std::env::var_os("HOMEDRIVE"), std::env::var_os("HOMEPATH")) {
        return Some(PathBuf::from(d).join(p));
    }
    None
}

/// Windows local-app-data directory (`%LOCALAPPDATA%`); Unix fallback is the
/// home directory (matches the previous dirs behaviour closely enough for the
/// only consumer, install-location probing).
pub fn data_local_dir() -> Option<PathBuf> {
    if let Some(d) = std::env::var_os("LOCALAPPDATA") {
        return Some(PathBuf::from(d));
    }
    home_dir()
}
