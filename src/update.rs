use crate::i18n::{Msg, t, tf};
use std::io::Cursor;
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// Network budget for the GitHub API call.
const API_TIMEOUT: Duration = Duration::from_secs(30);
/// Network budget for the release-asset download (archives can be large).
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);
/// Absolute cap on downloaded bytes — protects against a malformed/attacker
/// asset response exhausting memory.
const MAX_DOWNLOAD_BYTES: u64 = 512 * 1024 * 1024;

/// Opens `path` exclusively (fails if it exists). Any stale leftover from a
/// previous run is removed first. `remove_file` never follows symlinks, so a
/// pre-placed link cannot redirect the write to an arbitrary target.
fn open_temp_exclusive(path: &Path) -> std::io::Result<std::fs::File> {
    let _ = std::fs::remove_file(path);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// Determines candidate asset names (in priority order) and internal binary name.
fn get_target_candidates() -> Result<(&'static [&'static str], &'static str), String> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        Ok((
            &[
                "ai-hook-windows-x86_64.exe",
                "ai-hook.exe",
                "ai-hook-windows-x86_64.zip",
            ],
            "ai-hook.exe",
        ))
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        Ok((
            &[
                "ai-hook-linux-x86_64",
                "ai-hook",
                "ai-hook-linux-x86_64.tar.gz",
            ],
            "ai-hook",
        ))
    }

    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        Ok((
            &[
                "ai-hook-darwin-x86_64",
                "ai-hook",
                "ai-hook-darwin-x86_64.tar.gz",
            ],
            "ai-hook",
        ))
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        Ok((
            &[
                "ai-hook-darwin-aarch64",
                "ai-hook",
                "ai-hook-darwin-aarch64.tar.gz",
            ],
            "ai-hook",
        ))
    }

    // 32-bit (i686) — Windows and Linux only (macOS dropped 32-bit in 10.15).
    #[cfg(all(target_os = "windows", target_arch = "x86"))]
    {
        Ok((
            &[
                "ai-hook-windows-x86.exe",
                "ai-hook.exe",
                "ai-hook-windows-x86.zip",
            ],
            "ai-hook.exe",
        ))
    }

    #[cfg(all(target_os = "linux", target_arch = "x86"))]
    {
        Ok((
            &["ai-hook-linux-x86", "ai-hook", "ai-hook-linux-x86.tar.gz"],
            "ai-hook",
        ))
    }

    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "windows", target_arch = "x86"),
        all(target_os = "linux", target_arch = "x86"),
    )))]
    {
        Err(tf(
            Msg::M014,
            &[&std::env::consts::OS, &std::env::consts::ARCH],
        ))
    }
}

/// Simple Semantic Versioning parser (e.g. "0.1.4" -> (0, 1, 4))
fn parse_semver(v: &str) -> Option<(u32, u32, u32)> {
    let parts: Vec<&str> = v.trim_start_matches('v').split('.').collect();
    if parts.len() >= 3 {
        let major = parts[0].parse().ok()?;
        let minor = parts[1].parse().ok()?;
        let patch = parts[2].split('-').next()?.parse().ok()?;
        Some((major, minor, patch))
    } else {
        None
    }
}

/// Self-update command handler
pub fn handle_update(force: bool, repo: &str) -> Result<(), String> {
    let current_version = env!("CARGO_PKG_VERSION");
    let (candidate_assets, binary_name) = get_target_candidates()?;

    println!("{} https://github.com/{} ...", t(Msg::M015), repo);

    let api_url = format!("https://api.github.com/repos/{}/releases/latest", repo);
    let mut req = ureq::get(&api_url)
        .timeout(API_TIMEOUT)
        .set(
            "User-Agent",
            &format!("ai-hook-updater/{}", current_version),
        )
        .set("Accept", "application/vnd.github.v3+json");

    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        let trimmed = token.trim();
        if !trimmed.is_empty() {
            req = req.set("Authorization", &format!("Bearer {}", trimmed));
        }
    }

    let response = req.call().map_err(|e| match e {
        ureq::Error::Status(404, _) => tf(Msg::M016, &[&repo]),
        ureq::Error::Status(403, _) => t(Msg::M017).to_string(),
        other => tf(Msg::M018, &[&other]),
    })?;

    let release_val: serde_json::Value = response.into_json().map_err(|e| tf(Msg::M019, &[&e]))?;

    let tag_name = release_val
        .get("tag_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| t(Msg::M020).to_string())?;

    let latest_version = tag_name.trim_start_matches('v');

    println!("{}: v{}", t(Msg::M021), current_version);
    println!("{}: {}", t(Msg::M022), tag_name);

    let is_newer = match (parse_semver(latest_version), parse_semver(current_version)) {
        (Some(latest), Some(current)) => latest > current,
        _ => latest_version != current_version,
    };

    if !force && !is_newer {
        println!("✓ {} (v{}).", t(Msg::M023), current_version);
        return Ok(());
    }

    // Find the matching release asset by candidate priority
    let assets = release_val
        .get("assets")
        .and_then(|v| v.as_array())
        .ok_or_else(|| t(Msg::M024).to_string())?;

    let mut selected = None;
    for &cand in candidate_assets {
        if let Some(asset_obj) = assets.iter().find(|a| {
            a.get("name")
                .and_then(|n| n.as_str())
                .map(|n| n == cand)
                .unwrap_or(false)
        }) {
            selected = Some((cand, asset_obj));
            break;
        }
    }

    let (asset_name, asset) = selected.ok_or_else(|| {
        let available = assets
            .iter()
            .filter_map(|a| a.get("name").and_then(|n| n.as_str()))
            .collect::<Vec<_>>()
            .join(", ");
        tf(
            Msg::M025,
            &[&tag_name, &format!("{:?}", candidate_assets), &available],
        )
    })?;

    let download_url = asset
        .get("browser_download_url")
        .and_then(|u| u.as_str())
        .ok_or_else(|| t(Msg::M026).to_string())?;

    println!("{}", tf(Msg::M027, &[&download_url]));

    let mut download_req = ureq::get(download_url)
        .timeout(DOWNLOAD_TIMEOUT)
        .set(
            "User-Agent",
            &format!("ai-hook-updater/{}", current_version),
        )
        .set("Accept", "application/octet-stream");

    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        let trimmed = token.trim();
        if !trimmed.is_empty() {
            download_req = download_req.set("Authorization", &format!("Bearer {}", trimmed));
        }
    }

    let download_resp = download_req.call().map_err(|e| tf(Msg::M028, &[&e]))?;

    let mut binary_bytes = Vec::new();
    download_resp
        .into_reader()
        .take(MAX_DOWNLOAD_BYTES + 1)
        .read_to_end(&mut binary_bytes)
        .map_err(|e| tf(Msg::M029, &[&e]))?;
    if binary_bytes.len() as u64 > MAX_DOWNLOAD_BYTES {
        return Err(tf(Msg::M030, &[&(MAX_DOWNLOAD_BYTES / (1024 * 1024))]));
    }

    let temp_dir = std::env::temp_dir();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let temp_bin_path: PathBuf = temp_dir.join(format!(
        "ai-hook-update-{}-{}.tmp",
        std::process::id(),
        nonce
    ));

    // Handle extraction or raw executable write
    if asset_name.ends_with(".zip") {
        println!(
            "{} {:.2} MB ({}) '{}' ...",
            t(Msg::M031),
            binary_bytes.len() as f64 / (1024.0 * 1024.0),
            t(Msg::M032),
            binary_name
        );
        let cursor = Cursor::new(binary_bytes);
        let mut zip = zip::ZipArchive::new(cursor).map_err(|e| tf(Msg::M033, &[&e]))?;
        let mut found = false;

        for i in 0..zip.len() {
            let mut file = zip.by_index(i).map_err(|e| tf(Msg::M034, &[&e]))?;
            let name = file.name().to_string();
            if name == binary_name
                || name.ends_with(&format!("/{}", binary_name))
                || name.ends_with(&format!("\\{}", binary_name))
            {
                // Exclusive creation: never follow a pre-existing symlink.
                let mut out_file =
                    open_temp_exclusive(&temp_bin_path).map_err(|e| tf(Msg::M035, &[&e]))?;
                std::io::copy(&mut file, &mut out_file).map_err(|e| {
                    let _ = std::fs::remove_file(&temp_bin_path);
                    tf(Msg::M036, &[&e])
                })?;
                found = true;
                break;
            }
        }

        if !found {
            let _ = std::fs::remove_file(&temp_bin_path);
            return Err(tf(Msg::M037, &[&binary_name]));
        }
    } else if asset_name.ends_with(".tar.gz") || asset_name.ends_with(".tgz") {
        println!(
            "{} {:.2} MB ({}) '{}' ...",
            t(Msg::M031),
            binary_bytes.len() as f64 / (1024.0 * 1024.0),
            t(Msg::M032),
            binary_name
        );
        let cursor = Cursor::new(binary_bytes);
        let gz = flate2::read::GzDecoder::new(cursor);
        let mut archive = tar::Archive::new(gz);
        let mut found = false;

        for entry_res in archive.entries().map_err(|e| tf(Msg::M038, &[&e]))? {
            let mut entry = entry_res.map_err(|e| tf(Msg::M039, &[&e]))?;
            let path = entry.path().map_err(|e| tf(Msg::M040, &[&e]))?;
            if path.file_name().and_then(|n| n.to_str()) == Some(binary_name) {
                // `unpack` writes the entry to the exact destination file and
                // replaces it if present (it never follows symlinks: it unlinks
                // dst first), so exclusive creation is honored here too.
                entry.unpack(&temp_bin_path).map_err(|e| {
                    let _ = std::fs::remove_file(&temp_bin_path);
                    tf(Msg::M041, &[&e])
                })?;
                found = true;
                break;
            }
        }

        if !found {
            let _ = std::fs::remove_file(&temp_bin_path);
            return Err(tf(Msg::M042, &[&binary_name]));
        }
    } else {
        // Raw executable binary! Directly save to a fresh temporary file
        println!(
            "{} {:.2} MB ({})",
            t(Msg::M031),
            binary_bytes.len() as f64 / (1024.0 * 1024.0),
            t(Msg::M043)
        );
        let mut out_file = open_temp_exclusive(&temp_bin_path).map_err(|e| tf(Msg::M044, &[&e]))?;
        out_file.write_all(&binary_bytes).map_err(|e| {
            let _ = std::fs::remove_file(&temp_bin_path);
            tf(Msg::M044, &[&e])
        })?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&temp_bin_path, std::fs::Permissions::from_mode(0o755));
    }

    // Self-check BEFORE replacing the running executable: the downloaded
    // binary must report itself as ai-hook. This catches truncated downloads,
    // HTML error pages and wrong-architecture assets before they can corrupt
    // the installed copy.
    println!("{}...", t(Msg::M045));
    let verify_ok = Command::new(&temp_bin_path)
        .arg("--version")
        .output()
        .map(|o| {
            o.status.success()
                && String::from_utf8_lossy(&o.stdout)
                    .to_lowercase()
                    .contains("ai-hook")
        })
        .unwrap_or(false);

    if !verify_ok {
        let _ = std::fs::remove_file(&temp_bin_path);
        return Err(t(Msg::M046).to_string());
    }

    println!("{}...", t(Msg::M047));
    self_replace::self_replace(&temp_bin_path).map_err(|e| {
        let _ = std::fs::remove_file(&temp_bin_path);
        tf(Msg::M048, &[&e])
    })?;

    let _ = std::fs::remove_file(&temp_bin_path);

    let current_exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "ai-hook".to_string());

    println!("✨ {} {}!", t(Msg::M049), tag_name);
    println!("   {}: {}", t(Msg::M050), current_exe);

    Ok(())
}
