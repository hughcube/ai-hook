use std::io::Cursor;
use std::io::Read;
use std::path::PathBuf;

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

    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
    )))]
    {
        Err(format!(
            "Unsupported OS or CPU architecture: {} - {}. Please compile from source.",
            std::env::consts::OS,
            std::env::consts::ARCH
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

    println!("Checking for latest release from https://github.com/{} ...", repo);

    let api_url = format!("https://api.github.com/repos/{}/releases/latest", repo);
    let mut req = ureq::get(&api_url)
        .set("User-Agent", &format!("ai-hook-updater/{}", current_version))
        .set("Accept", "application/vnd.github.v3+json");

    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        let trimmed = token.trim();
        if !trimmed.is_empty() {
            req = req.set("Authorization", &format!("Bearer {}", trimmed));
        }
    }

    let response = req.call().map_err(|e| match e {
        ureq::Error::Status(404, _) => format!(
            "No published releases found for repository '{}' (HTTP 404).",
            repo
        ),
        ureq::Error::Status(403, _) => {
            "GitHub API rate limit exceeded or forbidden (HTTP 403). Try setting the GITHUB_TOKEN environment variable.".to_string()
        }
        other => format!("Failed to query GitHub release API: {}", other),
    })?;

    let release_val: serde_json::Value = response
        .into_json()
        .map_err(|e| format!("Failed to parse GitHub release JSON: {}", e))?;

    let tag_name = release_val
        .get("tag_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Release tag_name is missing from GitHub response".to_string())?;

    let latest_version = tag_name.trim_start_matches('v');

    println!("Current version: v{}", current_version);
    println!("Latest  version: {}", tag_name);

    let is_newer = match (parse_semver(latest_version), parse_semver(current_version)) {
        (Some(l), Some(c)) => l > c,
        _ => latest_version != current_version,
    };

    if !force && !is_newer {
        println!("✓ ai-hook is already up to date (v{}).", current_version);
        return Ok(());
    }

    // Find the matching release asset by candidate priority
    let assets = release_val
        .get("assets")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "No release assets found in the latest release".to_string())?;

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
        format!(
            "No matching binary or archive was found in release {}. Candidates: {:?}. Available in release: [{}]",
            tag_name,
            candidate_assets,
            assets
                .iter()
                .filter_map(|a| a.get("name").and_then(|n| n.as_str()))
                .collect::<Vec<_>>()
                .join(", ")
        )
    })?;

    let download_url = asset
        .get("browser_download_url")
        .and_then(|u| u.as_str())
        .ok_or_else(|| "Asset browser_download_url is missing".to_string())?;

    println!("Downloading {} from {} ...", asset_name, download_url);

    let mut download_req = ureq::get(download_url)
        .set("User-Agent", &format!("ai-hook-updater/{}", current_version))
        .set("Accept", "application/octet-stream");

    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        let trimmed = token.trim();
        if !trimmed.is_empty() {
            download_req = download_req.set("Authorization", &format!("Bearer {}", trimmed));
        }
    }

    let download_resp = download_req
        .call()
        .map_err(|e| format!("Failed to download release asset: {}", e))?;

    let mut binary_bytes = Vec::new();
    download_resp
        .into_reader()
        .read_to_end(&mut binary_bytes)
        .map_err(|e| format!("Failed to read downloaded asset: {}", e))?;

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
        println!("Downloaded {:.2} MB (archive). Extracting '{}' ...", binary_bytes.len() as f64 / (1024.0 * 1024.0), binary_name);
        let cursor = Cursor::new(binary_bytes);
        let mut zip = zip::ZipArchive::new(cursor)
            .map_err(|e| format!("Failed to parse zip archive: {}", e))?;
        let mut found = false;

        for i in 0..zip.len() {
            let mut file = zip
                .by_index(i)
                .map_err(|e| format!("Failed to read zip entry: {}", e))?;
            let name = file.name().to_string();
            if name == binary_name
                || name.ends_with(&format!("/{}", binary_name))
                || name.ends_with(&format!("\\{}", binary_name))
            {
                let mut out_file = std::fs::File::create(&temp_bin_path)
                    .map_err(|e| format!("Failed to create temporary output file: {}", e))?;
                std::io::copy(&mut file, &mut out_file)
                    .map_err(|e| format!("Failed to extract file: {}", e))?;
                found = true;
                break;
            }
        }

        if !found {
            return Err(format!("Binary '{}' was not found inside the zip archive", binary_name));
        }
    } else if asset_name.ends_with(".tar.gz") || asset_name.ends_with(".tgz") {
        println!("Downloaded {:.2} MB (archive). Extracting '{}' ...", binary_bytes.len() as f64 / (1024.0 * 1024.0), binary_name);
        let cursor = Cursor::new(binary_bytes);
        let gz = flate2::read::GzDecoder::new(cursor);
        let mut archive = tar::Archive::new(gz);
        let mut found = false;

        for entry_res in archive
            .entries()
            .map_err(|e| format!("Failed to read tar entries: {}", e))?
        {
            let mut entry = entry_res.map_err(|e| format!("Failed to inspect tar entry: {}", e))?;
            let path = entry.path().map_err(|e| format!("Invalid tar path: {}", e))?;
            if path.file_name().and_then(|n| n.to_str()) == Some(binary_name) {
                entry
                    .unpack(&temp_bin_path)
                    .map_err(|e| format!("Failed to unpack tar entry: {}", e))?;
                found = true;
                break;
            }
        }

        if !found {
            return Err(format!("Binary '{}' was not found inside the tar.gz archive", binary_name));
        }
    } else {
        // Raw executable binary! Directly save to temporary file
        println!("Downloaded {:.2} MB (raw executable).", binary_bytes.len() as f64 / (1024.0 * 1024.0));
        std::fs::write(&temp_bin_path, &binary_bytes)
            .map_err(|e| format!("Failed to write binary to temporary file: {}", e))?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&temp_bin_path, std::fs::Permissions::from_mode(0o755));
    }

    println!("Applying self-replacement to executable...");
    self_replace::self_replace(&temp_bin_path)
        .map_err(|e| format!("Self-replacement failed: {}", e))?;

    let _ = std::fs::remove_file(&temp_bin_path);

    let current_exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "ai-hook".to_string());

    println!("✨ Successfully updated ai-hook to {}!", tag_name);
    println!("   Binary: {}", current_exe);

    Ok(())
}
