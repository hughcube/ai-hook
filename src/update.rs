use crate::NoConsoleSpawn;
use crate::i18n::{Msg, t, tf};
use crate::{errln, outln};
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

/// Absolute cap on one uncompressed archive entry. `MAX_DOWNLOAD_BYTES` bounds
/// the wire size, but a small zip can expand to hundreds of GB, so the
/// extracted stream needs its own budget (archive-bomb guard).
const MAX_UNCOMPRESSED_BYTES: u64 = 256 * 1024 * 1024;

/// The repository `--repo` defaults to. Anything else needs explicit
/// confirmation: `update` downloads and overwrites the running executable.
const DEFAULT_REPO: &str = "hughcube/ai-hook";

/// Upper bound for the checksum file itself (it is tiny; the cap is pure
/// paranoia against a hostile or hijacked release response).
const MAX_CHECKSUM_FILE_BYTES: u64 = 1024 * 1024;

fn build_agent(timeout: Duration) -> ureq::Agent {
    let mut builder = ureq::builder().timeout(timeout);
    let proxy_url = std::env::var("HTTPS_PROXY")
        .or_else(|_| std::env::var("https_proxy"))
        .or_else(|_| std::env::var("HTTP_PROXY"))
        .or_else(|_| std::env::var("http_proxy"))
        .or_else(|_| std::env::var("ALL_PROXY"))
        .or_else(|_| std::env::var("all_proxy"));
    if let Ok(p) = proxy_url
        && !p.trim().is_empty()
        && let Ok(proxy) = ureq::Proxy::new(p.trim())
    {
        builder = builder.proxy(proxy);
    }
    builder.build()
}

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

/// Case-insensitive "yes/1/true" test, matching the other env flag helpers.
fn env_flag_true(name: &str) -> bool {
    std::env::var(name)
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes"
        })
        .unwrap_or(false)
}

/// Asks the operator to confirm a non-default repository. `update` replaces the
/// running executable with a downloaded binary, so silently trusting an
/// arbitrary `owner/repo` would turn a mistyped flag into remote code
/// execution.
fn confirm_custom_repo(repo: &str) -> Result<(), String> {
    if repo == DEFAULT_REPO || env_flag_true("AI_HOOK_ACCEPT_REPO") {
        return Ok(());
    }
    outln!("{}", tf(Msg::M145, &[&repo]));
    let mut answer = String::new();
    match std::io::stdin().read_line(&mut answer) {
        Ok(_) => {
            let a = answer.trim().to_ascii_lowercase();
            if a == "y" || a == "yes" {
                Ok(())
            } else {
                Err(t(Msg::M146).to_string())
            }
        }
        // No usable stdin (CI, piped input): refuse rather than assume yes.
        Err(_) => Err(t(Msg::M146).to_string()),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Copies at most `cap` bytes from `reader` to `writer`, failing if the source
/// turns out to be larger. Used to bound archive extraction.
fn copy_capped<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    cap: u64,
) -> std::io::Result<u64> {
    let mut limited = reader.take(cap + 1);
    let written = std::io::copy(&mut limited, writer)?;
    if written > cap {
        return Err(std::io::Error::other("uncompressed size cap exceeded"));
    }
    Ok(written)
}

/// Formats the archive bomb error, or a generic I/O error if it was something
/// else.
fn extraction_error(e: std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::Other {
        tf(Msg::M144, &[&(MAX_UNCOMPRESSED_BYTES / (1024 * 1024))])
    } else {
        e.to_string()
    }
}

/// Downloads `SHA256SUMS.txt` from the release and returns the expected digest
/// for `asset_name`.
///
/// `self_replace` overwrites the running binary, and a version-string
/// self-check proves nothing (any payload can print "ai-hook"), so the
/// published checksum is the only thing standing between a hijacked release and
/// arbitrary code execution on the user's machine.
fn fetch_expected_checksum(
    release: &serde_json::Value,
    asset_name: &str,
    current_version: &str,
) -> Result<String, String> {
    let url = release
        .get("assets")
        .and_then(|v| v.as_array())
        .and_then(|assets| {
            assets
                .iter()
                .find(|a| a.get("name").and_then(|n| n.as_str()) == Some("SHA256SUMS.txt"))
        })
        .and_then(|a| a.get("browser_download_url"))
        .and_then(|u| u.as_str())
        .ok_or_else(|| tf(Msg::M142, &[&"no SHA256SUMS.txt asset in the release"]))?;

    let mut last_err = String::new();
    for attempt in 1..=3 {
        let agent = build_agent(API_TIMEOUT);
        let mut req = agent
            .get(url)
            .set(
                "User-Agent",
                &format!("ai-hook-updater/{}", current_version),
            )
            .set("Cache-Control", "no-cache, no-store")
            .set("Pragma", "no-cache");
        if let Ok(token) = std::env::var("GITHUB_TOKEN") {
            let trimmed = token.trim();
            if !trimmed.is_empty() {
                req = req.set("Authorization", &format!("Bearer {}", trimmed));
            }
        }

        match req.call() {
            Ok(resp) => {
                let mut text = String::new();
                if resp
                    .into_reader()
                    .take(MAX_CHECKSUM_FILE_BYTES)
                    .read_to_string(&mut text)
                    .is_ok()
                {
                    // sha256sum writes "<hash>  <name>"; a leading '*' marks binary mode.
                    for line in text.lines() {
                        let mut parts = line.split_whitespace();
                        let hash = parts.next().unwrap_or("");
                        let name = parts.next().unwrap_or("").trim_start_matches('*');
                        if name == asset_name && hash.len() == 64 {
                            return Ok(hash.to_ascii_lowercase());
                        }
                    }
                    return Err(tf(Msg::M141, &[&asset_name]));
                }
            }
            Err(e) => {
                last_err = e.to_string();
                if attempt < 3 {
                    std::thread::sleep(Duration::from_millis(500 * attempt as u64));
                }
            }
        }
    }
    Err(tf(Msg::M142, &[&last_err]))
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

    // A non-default --repo means replacing the running executable with
    // somebody else's binary. Require an explicit confirmation.
    confirm_custom_repo(repo)?;

    outln!("{} https://github.com/{} ...", t(Msg::M015), repo);

    let api_url = format!("https://api.github.com/repos/{}/releases/latest", repo);
    let agent = build_agent(API_TIMEOUT);
    let mut req = agent
        .get(&api_url)
        .set(
            "User-Agent",
            &format!("ai-hook-updater/{}", current_version),
        )
        .set("Accept", "application/vnd.github.v3+json")
        .set("Cache-Control", "no-cache, no-store")
        .set("Pragma", "no-cache");

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

    outln!("{}: v{}", t(Msg::M021), current_version);
    outln!("{}: {}", t(Msg::M022), tag_name);

    let is_newer = match (parse_semver(latest_version), parse_semver(current_version)) {
        (Some(latest), Some(current)) => latest > current,
        _ => latest_version != current_version,
    };

    if !force && !is_newer {
        if crate::i18n::lang().is_zh() {
            outln!(
                "✓ {} (v{})。如需强制重新安装，请执行 `ai-hook update --force`",
                t(Msg::M023),
                current_version
            );
        } else {
            outln!(
                "✓ {} (v{}). Run with `--force` to reinstall.",
                t(Msg::M023),
                current_version
            );
        }
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

    let expected_checksum = if env_flag_true("AI_HOOK_SKIP_CHECKSUM") {
        errln!("[ai-hook] {}", t(Msg::M147));
        None
    } else {
        Some(fetch_expected_checksum(
            &release_val,
            asset_name,
            current_version,
        )?)
    };

    outln!("{}", tf(Msg::M027, &[&download_url]));

    let mut binary_bytes = Vec::new();
    let mut download_err = String::new();
    for attempt in 1..=3 {
        binary_bytes.clear();
        let download_agent = build_agent(DOWNLOAD_TIMEOUT);
        let mut download_req = download_agent
            .get(download_url)
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

        match download_req.call() {
            Ok(download_resp) => {
                let content_len = download_resp
                    .header("Content-Length")
                    .and_then(|s| s.parse::<u64>().ok());

                let mut reader = download_resp.into_reader();
                let mut buffer = [0u8; 64 * 1024];
                let mut last_reported = std::time::Instant::now();
                let mut read_failed = false;
                loop {
                    match reader.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(n) => {
                            binary_bytes.extend_from_slice(&buffer[..n]);
                            if binary_bytes.len() as u64 > MAX_DOWNLOAD_BYTES {
                                return Err(tf(
                                    Msg::M030,
                                    &[&(MAX_DOWNLOAD_BYTES / (1024 * 1024))],
                                ));
                            }
                            if last_reported.elapsed() >= Duration::from_millis(300) {
                                let downloaded_mb = binary_bytes.len() as f64 / (1024.0 * 1024.0);
                                if let Some(total) = content_len {
                                    let total_mb = total as f64 / (1024.0 * 1024.0);
                                    let pct =
                                        (binary_bytes.len() as f64 / total as f64 * 100.0) as u32;
                                    eprint!(
                                        "\r   ⬇ {:.2} MB / {:.2} MB ({}%)...",
                                        downloaded_mb, total_mb, pct
                                    );
                                } else {
                                    eprint!("\r   ⬇ {:.2} MB...", downloaded_mb);
                                }
                                let _ = std::io::stderr().flush();
                                last_reported = std::time::Instant::now();
                            }
                        }
                        Err(e) => {
                            download_err = e.to_string();
                            read_failed = true;
                            break;
                        }
                    }
                }
                if content_len.is_some() {
                    eprintln!();
                }
                if !read_failed && !binary_bytes.is_empty() {
                    download_err.clear();
                    break;
                }
            }
            Err(e) => {
                download_err = e.to_string();
            }
        }
        if attempt < 3 {
            eprintln!("   [重试 {}/3] 下载连接中断，正在重试...", attempt);
            std::thread::sleep(Duration::from_millis(1000));
        }
    }

    if !download_err.is_empty() || binary_bytes.is_empty() {
        return Err(tf(Msg::M028, &[&download_err]));
    }

    if let Some(ref expected) = expected_checksum {
        let actual = sha256_hex(&binary_bytes);
        if &actual != expected {
            return Err(tf(Msg::M140, &[expected, &actual]));
        }
        outln!("{}", t(Msg::M143));
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
        outln!(
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
                // Bounded copy: a small zip entry can expand enormously.
                let copied = copy_capped(&mut file, &mut out_file, MAX_UNCOMPRESSED_BYTES);
                drop(out_file); // release the handle so cleanup can unlink
                copied.map_err(|e| {
                    let _ = std::fs::remove_file(&temp_bin_path);
                    extraction_error(e)
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
        outln!(
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
                // Regular files only: never materialize a symlink or hardlink
                // entry under our temp path.
                if !entry.header().entry_type().is_file() {
                    continue;
                }
                // Bounded copy instead of `unpack`: a small tar.gz can expand
                // to hundreds of GB, and the declared size may lie.
                let mut out_file =
                    open_temp_exclusive(&temp_bin_path).map_err(|e| tf(Msg::M041, &[&e]))?;
                let copied = copy_capped(&mut entry, &mut out_file, MAX_UNCOMPRESSED_BYTES);
                drop(out_file); // release the handle so cleanup can unlink
                copied.map_err(|e| {
                    let _ = std::fs::remove_file(&temp_bin_path);
                    extraction_error(e)
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
        outln!(
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
    outln!("{}...", t(Msg::M045));
    let verify_ok = Command::new(&temp_bin_path)
        .arg("--version")
        .no_console_window()
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

    outln!("{}...", t(Msg::M047));

    let installed_exe = match apply_self_replace(&temp_bin_path) {
        Ok(p) => p,
        Err(e) => {
            let _ = std::fs::remove_file(&temp_bin_path);
            return Err(e);
        }
    };
    let _ = std::fs::remove_file(&temp_bin_path);

    let current_exe_str = installed_exe.to_string_lossy().to_string();
    outln!("✨ {} {}!", t(Msg::M049), tag_name);
    outln!("   {}: {}", t(Msg::M050), current_exe_str);

    Ok(())
}

/// Cleans up any leftover temporary files or rotated binaries from previous updates.
pub fn clean_old_temp_files(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                if file_name.starts_with("ai-hook")
                    && (file_name.contains(".old")
                        || file_name.contains(".bak")
                        || file_name.contains(".tmp")
                        || file_name.contains(".new"))
                {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }
}

/// Atomically replaces the currently running executable with the newly downloaded binary.
///
/// On Windows:
/// 1. Stages the file in the target directory (same volume guarantees atomic metadata rename);
/// 2. Renames the running binary to `.old-<nonce>.tmp` (supported by Windows NT for executing images);
/// 3. Renames the staged binary into the official destination slot;
/// 4. Rolls back on error;
/// 5. Attempts to unlink the old binary (deferred cleanup if file lock persists).
///
/// On Unix:
/// Standard copy-and-rename atomic overwrite.
fn apply_self_replace(new_binary_path: &Path) -> Result<PathBuf, String> {
    let current_exe = std::env::current_exe()
        .map_err(|e| format!("无法确定当前正在运行的可执行文件路径: {}", e))?;

    let parent_dir = current_exe
        .parent()
        .ok_or_else(|| "无法确定当前可执行文件所在目录".to_string())?;

    clean_old_temp_files(parent_dir);

    #[cfg(windows)]
    {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);

        let exe_name = current_exe
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("ai-hook.exe");

        let staging_path = parent_dir.join(format!("{}.new-{}.tmp", exe_name, nonce));
        let old_exe_path = parent_dir.join(format!("{}.old-{}.tmp", exe_name, nonce));

        // 1. Stage in the SAME directory
        std::fs::copy(new_binary_path, &staging_path).map_err(|e| {
            format!(
                "无法将下载的新版本复制到安装目录 '{}' 进行暂存: {}",
                staging_path.display(),
                e
            )
        })?;

        // 2. Rename running binary away
        if let Err(e) = std::fs::rename(&current_exe, &old_exe_path) {
            let _ = std::fs::remove_file(&staging_path);
            return Err(format!(
                "重命名当前正在运行的二进制文件失败 (可能正被其他进程独占占用): {}",
                e
            ));
        }

        // 3. Move staged binary into official slot
        if let Err(e) = std::fs::rename(&staging_path, &current_exe) {
            // Roll back
            let _ = std::fs::rename(&old_exe_path, &current_exe);
            let _ = std::fs::remove_file(&staging_path);
            return Err(format!("就位新版本失败，已安全回滚至原版本: {}", e));
        }

        // 4. Best-effort delete of the rotated old executable.
        let _ = std::fs::remove_file(&old_exe_path);

        Ok(current_exe)
    }

    #[cfg(not(windows))]
    {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);

        let exe_name = current_exe
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("ai-hook");

        let staging_path = parent_dir.join(format!(".{}.new-{}.tmp", exe_name, nonce));

        std::fs::copy(new_binary_path, &staging_path).map_err(|e| {
            format!(
                "无法暂存新版本到 '{}': {}",
                staging_path.display(),
                e
            )
        })?;

        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&staging_path, std::fs::Permissions::from_mode(0o755));

        if let Err(e) = std::fs::rename(&staging_path, &current_exe) {
            let _ = std::fs::remove_file(&staging_path);
            return Err(format!("替换可执行文件失败: {}", e));
        }

        Ok(current_exe)
    }
}
