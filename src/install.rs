use crate::eprint_ts;
use crate::i18n::{Msg, t};
use crate::{NoConsoleSpawn, outln};
use std::path::{Path, PathBuf};

/// Checks whether a directory is writable by attempting a quick probe file
pub fn is_dir_writable(dir: &Path) -> bool {
    if !dir.exists() {
        return false;
    }
    let test_file = dir.join(format!(".ai_hook_perm_test_{}", std::process::id()));
    if std::fs::write(&test_file, b"").is_ok() {
        let _ = std::fs::remove_file(&test_file);
        true
    } else {
        false
    }
}

/// Parses $PATH into entries, tolerating the MSYS/Git-Bash shape that is
/// injected into native Windows children: ':'-separated entries with '/c/…'
/// drive-mount prefixes.
pub fn path_entries_from_env() -> Vec<PathBuf> {
    let Some(raw) = std::env::var_os("PATH") else {
        return Vec::new();
    };
    let raw = raw.to_string_lossy();

    #[cfg(windows)]
    if !raw.contains(';') && raw.contains(':') {
        return raw
            .split(':')
            .filter(|p| !p.is_empty())
            .map(|p| {
                let b = p.as_bytes();
                if p.starts_with('/') && b.len() >= 3 && b[1].is_ascii_alphabetic() && b[2] == b'/'
                {
                    let drive = (b[1] as char).to_ascii_uppercase();
                    PathBuf::from(format!("{}:\\{}", drive, &p[3..]).replace('/', "\\"))
                } else {
                    PathBuf::from(p)
                }
            })
            .collect();
    }

    std::env::split_paths(raw.as_ref()).collect()
}

/// Drops the Windows verbatim prefix (`\\?\`, `\\?\UNC\`) that
/// `canonicalize()` adds, so a resolved path still compares and prints like
/// every other path instead of as `\\?\C:\…`.
fn strip_verbatim(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{rest}"))
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        p.to_path_buf()
    }
}

/// The directory holding the currently running executable, symlinks resolved.
///
/// Resolution matters: if ai-hook was launched through a symlink, installing
/// next to the *link* would replace the link itself with a regular file.
/// Resolving keeps the link pointing at the refreshed binary. Hard links need
/// no resolution — they are separate names for one file, and the name used to
/// launch the process is already a real path.
fn running_exe_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let resolved = strip_verbatim(&exe.canonicalize().unwrap_or(exe));
    resolved.parent().map(Path::to_path_buf)
}

/// Build outputs and package caches rather than real installations — never a
/// valid default install target.
fn is_ignored_path(p: &Path) -> bool {
    let s = p.to_string_lossy().replace('\\', "/").to_lowercase();
    (cfg!(windows) && s.contains("microsoft") && s.contains("windowsapps"))
        || s.contains("/target/")
        || s.contains("/node_modules/")
        || s.contains("/build/")
}

/// Canonical form of one PATH entry for comparison: lower-case, `/`-separated,
/// no trailing slash, with an MSYS `/c/…` drive prefix folded to `c:/…`.
///
/// A Windows PATH entry is `\`-separated while a `--target-dir` typed in Git
/// Bash is `/`-separated, and a Git-Bash-native child may hold either shape —
/// comparing them raw made a directory that IS on PATH report as missing.
fn normalize_path_entry(p: &Path) -> String {
    let cleaned = strip_verbatim(p);
    let s = cleaned.to_string_lossy().replace('\\', "/").to_lowercase();
    let folded = match s.strip_prefix('/') {
        Some(rest)
            if rest.len() >= 2
                && rest.as_bytes()[0].is_ascii_alphabetic()
                && rest.as_bytes()[1] == b'/' =>
        {
            format!("{}:/{}", &rest[..1], &rest[2..])
        }
        _ => s,
    };
    folded.trim_end_matches('/').to_string()
}

/// Resolves the directory an install should land in.
///
/// Order: an explicit `--target-dir`, then the directory the running ai-hook
/// itself lives in (so `install` refreshes that exact copy instead of an
/// unrelated PATH entry), then PATH auto-detection for putting a freshly built
/// binary on PATH without adding new environment variables.
pub fn resolve_global_install_dir(target_dir: Option<PathBuf>) -> PathBuf {
    if let Some(explicit) = target_dir {
        return explicit;
    }

    let existing_paths = path_entries_from_env();

    let norm_cmp = |p1: &Path, p2: &Path| -> bool {
        let s1 = p1
            .to_string_lossy()
            .replace('\\', "/")
            .trim_end_matches('/')
            .to_lowercase();
        let s2 = p2
            .to_string_lossy()
            .replace('\\', "/")
            .trim_end_matches('/')
            .to_lowercase();
        s1 == s2
    };

    // 0. Where this ai-hook itself lives. Build outputs are skipped so that
    //    running `install` from `target/release/` still reaches the PATH
    //    fallbacks below instead of no-op'ing onto its own build artifact.
    if let Some(dir) = running_exe_dir()
        && !is_ignored_path(&dir)
        && is_dir_writable(&dir)
    {
        return dir;
    }

    // 1. Unix: standard system-wide /usr/local/bin first when writable and in PATH
    #[cfg(not(windows))]
    {
        let usr_local_bin = PathBuf::from("/usr/local/bin");
        if existing_paths.iter().any(|p| norm_cmp(p, &usr_local_bin))
            && is_dir_writable(&usr_local_bin)
        {
            return usr_local_bin;
        }
    }

    // 2. Preferred standard user bin directories in PATH: ~/.local/bin, ~/.cargo/bin
    if let Some(home) = crate::paths::home_dir() {
        let local_bin = home.join(".local").join("bin");
        if existing_paths.iter().any(|p| norm_cmp(p, &local_bin)) && is_dir_writable(&local_bin) {
            return local_bin;
        }
        let cargo_bin = home.join(".cargo").join("bin");
        if existing_paths.iter().any(|p| norm_cmp(p, &cargo_bin)) && is_dir_writable(&cargo_bin) {
            return cargo_bin;
        }
    }

    // 3. Walk PATH left-to-right, skipping special/temporary paths
    for path in &existing_paths {
        if path.as_os_str().is_empty() || is_ignored_path(path) {
            continue;
        }
        if path.exists() && is_dir_writable(path) {
            return path.clone();
        }
    }

    // 4. Fallback default: ~/.local/bin (Standard cross-platform convention)
    if let Some(home) = crate::paths::home_dir() {
        home.join(".local").join("bin")
    } else {
        PathBuf::from("/usr/local/bin")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum InstallOutcome {
    SameFile(PathBuf),
    AlreadyExists(PathBuf),
    Installed(PathBuf),
}

/// True when `a` and `b` are the same physical file: identical after symlink
/// resolution, or two hard links onto one inode.
///
/// The inode check is Unix-only — std exposes no equivalent on Windows, where
/// the canonical-path comparison is the best available answer (and a copy onto
/// the running executable fails loudly there instead of silently corrupting it).
fn same_file(a: &Path, b: &Path) -> bool {
    fn canonical(p: &Path) -> String {
        p.canonicalize()
            .unwrap_or_else(|_| p.to_path_buf())
            .to_string_lossy()
            .trim_start_matches(r"\\?\")
            .to_lowercase()
    }

    if canonical(a) == canonical(b) {
        return true;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(ma), Ok(mb)) = (std::fs::metadata(a), std::fs::metadata(b)) {
            return ma.dev() == mb.dev() && ma.ino() == mb.ino();
        }
    }

    false
}

pub fn install_binary_file(
    src_exe: &Path,
    dest_dir: &Path,
    force: bool,
) -> Result<InstallOutcome, String> {
    if !dest_dir.exists() {
        std::fs::create_dir_all(dest_dir).map_err(|e| format!("{}: {}", dest_dir.display(), e))?;
    }

    let exe_name = if cfg!(windows) {
        "ai-hook.exe"
    } else {
        "ai-hook"
    };

    let dest_file = dest_dir.join(exe_name);

    // Same physical file? Covers both "src is already the installed copy" and
    // two hard links onto one inode — copying either onto itself would clobber
    // the binary that is currently executing.
    if same_file(src_exe, &dest_file) {
        return Ok(InstallOutcome::SameFile(dest_file));
    }

    let dest_exists = dest_file.exists();
    if dest_exists && !force {
        return Ok(InstallOutcome::AlreadyExists(dest_file));
    }

    // 安装/覆盖保护：带备份与失败自动回滚兜底
    let backup_path = if dest_exists {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        Some(dest_dir.join(format!("{}.old.{}", exe_name, nonce)))
    } else {
        None
    };

    let mut backed_up = false;
    if let Some(ref bak) = backup_path {
        let _ = std::fs::remove_file(bak);
        if std::fs::copy(&dest_file, bak).is_ok() {
            backed_up = true;
        }
    }

    let copy_res = match std::fs::copy(src_exe, &dest_file) {
        Ok(_) => Ok(()),
        Err(e) => {
            // Windows 兜底：如果目标文件可能因运行中被加写入锁，尝试重命名移开再复制
            #[cfg(windows)]
            {
                if let Some(ref bak) = backup_path {
                    if std::fs::rename(&dest_file, bak).is_ok() {
                        backed_up = true;
                        std::fs::copy(src_exe, &dest_file).map(|_| ())
                    } else {
                        Err(e)
                    }
                } else {
                    Err(e)
                }
            }
            #[cfg(not(windows))]
            Err(e)
        }
    };

    if let Err(e) = copy_res {
        if backed_up && let Some(ref bak) = backup_path {
            let _ = std::fs::remove_file(&dest_file);
            let _ = std::fs::rename(bak, &dest_file);
        }
        #[cfg(windows)]
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            return Err(format!(
                "{} {}: {}\n   {}",
                t(Msg::M093),
                dest_file.display(),
                e,
                t(Msg::M094)
            ));
        }
        return Err(format!("{} {}: {}", t(Msg::M093), dest_file.display(), e));
    }

    // 校验文件体积
    let src_len = std::fs::metadata(src_exe).map(|m| m.len()).ok();
    let dest_len = std::fs::metadata(&dest_file).map(|m| m.len()).ok();
    if src_len.is_some() && src_len != dest_len {
        if backed_up && let Some(ref bak) = backup_path {
            let _ = std::fs::remove_file(&dest_file);
            let _ = std::fs::rename(bak, &dest_file);
        } else {
            let _ = std::fs::remove_file(&dest_file);
        }
        return Err(format!(
            "{} {} ({}).",
            t(Msg::M095),
            dest_file.display(),
            t(Msg::M096)
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dest_file, std::fs::Permissions::from_mode(0o755));
    }

    // 自检验证：验证安装后的文件确实可用（Windows 下文件锁或 Defender 扫描可能导致短暂等待，做少量重试）
    let mut verify_ok = false;
    for attempt in 0..5 {
        if let Ok(o) = std::process::Command::new(&dest_file)
            .arg("--version")
            .no_console_window()
            .output()
            && o.status.success()
            && String::from_utf8_lossy(&o.stdout)
                .to_lowercase()
                .contains("ai-hook")
        {
            verify_ok = true;
            break;
        }
        if attempt < 4 {
            std::thread::sleep(std::time::Duration::from_millis(60));
        }
    }

    if !verify_ok {
        if backed_up && let Some(ref bak) = backup_path {
            let _ = std::fs::remove_file(&dest_file);
            let _ = std::fs::rename(bak, &dest_file);
        } else {
            let _ = std::fs::remove_file(&dest_file);
        }
        return Err("安装后的二进制自检验证失败，已自动回滚原版本。".to_string());
    }

    // 安装并验证完全成功，清理临时备份
    if backed_up && let Some(ref bak) = backup_path {
        let _ = std::fs::remove_file(bak);
    }

    Ok(InstallOutcome::Installed(dest_file))
}

pub fn handle_install(target_dir: Option<PathBuf>, force: bool) {
    let current_exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            eprint_ts!("{}: {}", t(Msg::M092), e);
            return;
        }
    };

    let dest_dir = resolve_global_install_dir(target_dir);

    let (dest_file, outcome) = match install_binary_file(&current_exe, &dest_dir, force) {
        Ok(outcome) => {
            let file = match &outcome {
                InstallOutcome::SameFile(f) => {
                    outln!("{}:", t(Msg::M098));
                    outln!("   {}", f.display());
                    f.clone()
                }
                InstallOutcome::AlreadyExists(f) => {
                    if crate::i18n::lang().is_zh() {
                        outln!("✨ 目标路径已存在二进制: {}", f.display());
                        outln!(
                            "   如需强制覆盖重新安装，请使用 `ai-hook install --force` (或 `-f`)"
                        );
                    } else {
                        outln!("✨ Target binary already exists: {}", f.display());
                        outln!("   Run with `--force` (or `-f`) to overwrite.");
                    }
                    f.clone()
                }
                InstallOutcome::Installed(f) => {
                    outln!("{}:", t(Msg::M097));
                    outln!("   {}", f.display());
                    f.clone()
                }
            };
            outln!();
            (file, Some(outcome))
        }
        Err(e) => {
            eprint_ts!("[ai-hook install] 错误: {}", e);
            let exe_name = if cfg!(windows) {
                "ai-hook.exe"
            } else {
                "ai-hook"
            };
            (dest_dir.join(exe_name), None)
        }
    };

    if outcome.is_none() {
        return;
    }

    // Check if the destination is already in PATH (no environment variables modified).
    let norm_dest = normalize_path_entry(&dest_dir);
    let in_path = path_entries_from_env()
        .iter()
        .any(|p| normalize_path_entry(p) == norm_dest);

    if in_path {
        outln!("✓ {}", t(Msg::M099));
        outln!("  '{}' {}.", dest_dir.display(), t(Msg::M100));
        outln!("  {}", t(Msg::M101));
    } else {
        outln!(
            "ℹ️  {} '{}' {}.",
            t(Msg::M102),
            dest_dir.display(),
            t(Msg::M103)
        );
        outln!("   {}:", t(Msg::M104));
        outln!("     {}", dest_file.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_target_dir_wins() {
        let dir = std::env::temp_dir().join("ai-hook-explicit-target");
        assert_eq!(resolve_global_install_dir(Some(dir.clone())), dir);
    }

    #[test]
    fn same_file_detects_identical_path() {
        let f = std::env::current_exe().expect("current exe");
        assert!(same_file(&f, &f));
    }

    #[test]
    fn same_file_rejects_distinct_files() {
        let tmp = std::env::temp_dir().join(format!("ai-hook-samefile-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let a = tmp.join("a.bin");
        let b = tmp.join("b.bin");
        std::fs::write(&a, b"a").unwrap();
        std::fs::write(&b, b"b").unwrap();
        assert!(!same_file(&a, &b));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Two hard links are one inode under two names: copying either onto the
    /// other would clobber the file, so they must resolve as the same file.
    #[cfg(unix)]
    #[test]
    fn same_file_detects_hard_link() {
        let tmp = std::env::temp_dir().join(format!("ai-hook-hardlink-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let a = tmp.join("a.bin");
        let b = tmp.join("b.bin");
        std::fs::write(&a, b"payload").unwrap();
        std::fs::hard_link(&a, &b).unwrap();
        assert!(
            same_file(&a, &b),
            "hard links must be recognised as the same file"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// The two shapes a Git-Bash host hands over must compare equal: a
    /// `--target-dir` typed as `C:/x` against the same directory in a Windows
    /// PATH entry `C:\x`, and an MSYS `/c/x` against `C:/x`.
    #[test]
    fn path_entry_normalisation_bridges_shapes() {
        let win = normalize_path_entry(Path::new(r"C:\Users\me\.local\bin\windows"));
        assert_eq!(
            win,
            normalize_path_entry(Path::new("C:/Users/me/.local/bin/windows"))
        );
        assert_eq!(
            win,
            normalize_path_entry(Path::new("/c/Users/me/.local/bin/windows"))
        );
        // Trailing separators never change the answer.
        assert_eq!(
            normalize_path_entry(Path::new("C:/Users/me/bin/")),
            normalize_path_entry(Path::new("C:/Users/me/bin"))
        );
        // A POSIX path that is not an MSYS drive mount is left alone.
        assert_eq!(
            normalize_path_entry(Path::new("/usr/local/bin")),
            "/usr/local/bin"
        );
    }

    /// `canonicalize()` on Windows yields a verbatim path; it must be folded
    /// back so it both prints normally and compares against PATH entries.
    #[test]
    fn verbatim_prefix_is_stripped() {
        assert_eq!(
            strip_verbatim(Path::new(r"\\?\C:\Users\me\.local\bin\windows")),
            PathBuf::from(r"C:\Users\me\.local\bin\windows")
        );
        assert_eq!(
            strip_verbatim(Path::new(r"\\?\UNC\server\share\bin")),
            PathBuf::from(r"\\server\share\bin")
        );
        assert_eq!(
            strip_verbatim(Path::new("C:/Users/me/bin")),
            PathBuf::from("C:/Users/me/bin")
        );
        assert_eq!(
            normalize_path_entry(Path::new(r"\\?\C:\Users\me\.local\bin\windows")),
            normalize_path_entry(Path::new(r"C:\Users\me\.local\bin\windows"))
        );
    }

    /// The test binary lives under `target/`, a build output: the default must
    /// fall through to PATH auto-detection instead of installing onto its own
    /// build artifact.
    #[test]
    fn default_target_skips_build_outputs() {
        let exe = std::env::current_exe().expect("current exe");
        assert!(
            is_ignored_path(&exe),
            "the test binary is expected to live under target/"
        );
        assert!(
            !is_ignored_path(&resolve_global_install_dir(None)),
            "the default must not resolve to a build output"
        );
    }
}
