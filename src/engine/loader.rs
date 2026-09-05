use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct RuleSource {
    pub id: String,
    pub path: PathBuf,
    pub code: String,
}

pub struct RuleLoader;

/// Only `.js` files are rules.
fn is_js(path: &Path) -> bool {
    path.extension().and_then(|s| s.to_str()) == Some("js")
}

impl RuleLoader {
    /// Loads only explicitly passed scripts or dedicated rules directory.
    /// Does NOT perform whole-system or plugins-wide directory traversal.
    pub fn load_rules(explicit_paths: &[PathBuf]) -> Vec<RuleSource> {
        let mut files = Vec::new();
        let mut seen = HashSet::new();

        // 1. Load from explicit script paths passed in CLI args
        if !explicit_paths.is_empty() {
            for p in explicit_paths {
                Self::collect_from_path(p, &mut files, &mut seen);
            }
            return files;
        }

        // 2. Check environment variable override.
        //    Path-list separator differs per platform: ';' on Windows (':' is
        //    part of drive letters such as "C:\..."), ';' or ':' elsewhere.
        if let Ok(env_rules) = std::env::var("AI_HOOK_RULES") {
            let separators = if cfg!(windows) { ";" } else { ";:" };
            for part in env_rules.split(|c| separators.contains(c)) {
                let trimmed = part.trim();
                if !trimmed.is_empty() {
                    Self::collect_from_path(Path::new(trimmed), &mut files, &mut seen);
                }
            }
            if !files.is_empty() {
                return files;
            }
        }

        // 3. Fallback to project-level rules directory if present (./.ai-hook/rules.js or ./.ai-hook/rules/)
        let local_rule_file = Path::new(".ai-hook/rules.js");
        if local_rule_file.is_file() {
            Self::collect_from_path(local_rule_file, &mut files, &mut seen);
        } else {
            let local_rules_dir = Path::new(".ai-hook/rules");
            if local_rules_dir.is_dir() {
                Self::collect_from_path(local_rules_dir, &mut files, &mut seen);
            }
        }

        files
    }

    fn collect_from_path(path: &Path, files: &mut Vec<RuleSource>, seen: &mut HashSet<PathBuf>) {
        // One stat to classify the path. `exists()` followed by `is_file()`
        // / `is_dir()` would cost two, and this runs on the critical path of
        // every single hook invocation.
        if path.is_file() {
            if is_js(path) {
                Self::add_file(path, files, seen);
            }
            return;
        }

        if !path.is_dir() {
            return;
        }

        // `DirEntry::file_type()` is already known from the directory
        // enumeration — on Windows FindFirstFile returns the attributes with
        // the entry, so it is free — whereas `path.is_file()` would re-stat
        // every entry. Symlinks are kept so rules shared via symlinks load as
        // before (`read_to_string` below follows them; a broken link simply
        // fails the read and is skipped). Filtering on the extension here
        // keeps `paths` small before the sort.
        let mut paths: Vec<PathBuf> = std::fs::read_dir(path)
            .map(|entries| {
                entries
                    .flatten()
                    .filter(|e| e.file_type().is_ok_and(|t| t.is_file() || t.is_symlink()))
                    .map(|e| e.path())
                    .filter(|p| is_js(p))
                    .collect()
            })
            .unwrap_or_default();

        // Directory rules are evaluated in deterministic file-name order:
        // `evaluate_all` short-circuits on the first Confirm/Deny, so the
        // load order must not depend on filesystem enumeration order.
        paths.sort();

        for p in paths {
            Self::add_file(&p, files, seen);
        }
    }

    fn add_file(path: &Path, files: &mut Vec<RuleSource>, seen: &mut HashSet<PathBuf>) {
        if seen.contains(path) {
            return;
        }

        let file_stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("rule")
            .to_string();

        if file_stem.starts_with('_') || file_stem.ends_with(".tmp") || file_stem.ends_with(".test")
        {
            return;
        }

        if let Ok(code) = std::fs::read_to_string(path) {
            seen.insert(path.to_path_buf());
            files.push(RuleSource {
                id: file_stem,
                path: path.to_path_buf(),
                code,
            });
        }
    }
}
