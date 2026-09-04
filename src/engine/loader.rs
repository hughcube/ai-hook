use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct RuleSource {
    pub id: String,
    pub path: PathBuf,
    pub code: String,
}

pub struct RuleLoader;

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

        // 2. Check environment variable override
        if let Ok(env_rules) = std::env::var("AI_HOOK_RULES") {
            for part in env_rules.split(|c| c == ';' || c == ':') {
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
        if let Ok(cwd) = std::env::current_dir() {
            let local_rule_file = cwd.join(".ai-hook").join("rules.js");
            if local_rule_file.is_file() {
                Self::collect_from_path(&local_rule_file, &mut files, &mut seen);
            } else {
                let local_rules_dir = cwd.join(".ai-hook").join("rules");
                if local_rules_dir.is_dir() {
                    Self::collect_from_path(&local_rules_dir, &mut files, &mut seen);
                }
            }
        }

        files
    }

    fn collect_from_path(
        path: &Path,
        files: &mut Vec<RuleSource>,
        seen: &mut HashSet<PathBuf>,
    ) {
        if !path.exists() {
            return;
        }

        if path.is_file() {
            if path.extension().and_then(|s| s.to_str()) == Some("js") {
                Self::add_file(path, files, seen);
            }
        } else if path.is_dir() {
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_file() && p.extension().and_then(|s| s.to_str()) == Some("js") {
                        Self::add_file(&p, files, seen);
                    }
                }
            }
        }
    }

    fn add_file(
        path: &Path,
        files: &mut Vec<RuleSource>,
        seen: &mut HashSet<PathBuf>,
    ) {
        let canonical = match path.canonicalize() {
            Ok(c) => c,
            Err(_) => path.to_path_buf(),
        };

        if seen.contains(&canonical) {
            return;
        }

        let file_stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("rule")
            .to_string();

        if file_stem.starts_with('_') || file_stem.ends_with(".tmp") || file_stem.ends_with(".test") {
            return;
        }

        if let Ok(code) = std::fs::read_to_string(path) {
            seen.insert(canonical);
            files.push(RuleSource {
                id: file_stem,
                path: path.to_path_buf(),
                code,
            });
        }
    }
}
