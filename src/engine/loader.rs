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
    /// Discovers all rule files across system, plugin, and project directories.
    pub fn discover_rules(custom_paths: Option<&[PathBuf]>) -> Vec<RuleSource> {
        let mut files = Vec::new();
        let mut seen = HashSet::new();

        // 1. Custom paths if specified
        if let Some(paths) = custom_paths {
            for p in paths {
                Self::collect_from_path(p, &mut files, &mut seen);
            }
            if !files.is_empty() {
                return files;
            }
        }

        // 2. Environment variable override
        if let Ok(env_path) = std::env::var("AI_HOOK_RULES_DIR") {
            Self::collect_from_path(Path::new(&env_path), &mut files, &mut seen);
        }

        // 3. Project-level local rules: ./.ai-hook/rules/
        if let Ok(cwd) = std::env::current_dir() {
            let local_rules = cwd.join(".ai-hook").join("rules");
            Self::collect_from_path(&local_rules, &mut files, &mut seen);
        }

        // 4. User-level rules: ~/.ai-hook/rules/
        if let Some(home) = dirs::home_dir() {
            let user_rules = home.join(".ai-hook").join("rules");
            Self::collect_from_path(&user_rules, &mut files, &mut seen);

            // 5. Plugin rules: ~/.agents/plugins/*/hooks/*.js
            let plugins_dir = home.join(".agents").join("plugins");
            if plugins_dir.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&plugins_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            let hooks_dir = path.join("hooks");
                            if hooks_dir.is_dir() {
                                Self::collect_from_path(&hooks_dir, &mut files, &mut seen);
                            }
                        }
                    }
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

        // Skip temporary or test scripts
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
