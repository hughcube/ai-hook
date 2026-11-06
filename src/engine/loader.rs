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
        //    Path-list separator matches the platform's PATH convention: ';'
        //    on Windows (':' is part of drive letters such as "C:\..."), ':'
        //    on Unix. Splitting Unix on ';' as well used to mis-split rule
        //    paths whose directory names contain a semicolon.
        if let Ok(env_rules) = std::env::var("AI_HOOK_RULES") {
            let separators = if cfg!(windows) { ";" } else { ":" };
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
            if is_js(path)
                && let Some(fallback) = Self::recover_missing_js_path(path)
            {
                Self::add_file(&fallback, files, seen);
            }
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
        // `evaluate_all` short-circuits on the first decisive outcome, so the
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

        if let Ok(mut code) = std::fs::read_to_string(path) {
            // Strip UTF-8 BOM if present (e.g. created by Windows Notepad)
            if code.starts_with('\u{feff}') {
                code.remove(0);
            }
            seen.insert(path.to_path_buf());
            files.push(RuleSource {
                id: file_stem,
                path: path.to_path_buf(),
                code,
            });
        }
    }

    /// Recovers a missing `.js` rule path during transient `ai sync` directory
    /// recreation or plugin renames (`ai` -> `agent`). Only runs on the cold
    /// missing-file path, so normal invocations pay zero extra stat cost.
    fn recover_missing_js_path(path: &Path) -> Option<PathBuf> {
        std::thread::sleep(std::time::Duration::from_millis(25));
        if path.is_file() {
            return Some(path.to_path_buf());
        }
        let home = crate::paths::home_dir()?;
        Self::recover_missing_js_path_with_home(path, &home)
    }

    fn recover_missing_js_path_with_home(path: &Path, home: &Path) -> Option<PathBuf> {
        let file_name = path.file_name()?.to_str()?;
        let hooks_dir = path.parent()?;
        if hooks_dir.file_name()?.to_str()? != "hooks" {
            return None;
        }

        let in_known_tree = path.starts_with(home)
            || path.components().any(|c| {
                matches!(
                    c.as_os_str().to_str(),
                    Some(
                        ".agents" | ".claude" | ".codebuddy" | ".workbuddy" | ".codex" | ".gemini"
                    )
                )
            });
        if !in_known_tree {
            return None;
        }

        let plugins_root = home.join(".agents").join("plugins");
        let p1 = hooks_dir.parent();
        let p2 = p1.and_then(|p| p.parent());

        // Covers both `<plugin>/hooks/<rule>.js` and `<plugin>/<version>/hooks/<rule>.js`
        for anc in [p1, p2].into_iter().flatten() {
            let Some(plugin) = anc.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            let canonical = plugins_root.join(plugin).join("hooks").join(file_name);
            if canonical.is_file() {
                return Some(canonical);
            }
            if plugin == "ai" {
                let renamed = plugins_root.join("agent").join("hooks").join(file_name);
                if renamed.is_file() {
                    return Some(renamed);
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recover_missing_js_path_cache_and_alias() {
        let tmp_home =
            std::env::temp_dir().join(format!("ai-hook-loader-recover-{}", std::process::id()));
        let sys_hooks = tmp_home
            .join(".agents")
            .join("plugins")
            .join("sys")
            .join("hooks");
        let agent_hooks = tmp_home
            .join(".agents")
            .join("plugins")
            .join("agent")
            .join("hooks");
        std::fs::create_dir_all(&sys_hooks).unwrap();
        std::fs::create_dir_all(&agent_hooks).unwrap();

        let sys_rule = sys_hooks.join("protect-rm-root.js");
        let agent_rule = agent_hooks.join("protect-agent-rules.js");
        std::fs::write(&sys_rule, "export default () => null;").unwrap();
        std::fs::write(&agent_rule, "export default () => null;").unwrap();

        // 1. Versioned cache path (`~/.claude/plugins/cache/local-plugins/sys/1.0.0/hooks/protect-rm-root.js`)
        let missing_cache = tmp_home
            .join(".claude")
            .join("plugins")
            .join("cache")
            .join("local-plugins")
            .join("sys")
            .join("1.0.0")
            .join("hooks")
            .join("protect-rm-root.js");
        assert_eq!(
            RuleLoader::recover_missing_js_path_with_home(&missing_cache, &tmp_home),
            Some(sys_rule)
        );

        // 2. Legacy plugin rename (`~/.agents/plugins/ai/hooks/protect-agent-rules.js` -> `agent`)
        let missing_ai = tmp_home
            .join(".agents")
            .join("plugins")
            .join("ai")
            .join("hooks")
            .join("protect-agent-rules.js");
        assert_eq!(
            RuleLoader::recover_missing_js_path_with_home(&missing_ai, &tmp_home),
            Some(agent_rule)
        );

        // 3. Unrelated temp test path must NOT recover
        let unrelated = std::env::temp_dir().join("nonexistent-rule.js");
        assert_eq!(
            RuleLoader::recover_missing_js_path_with_home(&unrelated, &tmp_home),
            None
        );

        std::fs::remove_dir_all(&tmp_home).ok();
    }
}
