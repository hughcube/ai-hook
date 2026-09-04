use rquickjs::{Ctx, Function, Object, Result};
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

#[derive(Default, Clone)]
pub struct RequestCache {
    files: Rc<RefCell<HashMap<String, Option<String>>>>,
    exists: Rc<RefCell<HashMap<String, bool>>>,
    git_branch: Rc<RefCell<Option<Option<String>>>>,
}

impl RequestCache {
    pub fn new() -> Self {
        Self::default()
    }
}

pub struct SysContext {
    cwd: PathBuf,
    cache: RequestCache,
}

impl SysContext {
    pub fn new(cwd: impl Into<PathBuf>, cache: RequestCache) -> Self {
        Self {
            cwd: cwd.into(),
            cache,
        }
    }

    fn resolve_path(&self, rel: &str) -> PathBuf {
        let p = Path::new(rel);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.cwd.join(p)
        }
    }

    pub fn fs_exists(&self, path_str: &str) -> bool {
        let full = self.resolve_path(path_str);
        let key = full.to_string_lossy().to_string();
        let mut cache = self.cache.exists.borrow_mut();
        if let Some(&val) = cache.get(&key) {
            return val;
        }
        let exists = full.exists();
        cache.insert(key, exists);
        exists
    }

    pub fn fs_read(&self, path_str: &str) -> Option<String> {
        let full = self.resolve_path(path_str);
        let key = full.to_string_lossy().to_string();
        let mut cache = self.cache.files.borrow_mut();
        if let Some(val) = cache.get(&key) {
            return val.clone();
        }
        let res = std::fs::read_to_string(&full).ok();
        cache.insert(key, res.clone());
        res
    }

    pub fn git_branch(&self) -> Option<String> {
        let mut cache = self.cache.git_branch.borrow_mut();
        if let Some(cached) = &*cache {
            return cached.clone();
        }

        let branch = Self::find_git_branch(&self.cwd);
        *cache = Some(branch.clone());
        branch
    }

    fn find_git_branch(start_dir: &Path) -> Option<String> {
        let mut curr = Some(start_dir);
        while let Some(dir) = curr {
            let git_dir = dir.join(".git");
            if git_dir.exists() {
                let head_file = if git_dir.is_dir() {
                    git_dir.join("HEAD")
                } else if git_dir.is_file() {
                    // Git worktree / submodule: .git is a file containing "gitdir: ..."
                    if let Ok(content) = std::fs::read_to_string(&git_dir) {
                        if let Some(rest) = content.trim().strip_prefix("gitdir:") {
                            let target = dir.join(rest.trim());
                            target.join("HEAD")
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                } else {
                    break;
                };

                if let Ok(head_content) = std::fs::read_to_string(head_file) {
                    let line = head_content.trim();
                    if let Some(ref_path) = line.strip_prefix("ref:") {
                        let ref_path = ref_path.trim();
                        if let Some(branch_name) = ref_path.strip_prefix("refs/heads/") {
                            return Some(branch_name.to_string());
                        }
                        return Some(ref_path.to_string());
                    } else if line.len() >= 7 {
                        // Detached HEAD, return short commit SHA
                        return Some(line[..7].to_string());
                    }
                }
                break;
            }
            curr = dir.parent();
        }
        None
    }

    pub fn exec(
        &self,
        cmd: &str,
        args: &[String],
        timeout_ms: u64,
    ) -> (i32, String, String) {
        let mut command = std::process::Command::new(cmd);
        command.args(args).current_dir(&self.cwd);

        // Simple timeout execution
        let start = std::time::Instant::now();
        let timeout = Duration::from_millis(timeout_ms);

        match command.output() {
            Ok(output) => {
                if start.elapsed() > timeout {
                    (-1, String::new(), "Command execution timed out".to_string())
                } else {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let code = output.status.code().unwrap_or(-1);
                    (code, stdout, stderr)
                }
            }
            Err(e) => (-1, String::new(), e.to_string()),
        }
    }
}

/// Binds the `sys` object into the QuickJS context.
pub fn create_sys_object<'js>(
    js_ctx: &Ctx<'js>,
    sys_ctx: Rc<SysContext>,
) -> Result<Object<'js>> {
    let sys = Object::new(js_ctx.clone())?;

    // 1. sys.env
    let env_obj = Object::new(js_ctx.clone())?;
    let env_get = Function::new(js_ctx.clone(), |name: String| -> Option<String> {
        std::env::var(name).ok()
    })?;
    env_obj.set("get", env_get)?;
    sys.set("env", env_obj)?;

    // 2. sys.cwd()
    let sys_for_cwd = sys_ctx.clone();
    let cwd_fn = Function::new(js_ctx.clone(), move || -> String {
        sys_for_cwd.cwd.to_string_lossy().to_string()
    })?;
    sys.set("cwd", cwd_fn)?;

    // 3. sys.fs
    let fs_obj = Object::new(js_ctx.clone())?;
    let sys_for_exists = sys_ctx.clone();
    let exists_fn = Function::new(js_ctx.clone(), move |path: String| -> bool {
        sys_for_exists.fs_exists(&path)
    })?;
    fs_obj.set("exists", exists_fn)?;

    let sys_for_read = sys_ctx.clone();
    let read_fn = Function::new(js_ctx.clone(), move |path: String| -> Option<String> {
        sys_for_read.fs_read(&path)
    })?;
    fs_obj.set("read", read_fn.clone())?;
    fs_obj.set("readText", read_fn)?;
    sys.set("fs", fs_obj)?;

    // 4. sys.git
    let git_obj = Object::new(js_ctx.clone())?;
    let sys_for_branch = sys_ctx.clone();
    let branch_fn = Function::new(js_ctx.clone(), move || -> Option<String> {
        sys_for_branch.git_branch()
    })?;
    git_obj.set("branch", branch_fn)?;
    sys.set("git", git_obj)?;

    // 5. sys.exec(cmd, args, options)
    let sys_for_exec = sys_ctx.clone();
    let exec_fn = Function::new(
        js_ctx.clone(),
        move |ctx: Ctx<'js>, cmd: String, args: Option<Vec<String>>, options: Option<Object<'js>>| -> Result<Object<'js>> {
            let arg_list = args.unwrap_or_default();
            let timeout = if let Some(opts) = options {
                opts.get::<_, Option<u64>>("timeoutMs").unwrap_or(None).unwrap_or(3000)
            } else {
                3000
            };

            let (code, stdout, stderr) = sys_for_exec.exec(&cmd, &arg_list, timeout);
            let res = Object::new(ctx.clone())?;
            res.set("code", code)?;
            res.set("stdout", stdout)?;
            res.set("stderr", stderr)?;
            Ok(res)
        },
    )?;
    sys.set("exec", exec_fn)?;

    Ok(sys)
}
