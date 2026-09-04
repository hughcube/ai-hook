use rquickjs::{Ctx, Function, Object, Result};
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

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
                        return Some(line[..7].to_string());
                    }
                }
                break;
            }
            curr = dir.parent();
        }
        None
    }
}

/// Binds purely nanosecond/microsecond native primitives to the JS runtime.
/// Deliberately avoids slow subprocess spawns.
pub fn create_sys_object<'js>(js_ctx: &Ctx<'js>, sys_ctx: Rc<SysContext>) -> Result<Object<'js>> {
    let sys = Object::new(js_ctx.clone())?;

    // 1. sys.env: Pure memory environment lookup (< 1 µs)
    // Supports both sys.env("KEY") and sys.env.get("KEY")
    let env_fn = Function::new(js_ctx.clone(), |name: Option<String>| -> Option<String> {
        name.and_then(|n| std::env::var(n).ok())
    })?;
    let env_get = Function::new(js_ctx.clone(), |name: String| -> Option<String> {
        std::env::var(name).ok()
    })?;
    env_fn.set("get", env_get)?;
    sys.set("env", env_fn)?;

    // 2. sys.cwd(): Current working directory
    let sys_for_cwd = sys_ctx.clone();
    let cwd_fn = Function::new(js_ctx.clone(), move || -> String {
        sys_for_cwd.cwd.to_string_lossy().to_string()
    })?;
    sys.set("cwd", cwd_fn)?;

    // 3. sys.fs: Rust native file I/O with request-scoped caching (~ 0.01 ms)
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

    let sys_for_list = sys_ctx.clone();
    let list_fn = Function::new(
        js_ctx.clone(),
        move |dir_path: Option<String>| -> Vec<String> {
            let target = match dir_path {
                Some(p) => sys_for_list.resolve_path(&p),
                None => sys_for_list.cwd.clone(),
            };
            if let Ok(entries) = std::fs::read_dir(target) {
                entries
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .collect()
            } else {
                Vec::new()
            }
        },
    )?;
    fs_obj.set("list", list_fn)?;
    sys.set("fs", fs_obj)?;

    // 4. sys.git: Pure-memory .git/HEAD parser (~ 0.02 ms, 0 git.exe processes)
    let git_obj = Object::new(js_ctx.clone())?;
    let sys_for_branch = sys_ctx.clone();
    let branch_fn = Function::new(js_ctx.clone(), move || -> Option<String> {
        sys_for_branch.git_branch()
    })?;
    git_obj.set("branch", branch_fn)?;

    let sys_for_root = sys_ctx.clone();
    let root_fn = Function::new(js_ctx.clone(), move || -> Option<String> {
        let mut curr = Some(sys_for_root.cwd.as_path());
        while let Some(dir) = curr {
            if dir.join(".git").exists() {
                return Some(dir.to_string_lossy().to_string());
            }
            curr = dir.parent();
        }
        None
    })?;
    git_obj.set("root", root_fn)?;

    let sys_for_git_status = sys_ctx.clone();
    let status_fn = Function::new(js_ctx.clone(), move || -> String {
        if let Some(b) = sys_for_git_status.git_branch() {
            format!("branch: {}", b)
        } else {
            "not a git repository".to_string()
        }
    })?;
    git_obj.set("status", status_fn)?;
    sys.set("git", git_obj)?;

    // 5. sys.exec(cmd, args?, options?): Execute external command or script
    let sys_for_exec = sys_ctx.clone();
    let exec_fn = Function::new(
        js_ctx.clone(),
        move |ctx: Ctx<'js>,
              cmd: String,
              args: rquickjs::function::Opt<Vec<String>>,
              options: rquickjs::function::Opt<Object<'js>>|
              -> Result<Object<'js>> {
            let exec_cmd = if cfg!(windows) && cmd.eq_ignore_ascii_case("bash") {
                resolve_windows_bash(&cmd)
            } else {
                cmd
            };
            let mut cmd_obj = std::process::Command::new(&exec_cmd);
            if let Some(a) = args.0 {
                cmd_obj.args(a);
            }
            let mut opt_input = None;
            if let Some(opt) = options.0 {
                if let Ok(cwd_val) = opt.get::<_, String>("cwd") {
                    cmd_obj.current_dir(sys_for_exec.resolve_path(&cwd_val));
                } else {
                    cmd_obj.current_dir(&sys_for_exec.cwd);
                }
                if let Ok(env_obj) = opt.get::<_, Object<'js>>("env") {
                    for key in env_obj.keys::<String>() {
                        if let Ok(k) = key {
                            if let Ok(v) = env_obj.get::<_, String>(&k) {
                                cmd_obj.env(k, v);
                            }
                        }
                    }
                }
                if let Ok(inp) = opt.get::<_, String>("input") {
                    opt_input = Some(inp);
                }
            } else {
                cmd_obj.current_dir(&sys_for_exec.cwd);
            }

            cmd_obj.stdout(std::process::Stdio::piped());
            cmd_obj.stderr(std::process::Stdio::piped());
            if opt_input.is_some() {
                cmd_obj.stdin(std::process::Stdio::piped());
            } else {
                cmd_obj.stdin(std::process::Stdio::null());
            }

            let result_obj = Object::new(ctx)?;
            match cmd_obj.spawn() {
                Ok(mut child) => {
                    if let Some(input_str) = opt_input {
                        if let Some(mut stdin) = child.stdin.take() {
                            use std::io::Write;
                            let _ = stdin.write_all(input_str.as_bytes());
                        }
                    }
                    match child.wait_with_output() {
                        Ok(output) => {
                            let code = output.status.code().unwrap_or(-1);
                            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                            result_obj.set("code", code)?;
                            result_obj.set("status", code)?;
                            result_obj.set("exitCode", code)?;
                            result_obj.set("stdout", stdout)?;
                            result_obj.set("stderr", stderr)?;
                            result_obj.set("success", output.status.success())?;
                        }
                        Err(e) => {
                            result_obj.set("code", -1)?;
                            result_obj.set("status", -1)?;
                            result_obj.set("exitCode", -1)?;
                            result_obj.set("stdout", "")?;
                            result_obj.set("stderr", format!("wait failed: {}", e))?;
                            result_obj.set("success", false)?;
                        }
                    }
                }
                Err(e) => {
                    result_obj.set("code", -1)?;
                    result_obj.set("status", -1)?;
                    result_obj.set("exitCode", -1)?;
                    result_obj.set("stdout", "")?;
                    result_obj.set("stderr", format!("spawn failed: {}", e))?;
                    result_obj.set("success", false)?;
                }
            }
            Ok(result_obj)
        },
    )?;
    sys.set("exec", exec_fn)?;

    // 6. sys.http: Light HTTP client
    let http_obj = Object::new(js_ctx.clone())?;

    fn execute_http_request<'js>(
        ctx: Ctx<'js>,
        method: &str,
        url: String,
        options: rquickjs::function::Opt<Object<'js>>,
    ) -> Result<Object<'js>> {
        let mut timeout_ms = 10000u64;
        let mut headers = HashMap::new();
        let mut body_str = None;

        if let Some(opt) = options.0 {
            if let Ok(t) = opt.get::<_, u64>("timeout") {
                timeout_ms = t;
            }
            if let Ok(b) = opt.get::<_, String>("body") {
                body_str = Some(b);
            }
            if let Ok(hdr_obj) = opt.get::<_, Object<'js>>("headers") {
                for key in hdr_obj.keys::<String>() {
                    if let Ok(k) = key {
                        if let Ok(v) = hdr_obj.get::<_, String>(&k) {
                            headers.insert(k, v);
                        }
                    }
                }
            }
        }

        let agent = ureq::builder()
            .timeout(std::time::Duration::from_millis(timeout_ms))
            .build();

        let mut req = agent.request(method, &url);
        for (k, v) in &headers {
            req = req.set(k, v);
        }

        let res_obj = Object::new(ctx.clone())?;
        let resp_result = if let Some(body) = body_str {
            req.send_string(&body)
        } else {
            req.call()
        };

        match resp_result {
            Ok(response) => {
                let status = response.status();
                let headers_obj = Object::new(ctx)?;
                for name in response.headers_names() {
                    if let Some(val) = response.header(&name) {
                        headers_obj.set(name, val)?;
                    }
                }
                let body = response.into_string().unwrap_or_default();
                res_obj.set("status", status)?;
                res_obj.set("ok", status >= 200 && status < 300)?;
                res_obj.set("headers", headers_obj)?;
                res_obj.set("body", body)?;
            }
            Err(ureq::Error::Status(status, response)) => {
                let headers_obj = Object::new(ctx)?;
                for name in response.headers_names() {
                    if let Some(val) = response.header(&name) {
                        headers_obj.set(name, val)?;
                    }
                }
                let body = response.into_string().unwrap_or_default();
                res_obj.set("status", status)?;
                res_obj.set("ok", false)?;
                res_obj.set("headers", headers_obj)?;
                res_obj.set("body", body)?;
            }
            Err(ureq::Error::Transport(transport_err)) => {
                res_obj.set("status", 0)?;
                res_obj.set("ok", false)?;
                res_obj.set("headers", Object::new(ctx)?)?;
                res_obj.set("body", format!("{}", transport_err))?;
            }
        }
        Ok(res_obj)
    }

    let get_fn = Function::new(
        js_ctx.clone(),
        |ctx: Ctx<'js>, url: String, options: rquickjs::function::Opt<Object<'js>>| -> Result<Object<'js>> {
            execute_http_request(ctx, "GET", url, options)
        },
    )?;
    http_obj.set("get", get_fn)?;

    let post_fn = Function::new(
        js_ctx.clone(),
        |ctx: Ctx<'js>, url: String, options: rquickjs::function::Opt<Object<'js>>| -> Result<Object<'js>> {
            execute_http_request(ctx, "POST", url, options)
        },
    )?;
    http_obj.set("post", post_fn)?;

    sys.set("http", http_obj)?;

    Ok(sys)
}

#[cfg(windows)]
fn resolve_windows_bash(fallback: &str) -> String {
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let dir_str = dir.to_string_lossy();
            if dir_str.to_ascii_lowercase().contains("system32") {
                continue;
            }
            let candidate = dir.join("bash.exe");
            if candidate.is_file() {
                return candidate.to_string_lossy().to_string();
            }
        }
    }
    let default_git_bash = std::path::Path::new(r"C:\Program Files\Git\bin\bash.exe");
    if default_git_bash.is_file() {
        return default_git_bash.to_string_lossy().to_string();
    }
    fallback.to_string()
}

#[cfg(not(windows))]
fn resolve_windows_bash(fallback: &str) -> String {
    fallback.to_string()
}

