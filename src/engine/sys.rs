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
            let raw_args = args.0.unwrap_or_default();
            let mut opt_input = None;
            let mut target_cwd = sys_for_exec.cwd.clone();

            if let Some(ref opt) = options.0 {
                if let Ok(cwd_val) = opt.get::<_, String>("cwd") {
                    target_cwd = sys_for_exec.resolve_path(&cwd_val);
                }
                if let Ok(inp) = opt.get::<_, String>("input") {
                    opt_input = Some(inp);
                }
            }

            let resolved = resolve_executable(&cmd, raw_args, &target_cwd);
            let mut cmd_obj = std::process::Command::new(&resolved.program);
            cmd_obj.args(&resolved.args);
            cmd_obj.current_dir(&target_cwd);

            if let Some(ref opt) = options.0
                && let Ok(env_obj) = opt.get::<_, Object<'js>>("env")
            {
                for k in env_obj.keys::<String>().flatten() {
                    if let Ok(v) = env_obj.get::<_, String>(&k) {
                        cmd_obj.env(k, v);
                    }
                }
            }

            cmd_obj.stdout(std::process::Stdio::piped());
            cmd_obj.stderr(std::process::Stdio::piped());
            if opt_input.is_some() {
                cmd_obj.stdin(std::process::Stdio::piped());
            } else {
                cmd_obj.stdin(std::process::Stdio::null());
            }

            use command_group::CommandGroup;
            let result_obj = Object::new(ctx)?;
            match cmd_obj.group_spawn() {
                Ok(mut group_child) => {
                    if let (Some(input_str), Some(mut stdin)) =
                        (opt_input, group_child.inner().stdin.take())
                    {
                        use std::io::Write;
                        let _ = stdin.write_all(input_str.as_bytes());
                    }
                    match group_child.wait_with_output() {
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
                for k in hdr_obj.keys::<String>().flatten() {
                    if let Ok(v) = hdr_obj.get::<_, String>(&k) {
                        headers.insert(k, v);
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
                res_obj.set("ok", (200..300).contains(&status))?;
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
        |ctx: Ctx<'js>,
         url: String,
         options: rquickjs::function::Opt<Object<'js>>|
         -> Result<Object<'js>> { execute_http_request(ctx, "GET", url, options) },
    )?;
    http_obj.set("get", get_fn)?;

    let post_fn = Function::new(
        js_ctx.clone(),
        |ctx: Ctx<'js>,
         url: String,
         options: rquickjs::function::Opt<Object<'js>>|
         -> Result<Object<'js>> { execute_http_request(ctx, "POST", url, options) },
    )?;
    http_obj.set("post", post_fn)?;

    sys.set("http", http_obj)?;

    Ok(sys)
}

#[derive(Debug, Clone)]
pub struct ResolvedCommand {
    pub program: String,
    pub args: Vec<String>,
}

pub fn resolve_executable(cmd: &str, raw_args: Vec<String>, cwd: &Path) -> ResolvedCommand {
    let direct_path = Path::new(cmd);
    let candidate_file = if direct_path.is_absolute() {
        if direct_path.is_file() {
            Some(direct_path.to_path_buf())
        } else {
            None
        }
    } else {
        let joined = cwd.join(direct_path);
        if joined.is_file() {
            Some(joined)
        } else if direct_path.is_file() {
            Some(direct_path.to_path_buf())
        } else {
            None
        }
    };

    if let Some(file_path) = candidate_file {
        return resolve_script_or_binary_file(&file_path, raw_args, cwd);
    }

    resolve_command_name(cmd, raw_args, cwd)
}

fn is_binary_executable(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if ext == "exe" {
        return true;
    }

    use std::io::Read;
    if let Ok(mut f) = std::fs::File::open(path) {
        let mut magic = [0u8; 4];
        if let Ok(n) = f.read(&mut magic) {
            if n >= 2 && magic[0] == b'M' && magic[1] == b'Z' {
                return true;
            }
            if n >= 4 {
                if magic == [0x7f, b'E', b'L', b'F'] {
                    return true;
                }
                if magic == [0xFE, 0xED, 0xFA, 0xCE]
                    || magic == [0xCE, 0xFA, 0xED, 0xFE]
                    || magic == [0xFE, 0xED, 0xFA, 0xCF]
                    || magic == [0xCF, 0xFA, 0xED, 0xFE]
                    || magic == [0xCA, 0xFE, 0xBA, 0xBE]
                    || magic == [0xBE, 0xBA, 0xFE, 0xCA]
                {
                    return true;
                }
            }
        }
    }
    false
}

struct ShebangInfo {
    interpreter: String,
    flags: Vec<String>,
}

fn parse_shebang(path: &Path) -> Option<ShebangInfo> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = [0u8; 512];
    let n = file.read(&mut buf).ok()?;
    if n < 3 || buf[0] != b'#' || buf[1] != b'!' {
        return None;
    }

    let header = String::from_utf8_lossy(&buf[..n]);
    let first_line = header.lines().next()?;
    let line_content = first_line.trim_start_matches("#!").trim();
    if line_content.is_empty() {
        return None;
    }

    let mut parts = shlex::split(line_content)?;
    if parts.is_empty() {
        return None;
    }

    let mut interp_raw = parts.remove(0);
    if interp_raw.ends_with("/env") || interp_raw == "env" {
        if !parts.is_empty() && parts[0] == "-S" {
            parts.remove(0);
        }
        if !parts.is_empty() {
            interp_raw = parts.remove(0);
        }
    }

    let interp_name = Path::new(&interp_raw)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(&interp_raw)
        .to_string();

    Some(ShebangInfo {
        interpreter: interp_name,
        flags: parts,
    })
}

fn find_executable_in_path(cmd_name: &str, cwd: &Path) -> Option<String> {
    if let Ok(p) = which::which_in(cmd_name, std::env::var_os("PATH"), cwd) {
        #[cfg(windows)]
        {
            if cmd_name.eq_ignore_ascii_case("bash")
                && p.to_string_lossy()
                    .to_ascii_lowercase()
                    .contains("system32")
            {
                // 跳过 WSL System32 存根
            } else {
                return Some(p.to_string_lossy().to_string());
            }
        }
        #[cfg(not(windows))]
        {
            return Some(p.to_string_lossy().to_string());
        }
    }

    // 在精简 Linux 容器（如 Alpine）中缺少 bash 时平滑降级至 sh
    if cmd_name == "bash"
        && let Ok(p) = which::which_in("sh", std::env::var_os("PATH"), cwd)
    {
        return Some(p.to_string_lossy().to_string());
    }

    if cmd_name == "zsh" {
        if let Ok(p) = which::which_in("bash", std::env::var_os("PATH"), cwd) {
            #[cfg(windows)]
            {
                if !p
                    .to_string_lossy()
                    .to_ascii_lowercase()
                    .contains("system32")
                {
                    return Some(p.to_string_lossy().to_string());
                }
            }
            #[cfg(not(windows))]
            {
                return Some(p.to_string_lossy().to_string());
            }
        }
        if let Ok(p) = which::which_in("sh", std::env::var_os("PATH"), cwd) {
            return Some(p.to_string_lossy().to_string());
        }
    }

    None
}

fn resolve_script_or_binary_file(
    file_path: &Path,
    raw_args: Vec<String>,
    cwd: &Path,
) -> ResolvedCommand {
    if is_binary_executable(file_path) {
        return ResolvedCommand {
            program: file_path.to_string_lossy().to_string(),
            args: raw_args,
        };
    }

    let ext = file_path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    // 1. PowerShell 脚本 (.ps1)
    if ext == "ps1" {
        let ps_exe = find_executable_in_path("pwsh", cwd)
            .or_else(|| find_executable_in_path("powershell", cwd))
            .unwrap_or_else(|| "pwsh".to_string());
        #[cfg(windows)]
        let mut args = vec![
            "-NoProfile".to_string(),
            "-ExecutionPolicy".to_string(),
            "Bypass".to_string(),
            "-File".to_string(),
            file_path.to_string_lossy().to_string(),
        ];
        #[cfg(not(windows))]
        let mut args = vec![
            "-NoProfile".to_string(),
            "-File".to_string(),
            file_path.to_string_lossy().to_string(),
        ];
        args.extend(raw_args);
        return ResolvedCommand {
            program: ps_exe,
            args,
        };
    }

    // 2. Windows 批处理脚本 (.bat / .cmd)
    if ext == "bat" || ext == "cmd" {
        let cmd_exe = std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".to_string());
        let mut args = vec!["/c".to_string(), file_path.to_string_lossy().to_string()];
        args.extend(raw_args);
        return ResolvedCommand {
            program: cmd_exe,
            args,
        };
    }

    // 3. Python 脚本 (.py)
    if ext == "py" {
        let py_prog = find_executable_in_path("python3", cwd)
            .or_else(|| find_executable_in_path("python", cwd))
            .unwrap_or_else(|| "python".to_string());
        let mut args = vec![file_path.to_string_lossy().to_string()];
        args.extend(raw_args);
        return ResolvedCommand {
            program: py_prog,
            args,
        };
    }

    // 4. 解析 Shebang
    let shebang = parse_shebang(file_path);

    #[cfg(not(windows))]
    {
        if let Some(sb) = shebang {
            let interp = find_executable_in_path(&sb.interpreter, cwd).unwrap_or(sb.interpreter);
            let mut args = sb.flags;
            args.push(file_path.to_string_lossy().to_string());
            args.extend(raw_args);
            return ResolvedCommand {
                program: interp,
                args,
            };
        } else if ext == "zsh" {
            let interp = find_executable_in_path("zsh", cwd).unwrap_or_else(|| "zsh".to_string());
            let mut args = vec![file_path.to_string_lossy().to_string()];
            args.extend(raw_args);
            return ResolvedCommand {
                program: interp,
                args,
            };
        } else if ext == "sh" {
            let interp = find_executable_in_path("sh", cwd).unwrap_or_else(|| "sh".to_string());
            let mut args = vec![file_path.to_string_lossy().to_string()];
            args.extend(raw_args);
            return ResolvedCommand {
                program: interp,
                args,
            };
        }
        ResolvedCommand {
            program: file_path.to_string_lossy().to_string(),
            args: raw_args,
        }
    }

    #[cfg(windows)]
    {
        let target_interp = if let Some(ref sb) = shebang {
            sb.interpreter.to_ascii_lowercase()
        } else if ext == "zsh" {
            "zsh".to_string()
        } else if ext == "sh" {
            "sh".to_string()
        } else {
            return ResolvedCommand {
                program: file_path.to_string_lossy().to_string(),
                args: raw_args,
            };
        };

        if target_interp != "bash" && target_interp != "zsh" && target_interp != "sh" {
            let prog = find_executable_in_path(&target_interp, cwd).unwrap_or(target_interp);
            let mut args = shebang.map(|s| s.flags).unwrap_or_default();
            args.push(file_path.to_string_lossy().to_string());
            args.extend(raw_args);
            return ResolvedCommand {
                program: prog,
                args,
            };
        }

        let shell_prog = find_windows_posix_shell(&target_interp, cwd);
        let mut args = shebang.map(|s| s.flags).unwrap_or_default();
        args.push(file_path.to_string_lossy().replace('\\', "/"));
        args.extend(raw_args);
        ResolvedCommand {
            program: shell_prog,
            args,
        }
    }
}

fn resolve_command_name(cmd: &str, raw_args: Vec<String>, _cwd: &Path) -> ResolvedCommand {
    #[cfg(windows)]
    {
        let lower = cmd.to_ascii_lowercase();
        let stripped = lower.strip_suffix(".exe").unwrap_or(&lower);
        if stripped == "bash" || stripped == "zsh" || stripped == "sh" {
            let shell_prog = find_windows_posix_shell(stripped, _cwd);
            return ResolvedCommand {
                program: shell_prog,
                args: raw_args,
            };
        }
    }

    ResolvedCommand {
        program: cmd.to_string(),
        args: raw_args,
    }
}

#[cfg(windows)]
fn find_windows_posix_shell(preferred: &str, cwd: &Path) -> String {
    if let Ok(shell_env) = std::env::var("SHELL") {
        let shell_path = Path::new(&shell_env);
        if shell_path.is_file() {
            let shell_name = shell_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if shell_name == "zsh" || shell_name == "bash" || shell_name == "sh" {
                return shell_env;
            }
        }
    }

    let search_order: Vec<&str> = match preferred {
        "zsh" => vec!["zsh", "bash", "sh"],
        "bash" => vec!["bash", "sh", "zsh"],
        "sh" => vec!["sh", "bash", "zsh"],
        other => vec![other, "bash", "sh", "zsh"],
    };

    for target in search_order {
        if let Some(path) = find_executable_in_path(target, cwd)
            && !path.to_ascii_lowercase().contains("system32")
        {
            return path;
        }
    }

    preferred.to_string()
}
