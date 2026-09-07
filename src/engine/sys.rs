use rquickjs::{Ctx, Function, Object, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use crate::NoConsoleSpawn;

/// Windows: CREATE_NO_WINDOW (see NoConsoleSpawn docs).
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Spawn `cmd` inside a job/process-group with stdout/stderr piped, keeping
/// the console hidden on Windows.
///
/// ⚠️ Must go through `CommandGroupBuilder::creation_flags`, NOT
/// `std::process::Command::creation_flags`: command-group 5.x overwrites the
/// std Command flags with `builder.creation_flags | CREATE_SUSPENDED` at
/// spawn time, silently dropping CREATE_NO_WINDOW — on this GUI-subsystem
/// binary every console child then allocates a fresh conhost window (a
/// visible new-terminal flash on every sys.exec call).
#[cfg(windows)]
fn group_spawn_hidden(cmd: &mut std::process::Command) -> std::io::Result<command_group::GroupChild> {
    use command_group::CommandGroup;
    cmd.group()
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
}

#[cfg(not(windows))]
fn group_spawn_hidden(cmd: &mut std::process::Command) -> std::io::Result<command_group::GroupChild> {
    use command_group::CommandGroup;
    cmd.group_spawn()
}

/// Host-capability surface handed to every rule.
///
/// There is deliberately **no request-level cache** here: within one hook
/// invocation the OS page/dentry cache already turns repeated reads of the
/// same file into pure in-memory operations, and the rule set has no
/// shared-read pattern worth an extra concept (one request cache, its
/// invalidation rules, and its memory bounds). Keep this object boring.
pub struct SysContext {
    cwd: PathBuf,
}

impl SysContext {
    pub fn new(cwd: impl Into<PathBuf>) -> Self {
        Self { cwd: cwd.into() }
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
        self.resolve_path(path_str).exists()
    }

    pub fn fs_read_text(&self, path_str: &str) -> Option<String> {
        std::fs::read_to_string(self.resolve_path(path_str)).ok()
    }

    pub fn git_branch(&self) -> Option<String> {
        Self::find_git_branch(&self.cwd)
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

/// Binds the host-capability object to the JS runtime. Read-only lookups
/// (env/fs/git) are pure in-memory native calls; `exec`/`http` are the
/// deliberate sandbox-escape hatches — flagged at their binding sites below.
pub fn create_sys_object<'js>(js_ctx: &Ctx<'js>, sys_ctx: Rc<SysContext>) -> Result<Object<'js>> {
    let sys = Object::new(js_ctx.clone())?;

    // 1. sys.env(key): pure in-memory environment lookup (< 1 µs).
    let env_fn = Function::new(js_ctx.clone(), |name: Option<String>| -> Option<String> {
        name.and_then(|n| std::env::var(n).ok())
    })?;
    sys.set("env", env_fn)?;

    // (sys.cwd() does not exist: the working directory is `ctx.cwd`, and
    // SysContext resolves every relative path passed to fs/exec against it.)

    // 2. sys.fs: Rust-native file I/O. One name per operation.
    let fs_obj = Object::new(js_ctx.clone())?;
    let sys_for_exists = sys_ctx.clone();
    let exists_fn = Function::new(js_ctx.clone(), move |path: String| -> bool {
        sys_for_exists.fs_exists(&path)
    })?;
    fs_obj.set("exists", exists_fn)?;

    let sys_for_read = sys_ctx.clone();
    let read_fn = Function::new(js_ctx.clone(), move |path: String| -> Option<String> {
        sys_for_read.fs_read_text(&path)
    })?;
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

    // 3. sys.git: pure-memory .git/HEAD parser (~ 0.02 ms, 0 git.exe
    //    processes). Branch and repo root are the whole surface.
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
    sys.set("git", git_obj)?;

    // 4. sys.exec(cmd, args?, options?): Execute external command or script.
    //
    //    ⚠️ SANDBOX ESCAPE: this runs arbitrary processes with the hook's full
    //    permissions — the QuickJS sandbox does not contain it. `sys` is the
    //    only escape hatch (plain JS has zero I/O primitives), which is why it
    //    lives here visibly instead of being spread across rules. The result
    //    carries one exit-code field (`code`) and one success flag (`ok`,
    //    matching `sys.http`).
    //
    //    Liveness bound: the JS watchdog interrupt cannot fire while a native
    //    call blocks, so the execution is bounded here instead — `timeout`
    //    (ms, default 10 000) after which the whole process group is killed
    //    and the result reports `ok: false`. Without it a hanging child would
    //    stall the entire hook until the host's own (much longer) hook
    //    timeout kicks in.
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
            let mut timeout_ms: u64 = 10_000;

            if let Some(ref opt) = options.0 {
                if let Ok(cwd_val) = opt.get::<_, String>("cwd") {
                    target_cwd = sys_for_exec.resolve_path(&cwd_val);
                }
                if let Ok(inp) = opt.get::<_, String>("input") {
                    opt_input = Some(inp);
                }
                if let Ok(t) = opt.get::<_, u64>("timeout") {
                    timeout_ms = t;
                }
            }

            let resolved = resolve_executable(&cmd, raw_args, &target_cwd);
            let mut cmd_obj = std::process::Command::new(&resolved.program);
            cmd_obj.args(&resolved.args);
            cmd_obj.current_dir(&target_cwd);
            cmd_obj.no_console_window();

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

            let result_obj = Object::new(ctx)?;
            match group_spawn_hidden(&mut cmd_obj) {
                Ok(mut group_child) => {
                    // Feed stdin from a thread: a child that never reads must
                    // not block us on write_all before we even start polling.
                    if let Some(input_str) = opt_input
                        && let Some(mut stdin) = group_child.inner().stdin.take()
                    {
                        use std::io::Write;
                        std::thread::spawn(move || {
                            let _ = stdin.write_all(input_str.as_bytes());
                        });
                    }
                    // Drain both pipes from threads so a chatty child cannot
                    // deadlock on a full pipe buffer while we poll for exit.
                    let stdout_pipe = group_child.inner().stdout.take();
                    let stderr_pipe = group_child.inner().stderr.take();
                    let out_handle = std::thread::spawn(move || {
                        let mut buf = Vec::new();
                        if let Some(mut p) = stdout_pipe {
                            use std::io::Read;
                            let _ = p.read_to_end(&mut buf);
                        }
                        buf
                    });
                    let err_handle = std::thread::spawn(move || {
                        let mut buf = Vec::new();
                        if let Some(mut p) = stderr_pipe {
                            use std::io::Read;
                            let _ = p.read_to_end(&mut buf);
                        }
                        buf
                    });

                    // Poll for exit with a hard deadline; on expiry kill the
                    // whole group (children included) and reap it.
                    let deadline =
                        std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
                    let mut status = group_child.try_wait().ok().flatten();
                    let mut timed_out = false;
                    while status.is_none() {
                        if std::time::Instant::now() >= deadline {
                            let _ = group_child.kill();
                            let _ = group_child.wait();
                            timed_out = true;
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        status = group_child.try_wait().ok().flatten();
                    }

                    let stdout_bytes = out_handle.join().unwrap_or_default();
                    let stderr_bytes = err_handle.join().unwrap_or_default();
                    let stderr_text = String::from_utf8_lossy(&stderr_bytes).to_string();

                    if timed_out {
                        result_obj.set("code", -1)?;
                        result_obj.set("ok", false)?;
                        result_obj
                            .set("stdout", String::from_utf8_lossy(&stdout_bytes).to_string())?;
                        result_obj.set(
                            "stderr",
                            format!(
                                "timed out after {} ms{}",
                                timeout_ms,
                                if stderr_text.is_empty() {
                                    String::new()
                                } else {
                                    format!("\n{}", stderr_text)
                                }
                            ),
                        )?;
                    } else if let Some(exit) = status {
                        let code = exit.code().unwrap_or(-1);
                        result_obj.set("code", code)?;
                        result_obj.set("ok", exit.success())?;
                        result_obj
                            .set("stdout", String::from_utf8_lossy(&stdout_bytes).to_string())?;
                        result_obj.set("stderr", stderr_text)?;
                    } else {
                        // try_wait error path (failed to poll)
                        result_obj.set("code", -1)?;
                        result_obj.set("ok", false)?;
                        result_obj
                            .set("stdout", String::from_utf8_lossy(&stdout_bytes).to_string())?;
                        result_obj.set("stderr", stderr_text)?;
                    }
                }
                Err(e) => {
                    result_obj.set("code", -1)?;
                    result_obj.set("ok", false)?;
                    result_obj.set("stdout", "")?;
                    result_obj.set("stderr", format!("spawn failed: {}", e))?;
                }
            }
            Ok(result_obj)
        },
    )?;
    sys.set("exec", exec_fn)?;

    // 5. sys.http: light HTTP client.
    //
    //    ⚠️ SANDBOX ESCAPE: arbitrary network access, same trust level as
    //    `sys.exec`. Requests default to a 10 s timeout; `ok` mirrors the
    //    2xx range so rules never hand-roll `status >= 200 && status < 300`.
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
