// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `wxc-exec` `ProcessContainer` launcher and request types.

use base64::Engine as _;
use serde::Serialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use thiserror::Error;
use tokio::process::Command;
use tracing::{debug, info};

/// Stable MXC schema version shared by the mapper and live launcher.
pub const MXC_SCHEMA_VERSION: &str = "1.0.0";

/// MXC development schema for state-aware `isolation_session` lifecycles. Only
/// this contract carries provision-time filesystem grants, which MXC enforces
/// by brokering each path from the calling user to the agent user (BFS).
pub const MXC_ISOLATION_SESSION_SCHEMA_VERSION: &str = "1.1.0-alpha";

/// Environment flag selecting the in-process mock `wxc-exec` shim. When set to
/// `"1"`, the invoker does not spawn `wxc-exec.exe`. This wiring shim has no
/// `AppContainer` token and must fail runtime audit before workload execution.
pub const MOCK_ENV_VAR: &str = "OPENSHELL_MXC_MOCK_WXC";

fn mock_enabled() -> bool {
    std::env::var(MOCK_ENV_VAR).is_ok_and(|value| value == "1")
}

/// Normalize a path/command fragment to lowercase backslash form for the mock's
/// in-policy substring check.
fn mock_normalize(s: &str) -> String {
    s.replace('/', "\\").to_lowercase()
}

// ── Request types ─────────────────────────────────────────────────────────────

/// Filesystem shares for the sandbox.
///
/// `ProcessContainer` honors `readwrite`/`readonly` grants and `denied_paths`.
#[derive(Debug, Default)]
#[allow(clippy::struct_field_names)]
pub struct MxcFilesystem {
    pub readwrite_paths: Vec<String>,
    pub readonly_paths: Vec<String>,
    pub denied_paths: Vec<String>,
    /// Directories that may be listed and traversed but not read into. Only
    /// sent for `isolation_session`, where the sandbox working directory must
    /// be enterable even when the policy grants none of its contents.
    pub enumerate_paths: Vec<String>,
}

/// Network redirect fragment emitted when governed egress is enabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxcNetwork {
    pub egress_default: String,
    pub proxy: Option<SocketAddr>,
    /// When true, emits permissive MXC 1.0 directional ingress and host loopback.
    /// Required for node.js to initialize inside a processcontainer — without
    /// it, node.exe DLL initialization fails with `STATUS_DLL_INIT_FAILED`.
    pub allow_local_network: bool,
}

/// Directional clipboard access in the MXC top-level `ui` policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MxcClipboardAccess {
    None,
    Read,
    Write,
    All,
}

impl MxcClipboardAccess {
    const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Read => "read",
            Self::Write => "write",
            Self::All => "all",
        }
    }
}

/// Cross-platform MXC UI policy emitted for a process container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxcUi {
    pub disable: bool,
    pub clipboard: MxcClipboardAccess,
    pub injection: bool,
}

fn ui_json(ui: &MxcUi) -> serde_json::Value {
    serde_json::json!({
        "disable": ui.disable,
        "clipboard": ui.clipboard.as_str(),
        "injection": ui.injection,
    })
}

/// `processContainer`-specific knobs (one-shot `AppContainer` backend).
#[derive(Debug, Default, Clone)]
pub struct MxcProcessContainer {
    /// Request a Less-Privileged `AppContainer` (stricter default-deny).
    pub least_privilege: bool,
    /// `AppContainer` capabilities to grant (e.g. `internetClient`).
    pub capabilities: Vec<String>,
}

/// Process config for the exec phase.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MxcProcess {
    pub command_line: String,
    pub cwd: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    /// 0 = no timeout (long-lived agent).
    pub timeout: u64,
}

/// Redacts `process.env` and `process.commandLine` from a wxc-config JSON
/// before it's ever logged or written to a sandbox-readable path (only
/// under `self.debug`, but debug output still isn't a safe place for it).
/// Both can carry host secrets verbatim -- `env` e.g. the shipped
/// `OpenClaw` example config's `OPENCLAW_GATEWAY_TOKEN`, `commandLine`
/// whenever a secret is passed as a literal CLI argument -- and both debug
/// sinks (gateway logs, and for `run_oneshot` a file inside the sandbox's
/// own readwrite path) are places an attacker or an over-broad log
/// retention policy could read from. Everything else debug tooling might
/// need to compare (filesystem grants, network policy, ...) is left intact.
fn redact_env_for_debug(config: &serde_json::Value) -> serde_json::Value {
    let mut redacted = config.clone();
    if let Some(env) = redacted.get_mut("process").and_then(|p| p.get_mut("env")) {
        let count = env.as_array().map_or(0, Vec::len);
        *env = serde_json::json!(format!("<redacted: {count} entries>"));
    }
    if let Some(command_line) = redacted
        .get_mut("process")
        .and_then(|p| p.get_mut("commandLine"))
    {
        *command_line = serde_json::json!("<redacted>");
    }
    redacted
}

fn network_json(network: &MxcNetwork) -> serde_json::Value {
    let mut value = if network.proxy.is_some() {
        // Use direct loopback egress rather than runtimeConfig.networkProxy proxy
        // mode. Proxy mode routes all outbound TCP through processmodel.dll's WFP
        // redirect, which can block the authenticated Sandbox Protocol and
        // explicit proxy connections to their host loopback listeners. Limit the
        // exception to 127.0.0.1/32 rather than the broader 127.0.0.0/8 range.
        // PSEC tier is still selected because requires_psec_networking() returns
        // true when egress.allow is non-empty (no NetworkIsolationSetAppContainerConfig
        // call needed — no elevation required).
        //
        // Deliberately no `ports` restriction: the authenticated Sandbox
        // Protocol listener, generation-scoped supervisor proxy, and dynamic
        // forwarding listeners all use independently allocated loopback ports.
        serde_json::json!({
            "egress": {
                "default": "deny",
                "allow": [{"to": [{"cidr": "127.0.0.1/32"}]}]
            },
            "ingress": { "default": "allow", "hostLoopback": "allow" },
        })
    } else {
        serde_json::json!({ "egress": { "default": network.egress_default } })
    };
    if network.proxy.is_none() && network.allow_local_network {
        value["ingress"] = serde_json::json!({ "default": "allow", "hostLoopback": "allow" });
    }
    value
}

fn oneshot_config_json(
    container_id: &str,
    filesystem: &MxcFilesystem,
    pc: &MxcProcessContainer,
    process: &MxcProcess,
    network: Option<&MxcNetwork>,
    ui: Option<&MxcUi>,
) -> serde_json::Value {
    let mut filesystem_json = serde_json::Map::new();
    if !filesystem.readwrite_paths.is_empty() {
        filesystem_json.insert(
            "readwritePaths".into(),
            filesystem.readwrite_paths.clone().into(),
        );
    }
    if !filesystem.readonly_paths.is_empty() {
        filesystem_json.insert(
            "readonlyPaths".into(),
            filesystem.readonly_paths.clone().into(),
        );
    }
    if !filesystem.denied_paths.is_empty() {
        filesystem_json.insert("deniedPaths".into(), filesystem.denied_paths.clone().into());
    }

    let mut pc_json = serde_json::Map::new();
    pc_json.insert("leastPrivilege".into(), pc.least_privilege.into());
    if !pc.capabilities.is_empty() {
        pc_json.insert("capabilities".into(), pc.capabilities.clone().into());
    }

    let mut config = serde_json::json!({
        "version": MXC_SCHEMA_VERSION,
        "containerId": container_id,
        "containment": "processcontainer",
        "process": {
            "commandLine": process.command_line.as_str(),
            "cwd": process.cwd.as_str(),
            "env": &process.env,
            "timeout": process.timeout,
        },
        "processContainer": serde_json::Value::Object(pc_json),
        "filesystem": serde_json::Value::Object(filesystem_json),
    });
    if let Some(network) = network {
        config["network"] = network_json(network);
    }
    // Root-level ui section required by mxc-fixes-env-vars build. Comes from
    // the typed SandboxPolicy via `ui` -- EmbeddedPolicyMapper always
    // populates this for process_container (with restrictive defaults --
    // disable=true, Win32k syscall lockdown -- when the policy has no
    // explicit `ui:` section), so `None` here only happens in tests that
    // bypass the mapper; omit the section entirely rather than guess.
    if let Some(ui) = ui {
        config["ui"] = ui_json(ui);
    }
    config
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum InvokerError {
    #[error("wxc-exec spawn failed: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("wxc-exec config serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("wxc-exec {operation} failed (exit {exit_code}): {message}")]
    Phase {
        operation: &'static str,
        exit_code: i32,
        message: String,
    },
    #[error("wxc-exec {0} is not available in mock mode")]
    Mock(&'static str),
}

/// The agent identity minted by an `isolation_session` provision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationSessionProvisioned {
    /// Opaque MXC lifecycle id addressing every later phase.
    pub sandbox_id: String,
    pub agent_user_name: String,
    pub agent_user_sid: String,
}

/// The canonical unrestricted-network acknowledgment MXC requires at
/// `isolation_session` provision: the backend cannot filter the session network.
fn isolation_session_network_json() -> serde_json::Value {
    serde_json::json!({
        "egress": { "default": "allow" },
        "ingress": { "default": "allow", "hostLoopback": "allow" },
    })
}

fn isolation_session_provision_json(filesystem: &MxcFilesystem) -> serde_json::Value {
    let mut filesystem_json = serde_json::Map::new();
    if !filesystem.readwrite_paths.is_empty() {
        filesystem_json.insert(
            "readwritePaths".into(),
            filesystem.readwrite_paths.clone().into(),
        );
    }
    if !filesystem.readonly_paths.is_empty() {
        filesystem_json.insert(
            "readonlyPaths".into(),
            filesystem.readonly_paths.clone().into(),
        );
    }
    if !filesystem.enumerate_paths.is_empty() {
        filesystem_json.insert(
            "enumeratePaths".into(),
            filesystem.enumerate_paths.clone().into(),
        );
    }
    if !filesystem.denied_paths.is_empty() {
        filesystem_json.insert("deniedPaths".into(), filesystem.denied_paths.clone().into());
    }
    let mut config = serde_json::json!({
        "version": MXC_ISOLATION_SESSION_SCHEMA_VERSION,
        "containment": "isolation_session",
        "network": isolation_session_network_json(),
    });
    if !filesystem_json.is_empty() {
        config["filesystem"] = serde_json::Value::Object(filesystem_json);
    }
    config
}

fn isolation_session_exec_json(process: &MxcProcess) -> serde_json::Value {
    let mut process_json = serde_json::json!({
        "commandLine": process.command_line.as_str(),
        "cwd": process.cwd.as_str(),
        "timeout": process.timeout,
    });
    if !process.env.is_empty() {
        // The agent user's default environment cannot be replaced, only overlaid.
        process_json["env"] = serde_json::json!(&process.env);
        process_json["inheritDefaultEnv"] = serde_json::json!(true);
    }
    serde_json::json!({
        "version": MXC_ISOLATION_SESSION_SCHEMA_VERSION,
        "process": process_json,
    })
}

/// Extracts a readable failure from a wxc-exec response envelope.
fn phase_failure(
    operation: &'static str,
    exit_code: i32,
    stdout: &str,
    stderr: &str,
) -> InvokerError {
    let message = serde_json::from_str::<serde_json::Value>(stdout)
        .ok()
        .and_then(|envelope| {
            envelope.get("error").map(|error| {
                let code = error
                    .get("code")
                    .and_then(|c| c.as_str())
                    .unwrap_or("error");
                let text = error.get("message").and_then(|m| m.as_str()).unwrap_or("");
                format!("{code}: {text}")
            })
        })
        .unwrap_or_else(|| {
            let detail = if stderr.trim().is_empty() {
                stdout
            } else {
                stderr
            };
            detail.trim().to_string()
        });
    InvokerError::Phase {
        operation,
        exit_code,
        message,
    }
}

// ── Invoker ───────────────────────────────────────────────────────────────────

/// Wraps the one-shot `wxc-exec` `ProcessContainer` invocation.
#[derive(Debug, Clone)]
pub struct WxcExecInvoker {
    exec_path: PathBuf,
    debug: bool,
    /// When true, use the in-process mock instead of spawning `wxc-exec.exe`.
    mock: bool,
}

impl WxcExecInvoker {
    pub fn new(exec_path: impl Into<PathBuf>, debug: bool) -> Self {
        Self {
            exec_path: exec_path.into(),
            debug,
            mock: mock_enabled(),
        }
    }

    pub(crate) const fn is_mock(&self) -> bool {
        self.mock
    }

    fn real_command(&self) -> Command {
        let mut command = Command::new(&self.exec_path);
        command
            // Both processes in the runtime pair must die if their monitor is
            // cancelled, not only when it takes the explicit shutdown branch.
            .kill_on_drop(true)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        command
    }

    /// Launch the real boundary runtime without OS isolation for wiring tests.
    /// Filesystem denial must be tested with real MXC, not this mock.
    fn mock_spawn_with_grants(
        process: &MxcProcess,
        grants: &[String],
    ) -> Result<tokio::process::Child, InvokerError> {
        let cmd_norm = mock_normalize(&process.command_line);
        // The RFC 0012 boundary is launched with its granted bootstrap directory.
        // This check concerns bootstrap wiring, never workload authorization.
        let in_policy = grants.iter().any(|g| !g.is_empty() && cmd_norm.contains(g));

        // Spawn the encoded executable directly: a cmd.exe intermediary would
        // survive only as a parent handle while kill_on_drop orphaned its child.
        let (program, arguments) = process
            .command_line
            .strip_prefix('"')
            .map_or_else(
                || process.command_line.split_once(char::is_whitespace),
                |quoted| quoted.split_once('"'),
            )
            .unwrap_or((&process.command_line, ""));
        let mut cmd = Command::new(if in_policy { program } else { "cmd" });
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true);
        if in_policy {
            debug!(command = %process.command_line, "mock exec: in-policy, running agent");
            // Retain the already-encoded Windows argv without another quoting pass.
            cmd.raw_arg(arguments.trim_start());
        } else {
            debug!(command = %process.command_line, "mock exec: OUT-OF-POLICY, denying");
            cmd.arg("/c").arg(
                "echo Access is denied. (out-of-policy write blocked by AppContainer) 1>&2& exit 1",
            );
        }
        let child = cmd.spawn()?;
        Ok(child)
    }

    /// Build a **one-shot** `processContainer` config (no `phase`) and spawn it.
    ///
    /// `processContainer` is a single ephemeral `AppContainer`: one `wxc-exec`
    /// invocation creates the container, runs the sandbox runtime, and tears it
    /// down when that runtime exits. The `AppContainer` is genuinely
    /// default-deny, so a write to any ungranted path is denied by the OS.
    ///
    /// **Stdout is raw agent output; the exit code is the agent's own exit code.**
    pub async fn run_oneshot(
        &self,
        container_id: &str,
        filesystem: MxcFilesystem,
        pc: MxcProcessContainer,
        process: MxcProcess,
        network: Option<MxcNetwork>,
        ui: Option<MxcUi>,
    ) -> Result<tokio::process::Child, InvokerError> {
        let config = oneshot_config_json(
            container_id,
            &filesystem,
            &pc,
            &process,
            network.as_ref(),
            ui.as_ref(),
        );
        if self.mock {
            let grants: Vec<String> = filesystem
                .readwrite_paths
                .iter()
                .map(|p| mock_normalize(p))
                .collect();
            return Self::mock_spawn_with_grants(&process, &grants);
        }

        let json = serde_json::to_string(&config)?;
        if self.debug {
            // Redacted before either sink: the readwrite path is inside the
            // sandbox itself (readable by whatever untrusted code runs
            // there), and gateway logs may have broader retention/access
            // than the secrets in `process.env` (e.g. OPENCLAW_GATEWAY_TOKEN
            // in the shipped OpenClaw example config) should get.
            let redacted = redact_env_for_debug(&config);
            let redacted_json = serde_json::to_string(&redacted).unwrap_or_else(|_| json.clone());
            // Dump into the first readwrite path for comparison.
            if let Some(rw) = config
                .get("filesystem")
                .and_then(|f| f.get("readwritePaths"))
                .and_then(|a| a.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
            {
                let _ = std::fs::write(
                    std::path::Path::new(rw).join("wxc-exec-config-debug.json"),
                    &redacted_json,
                );
            }
            let pretty =
                serde_json::to_string_pretty(&redacted).unwrap_or_else(|_| redacted_json.clone());
            info!(container_id = %container_id, "generated wxc-config:\n{pretty}");
        }
        let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());

        let mut cmd = self.real_command();
        cmd.arg("--config-base64").arg(&b64);
        if self.debug {
            cmd.arg("--debug");
        }

        info!(container_id = %container_id, "wxc-exec one-shot processContainer spawn");
        let child = cmd.spawn()?;
        Ok(child)
    }

    /// Runs one non-exec state-aware phase to completion and returns its
    /// `result` object.
    async fn run_phase(
        &self,
        operation: &'static str,
        config: &serde_json::Value,
        sandbox_id: Option<&str>,
    ) -> Result<serde_json::Value, InvokerError> {
        if self.mock {
            return Err(InvokerError::Mock(operation));
        }
        let json = serde_json::to_string(config)?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
        let mut cmd = Command::new(&self.exec_path);
        cmd.kill_on_drop(true)
            .stdin(std::process::Stdio::null())
            .arg("--config-base64")
            .arg(&b64)
            .arg("--operation")
            .arg(operation);
        if let Some(sandbox_id) = sandbox_id {
            cmd.arg("--container-id").arg(sandbox_id);
        }
        if self.debug {
            cmd.arg("--debug");
        }
        debug!(operation, config = %json, "wxc-exec isolation_session phase");
        let output = cmd.output().await?;
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let exit_code = output.status.code().unwrap_or(-1);
        if !output.status.success() {
            return Err(phase_failure(operation, exit_code, &stdout, &stderr));
        }
        if stdout.trim().is_empty() {
            return Ok(serde_json::Value::Null);
        }
        let envelope: serde_json::Value = serde_json::from_str(stdout.trim())
            .map_err(|_| phase_failure(operation, exit_code, &stdout, &stderr))?;
        if envelope.get("error").is_some() {
            return Err(phase_failure(operation, exit_code, &stdout, &stderr));
        }
        Ok(envelope
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Null))
    }

    /// Provisions an agent user and brokers `filesystem` to it.
    pub async fn provision_isolation_session(
        &self,
        filesystem: &MxcFilesystem,
    ) -> Result<IsolationSessionProvisioned, InvokerError> {
        let result = self
            .run_phase(
                "provision",
                &isolation_session_provision_json(filesystem),
                None,
            )
            .await?;
        let field = |value: Option<&serde_json::Value>, name: &str| {
            value
                .and_then(serde_json::Value::as_str)
                .filter(|text| !text.is_empty())
                .map(ToString::to_string)
                .ok_or_else(|| InvokerError::Phase {
                    operation: "provision",
                    exit_code: 0,
                    message: format!("provision result is missing {name}"),
                })
        };
        let metadata = result.get("metadata");
        Ok(IsolationSessionProvisioned {
            sandbox_id: field(result.get("sandboxId"), "sandboxId")?,
            agent_user_name: field(
                metadata.and_then(|m| m.get("agentUserName")),
                "metadata.agentUserName",
            )?,
            agent_user_sid: field(
                metadata.and_then(|m| m.get("agentUserSid")),
                "metadata.agentUserSid",
            )?,
        })
    }

    pub async fn start_isolation_session(&self, sandbox_id: &str) -> Result<(), InvokerError> {
        let config = serde_json::json!({ "version": MXC_ISOLATION_SESSION_SCHEMA_VERSION });
        self.run_phase("start", &config, Some(sandbox_id))
            .await
            .map(|_| ())
    }

    pub async fn stop_isolation_session(&self, sandbox_id: &str) -> Result<(), InvokerError> {
        let config = serde_json::json!({ "version": MXC_ISOLATION_SESSION_SCHEMA_VERSION });
        self.run_phase("stop", &config, Some(sandbox_id))
            .await
            .map(|_| ())
    }

    pub async fn deprovision_isolation_session(
        &self,
        sandbox_id: &str,
    ) -> Result<(), InvokerError> {
        let config = serde_json::json!({ "version": MXC_ISOLATION_SESSION_SCHEMA_VERSION });
        self.run_phase("deprovision", &config, Some(sandbox_id))
            .await
            .map(|_| ())
    }

    /// Starts `process` inside a started isolation session. The returned
    /// `wxc-exec` child relays the in-session process's output and exit code.
    pub fn spawn_isolation_session_exec(
        &self,
        sandbox_id: &str,
        process: &MxcProcess,
    ) -> Result<tokio::process::Child, InvokerError> {
        if self.mock {
            return Err(InvokerError::Mock("exec"));
        }
        let json = serde_json::to_string(&isolation_session_exec_json(process))?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
        let mut cmd = self.real_command();
        cmd.stdin(std::process::Stdio::null())
            .arg("--config-base64")
            .arg(&b64)
            .arg("--operation")
            .arg("exec")
            .arg("--container-id")
            .arg(sandbox_id);
        if self.debug {
            cmd.arg("--debug");
        }
        info!(sandbox_id, "wxc-exec isolation_session exec spawn");
        Ok(cmd.spawn()?)
    }
}

// ── Tests (pure serde — compile and run cross-platform) ──────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "windows")]
    #[tokio::test]
    #[allow(unsafe_code)] // Native synchronization handle verifies cancellation.
    async fn real_launcher_command_terminates_on_drop() {
        use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
        };

        // Exercise the real launcher's command construction with a native,
        // long-lived process. This is not an MXC enforcement test or mock E2E.
        let powershell = PathBuf::from(std::env::var("SystemRoot").unwrap())
            .join("System32/WindowsPowerShell/v1.0/powershell.exe");
        let invoker = WxcExecInvoker::new(powershell, false);
        let child = invoker
            .real_command()
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Sleep -Seconds 60",
            ])
            .spawn()
            .expect("launch long-lived PowerShell process");
        // SAFETY: OpenProcess supplies a synchronization-only handle for the
        // child, retained through termination and closed exactly once below.
        unsafe {
            let handle = OpenProcess(PROCESS_SYNCHRONIZE, false, child.id().unwrap())
                .expect("open child synchronization handle");
            assert_eq!(WaitForSingleObject(handle, 0), WAIT_TIMEOUT);
            drop(child);
            let exited = WaitForSingleObject(handle, 5_000);
            CloseHandle(handle).expect("close child handle");
            assert_eq!(exited, WAIT_OBJECT_0, "cancelled launcher must terminate");
        }
    }

    #[test]
    fn isolation_session_provision_uses_the_brokered_filesystem_contract() {
        let config = isolation_session_provision_json(&MxcFilesystem {
            readwrite_paths: vec!["C:\\Users\\a\\work".into()],
            readonly_paths: vec!["C:\\Users\\a\\docs".into()],
            denied_paths: Vec::new(),
            enumerate_paths: vec!["C:\\Users\\a".into()],
        });
        assert_eq!(config["version"], MXC_ISOLATION_SESSION_SCHEMA_VERSION);
        assert_eq!(config["containment"], "isolation_session");
        assert_eq!(
            config["filesystem"]["readwritePaths"][0],
            "C:\\Users\\a\\work"
        );
        assert_eq!(
            config["filesystem"]["readonlyPaths"][0],
            "C:\\Users\\a\\docs"
        );
        assert!(config["filesystem"].get("deniedPaths").is_none());
        assert_eq!(config["filesystem"]["enumeratePaths"][0], "C:\\Users\\a");
        assert_eq!(config["network"]["egress"]["default"], "allow");
        assert_eq!(config["network"]["ingress"]["hostLoopback"], "allow");
        assert!(config.get("phase").is_none());
        assert!(config.get("ui").is_none());
    }

    #[test]
    fn isolation_session_exec_overlays_env_on_the_agent_default() {
        let mut process = MxcProcess {
            command_line: "C:\\Windows\\System32\\cmd.exe /c exit 0".into(),
            cwd: "C:\\Users\\a\\work".into(),
            env: Vec::new(),
            timeout: 0,
        };
        let config = isolation_session_exec_json(&process);
        assert!(config["process"].get("env").is_none());
        assert!(config["process"].get("inheritDefaultEnv").is_none());
        process.env = vec!["A=1".into()];
        let config = isolation_session_exec_json(&process);
        assert_eq!(config["process"]["env"][0], "A=1");
        assert_eq!(config["process"]["inheritDefaultEnv"], true);
    }

    #[test]
    fn phase_failure_prefers_the_mxc_error_envelope() {
        let error = phase_failure(
            "provision",
            1,
            r#"{"error":{"code":"policy_validation","message":"bad path"}}"#,
            "noise",
        );
        assert!(error.to_string().contains("policy_validation: bad path"));
        let error = phase_failure("start", 2, "", "stderr text");
        assert!(error.to_string().contains("stderr text"));
    }

    #[test]
    fn oneshot_processcontainer_config_json_shape() {
        // Mirror the JSON `run_oneshot` builds for the one-shot processContainer
        // path: no `phase` (routes to one-shot), `containment: processcontainer`,
        // a `process` block, the `processContainer` knobs, and filesystem grants
        // incl. deniedPaths.
        let config = serde_json::json!({
            "version": MXC_SCHEMA_VERSION,
            "containerId": "sb-1",
            "containment": "processcontainer",
            "process": {
                "commandLine": "C:\\work\\demo\\agent.exe",
                "cwd": "C:\\work\\demo",
                "env": Vec::<String>::new(),
                "timeout": 0,
            },
            "processContainer": { "leastPrivilege": true },
            "filesystem": {
                "readwritePaths": ["C:\\work\\demo"],
                "deniedPaths": ["C:\\secret"],
            },
        });
        assert_eq!(config["containment"], "processcontainer");
        assert!(
            config.get("phase").is_none(),
            "one-shot config must omit phase"
        );
        assert_eq!(config["processContainer"]["leastPrivilege"], true);
        assert_eq!(config["filesystem"]["readwritePaths"][0], "C:\\work\\demo");
        assert_eq!(config["filesystem"]["deniedPaths"][0], "C:\\secret");
    }

    #[test]
    fn network_json_emits_directional_format() {
        // MXC 1.0.0: egress/ingress replaces the legacy
        // defaultPolicy / allowedHosts / proxy.localhost shape.
        let network = MxcNetwork {
            egress_default: "deny".into(),
            proxy: Some("127.0.0.1:18080".parse().unwrap()),
            allow_local_network: false,
        };
        let value = network_json(&network);
        // Loopback-allow mode: egress.default="deny" with 127.0.0.1/32 allow rule.
        // Allows the sandbox to reach its authenticated host-side listeners
        // without enabling direct Internet access.
        assert_eq!(value["egress"]["default"], "deny");
        assert_eq!(value["egress"]["allow"][0]["to"][0]["cidr"], "127.0.0.1/32");
        // ingress.hostLoopback="allow" grants networkLoopback PSEC capability.
        assert_eq!(value["ingress"]["default"], "allow");
        assert_eq!(value["ingress"]["hostLoopback"], "allow");
        assert!(value.get("proxy").is_none());
        assert!(value.get("defaultPolicy").is_none());
    }

    #[test]
    fn oneshot_config_json_omits_network_without_proxy() {
        let filesystem = MxcFilesystem {
            readwrite_paths: vec!["C:\\work\\demo".into()],
            readonly_paths: Vec::new(),
            denied_paths: Vec::new(),
            enumerate_paths: Vec::new(),
        };
        let pc = MxcProcessContainer::default();
        let process = MxcProcess {
            command_line: "cmd /c exit 0".into(),
            cwd: "C:\\work\\demo".into(),
            env: Vec::new(),
            timeout: 0,
        };
        let config = oneshot_config_json("sb-1", &filesystem, &pc, &process, None, None);

        assert!(config.get("network").is_none());
        assert!(config.get("ui").is_none());
    }

    #[test]
    fn oneshot_config_json_emits_typed_ui_policy() {
        let filesystem = MxcFilesystem::default();
        let pc = MxcProcessContainer::default();
        let process = MxcProcess {
            command_line: "cmd /c exit 0".into(),
            cwd: "C:\\work\\demo".into(),
            env: Vec::new(),
            timeout: 0,
        };
        let ui = MxcUi {
            disable: false,
            clipboard: MxcClipboardAccess::Write,
            injection: true,
        };
        let config = oneshot_config_json("sb-ui", &filesystem, &pc, &process, None, Some(&ui));

        assert_eq!(config["ui"]["disable"], false);
        assert_eq!(config["ui"]["clipboard"], "write");
        assert_eq!(config["ui"]["injection"], true);
    }
}
