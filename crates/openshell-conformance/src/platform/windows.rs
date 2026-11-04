// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs;

use super::{CommandExpectation, SandboxFixture, SmokeFixture};

pub fn smoke_fixture() -> Result<SmokeFixture, String> {
    let (temp_dir, workload_dir, create_args) = writable_fixture("smoke")?;
    let ready_path = workload_dir.join("ready.txt");
    let command = vec![
        r"C:\Windows\System32\cmd.exe".to_string(),
        "/c".to_string(),
        format!("echo ready > \"{}\" & set /p idle=", ready_path.display()),
    ];
    Ok(SmokeFixture::new(
        create_args,
        Some(command),
        Some(temp_dir),
    ))
}

pub fn marker_command(marker: &str) -> CommandExpectation {
    CommandExpectation::new(
        vec![
            r"C:\Windows\System32\cmd.exe".to_string(),
            "/c".to_string(),
            format!("echo {marker}"),
        ],
        format!("{marker}\r\n"),
    )
}

pub fn lifecycle_fixture() -> Result<SandboxFixture, String> {
    let (temp_dir, workload_dir, create_args) = writable_fixture("lifecycle")?;
    Ok(SandboxFixture::new(
        workload_dir.to_string_lossy().into_owned(),
        create_args,
        Some(temp_dir),
    ))
}

pub fn file_transfer_fixture() -> Result<SandboxFixture, String> {
    let (temp_dir, workload_dir, create_args) = writable_fixture("file-transfer")?;
    Ok(SandboxFixture::new(
        workload_dir.to_string_lossy().into_owned(),
        create_args,
        Some(temp_dir),
    ))
}

pub fn policy_fixture() -> Result<SandboxFixture, String> {
    let (temp_dir, workload_dir, create_args) = writable_fixture("policy")?;
    Ok(SandboxFixture::new(
        workload_dir.to_string_lossy().into_owned(),
        create_args,
        Some(temp_dir),
    ))
}

pub fn restricted_network_policy_fixture() -> Result<SandboxFixture, String> {
    let (temp_dir, workload_dir, create_args) = writable_fixture_with_network("policy", true)?;
    Ok(SandboxFixture::new(
        workload_dir.to_string_lossy().into_owned(),
        create_args,
        Some(temp_dir),
    ))
}

pub fn keep_alive(fixture: &SandboxFixture) -> Vec<String> {
    vec![
        r"C:\Windows\System32\cmd.exe".to_string(),
        "/c".to_string(),
        format!(
            "echo ready > \"{}\" & set /p idle=",
            fixture.path("ready.txt")
        ),
    ]
}

pub fn increment_then_wait(path: &str) -> Vec<String> {
    vec![
        r"C:\Windows\System32\cmd.exe".to_string(),
        "/v:on".to_string(),
        "/c".to_string(),
        format!(
            "set count=0 & (if exist \"{path}\" set /p count=<\"{path}\") & \
             set /a count+=1 > NUL & >\"{path}\" echo !count!& \
             set /p idle="
        ),
    ]
}

pub fn write_text(path: &str, value: &str) -> CommandExpectation {
    CommandExpectation::new(
        vec![
            r"C:\Windows\System32\cmd.exe".to_string(),
            "/c".to_string(),
            format!(">\"{path}\" echo {value}"),
        ],
        String::new(),
    )
}

pub fn read_text(path: &str, value: &str) -> CommandExpectation {
    CommandExpectation::new(
        vec![
            r"C:\Windows\System32\cmd.exe".to_string(),
            "/c".to_string(),
            format!("type \"{path}\""),
        ],
        format!("{value}\r\n"),
    )
}

fn writable_fixture(
    name: &str,
) -> Result<(tempfile::TempDir, std::path::PathBuf, Vec<String>), String> {
    writable_fixture_with_network(name, false)
}

fn writable_fixture_with_network(
    name: &str,
    empty_network_policy: bool,
) -> Result<(tempfile::TempDir, std::path::PathBuf, Vec<String>), String> {
    let temp_dir = tempfile::Builder::new()
        .prefix(&format!("openshell-conformance-{name}-"))
        .tempdir()
        .map_err(|error| format!("create Windows {name} fixture directory: {error}"))?;
    let workload_dir = temp_dir.path().join("workload");
    fs::create_dir(&workload_dir)
        .map_err(|error| format!("create Windows {name} workload directory: {error}"))?;

    let workload_policy_path = workload_dir
        .to_str()
        .ok_or_else(|| format!("Windows {name} workload path is not valid Unicode"))?
        .replace('\\', "/")
        .replace('"', "\\\"");
    let policy_path = temp_dir.path().join("policy.yaml");
    let network_policy = if empty_network_policy {
        "network_policies: {}\n"
    } else {
        ""
    };
    let policy = format!(
        "version: 1\nfilesystem_policy:\n  include_workdir: false\n  read_only: []\n  read_write:\n    - \"{workload_policy_path}\"\n{network_policy}"
    );
    fs::write(&policy_path, policy)
        .map_err(|error| format!("write Windows {name} policy: {error}"))?;
    let create_args = vec![
        "--policy".to_string(),
        policy_path.to_string_lossy().into_owned(),
    ];
    Ok((temp_dir, workload_dir, create_args))
}

const CURL: &str = r"C:\Windows\System32\curl.exe";

/// Print the canonical path of the client that network-policy probes run as.
///
/// curl ships at a fixed System32 path, so the probe confirms it exists there
/// rather than searching PATH; `where.exe` prints nothing inside an AppContainer.
pub fn probe_binary_command() -> Vec<String> {
    vec![
        r"C:\Windows\System32\cmd.exe".to_string(),
        "/c".to_string(),
        format!("if exist \"{CURL}\" echo {CURL}"),
    ]
}

/// Whether `path` is the canonical probe client path the proxy attributes.
pub fn is_probe_binary(path: &str) -> bool {
    let bytes = path.as_bytes();
    let absolute =
        (bytes.len() > 2 && bytes[1] == b':' && bytes[2] == b'\\') || path.starts_with(r"\\");
    absolute
        && !path.contains('\n')
        && path
            .rsplit('\\')
            .next()
            .is_some_and(|name| name.eq_ignore_ascii_case("curl.exe"))
}

/// Print the raw HTTP response for one request to the sandbox-local policy API.
///
/// Windows has no `/dev/tcp`, so the request goes through the sandbox's
/// `http_proxy`, which is where policy.local is served.
pub fn policy_local_request(method: &str, path: &str, body: &str) -> Vec<String> {
    let mut argv = vec![
        CURL.to_string(),
        "--silent".to_string(),
        "--include".to_string(),
        "--max-time".to_string(),
        "30".to_string(),
        "--request".to_string(),
        method.to_string(),
        "--header".to_string(),
        "Content-Type: application/json".to_string(),
    ];
    if !body.is_empty() {
        argv.push("--data-binary".to_string());
        argv.push(body.to_string());
    }
    argv.push(format!("http://policy.local{path}"));
    argv
}

/// Open one TCP connection to `host:port`, printing `DENIED` when policy refuses
/// it and `UNEXPECTED_ALLOWED` (exit 1) when it connects.
///
/// `--proxytunnel` makes curl issue a CONNECT for every scheme, so the proxy
/// sees an L4 open just as transparent interception does on Linux.
pub fn denied_tcp_open(host: &str, port: u16) -> Vec<String> {
    let url = if port == 443 {
        format!("https://{host}/")
    } else {
        format!("http://{host}:{port}/")
    };
    vec![
        r"C:\Windows\System32\cmd.exe".to_string(),
        "/c".to_string(),
        format!(
            "curl.exe --silent --proxytunnel --output NUL --max-time 20 {url} & \
             if errorlevel 1 (echo DENIED) else (echo UNEXPECTED_ALLOWED& exit 1)"
        ),
    ]
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_fixture_defines_a_long_running_windows_workload() {
        let fixture = smoke_fixture().unwrap();
        let command = fixture.command().unwrap();
        assert_eq!(command[0], r"C:\Windows\System32\cmd.exe");
        assert!(command[2].contains("ready.txt"));
        assert!(command[2].contains("set /p idle="));

        let policy_path = &fixture.create_args()[1];
        let policy = fs::read_to_string(policy_path).unwrap();
        assert!(policy.contains("read_write:"));
        assert!(
            command[2].contains(
                std::path::Path::new(policy_path)
                    .parent()
                    .unwrap()
                    .join("workload")
                    .to_string_lossy()
                    .as_ref()
            )
        );
    }

    #[test]
    fn lifecycle_commands_use_windows_tools_and_policy() {
        let fixture = lifecycle_fixture().unwrap();
        let path = fixture.path("sentinel.txt");
        assert!(
            std::path::Path::new(&path)
                .ends_with(std::path::Path::new("workload").join("sentinel.txt"))
        );
        assert_eq!(keep_alive(&fixture)[0], r"C:\Windows\System32\cmd.exe");
        assert_eq!(marker_command("marker").expected_stdout(), "marker\r\n");
        assert_eq!(write_text(&path, "value").expected_stdout(), "");
        assert_eq!(read_text(&path, "value").expected_stdout(), "value\r\n");
        assert!(increment_then_wait(&path)[3].contains("!count!"));
        assert!(
            fs::read_to_string(&fixture.create_args()[1])
                .unwrap()
                .contains("read_write:")
        );
    }

    #[test]
    fn policy_fixtures_use_windows_paths_and_explicit_network_restrictions() {
        let fixture = policy_fixture().unwrap();
        let policy = fs::read_to_string(&fixture.create_args()[1]).unwrap();
        assert!(!policy.contains("network_policies:"));
        assert!(!policy.contains("/sandbox"));
        assert_eq!(keep_alive(&fixture)[0], r"C:\Windows\System32\cmd.exe");

        let restricted_fixture = restricted_network_policy_fixture().unwrap();
        let restricted_policy = fs::read_to_string(&restricted_fixture.create_args()[1]).unwrap();
        assert!(restricted_policy.contains("network_policies: {}"));
    }

    #[test]
    fn file_transfer_fixture_provides_a_writable_windows_workspace() {
        let fixture = file_transfer_fixture().unwrap();
        let remote = fixture.path("payload.txt");
        assert!(std::path::Path::new(&remote).ends_with("payload.txt"));
        assert!(
            fs::read_to_string(&fixture.create_args()[1])
                .unwrap()
                .contains("read_write:")
        );
    }

    #[test]
    fn probe_binary_matches_windows_curl_paths() {
        assert!(is_probe_binary(r"C:\Windows\System32\curl.exe"));
        assert!(is_probe_binary(r"c:\windows\system32\CURL.EXE"));
        assert!(!is_probe_binary("curl.exe"));
        assert!(!is_probe_binary(r"C:\Windows\System32\cmd.exe"));
        assert!(!is_probe_binary("/usr/bin/bash"));
    }

    #[test]
    fn network_probes_use_curl_through_the_proxy() {
        let request = policy_local_request("POST", "/v1/proposals", "{\"a\":1}");
        assert_eq!(request[0], CURL);
        assert_eq!(request.last().unwrap(), "http://policy.local/v1/proposals");
        assert!(
            request
                .windows(2)
                .any(|pair| pair[0] == "--data-binary" && pair[1] == "{\"a\":1}")
        );
        assert!(
            !policy_local_request("GET", "/v1/policy/current", "")
                .contains(&"--data-binary".to_string())
        );
        assert!(denied_tcp_open("1.1.1.1", 443)[2].contains("--proxytunnel"));
        assert!(denied_tcp_open("1.1.1.1", 443)[2].contains("https://1.1.1.1/"));
        assert!(denied_tcp_open("pypi.org", 80)[2].contains("http://pypi.org:80/"));
    }
}
