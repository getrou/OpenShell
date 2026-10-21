// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Measured Windows process containment identity; never an authored profile name.

use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    GetLengthSid, GetTokenInformation, IsValidSid, TOKEN_APPCONTAINER_INFORMATION, TOKEN_ELEVATION,
    TOKEN_QUERY, TOKEN_USER, TokenAppContainerSid, TokenElevation, TokenIsAppContainer, TokenUser,
};
use windows::Win32::System::Threading::{
    GetCurrentProcessId, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

struct OwnedHandle(HANDLE);

#[allow(unsafe_code)]
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this guard owns a real handle acquired by a successful Win32
        // call, and closes it exactly once. It never wraps pseudo handles.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

#[allow(unsafe_code)]
pub fn current_appcontainer_sid() -> Result<String, String> {
    // SAFETY: GetCurrentProcessId has no pointer or lifetime preconditions.
    process_appcontainer_sid(unsafe { GetCurrentProcessId() })
}

#[allow(unsafe_code)]
fn process_appcontainer_sid(process_id: u32) -> Result<String, String> {
    // SAFETY: owned handles are closed by guards on every exit path. Query
    // buffers are correctly sized/aligned and remain alive while SID pointers
    // are used. The SID extent is checked before conversion.
    unsafe {
        let process = OwnedHandle(
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id)
                .map_err(|error| format!("open MXC process identity: {error}"))?,
        );
        let mut token = HANDLE::default();
        OpenProcessToken(process.0, TOKEN_QUERY, &raw mut token)
            .map_err(|error| format!("open MXC process token: {error}"))?;
        let token = OwnedHandle(token);
        let mut contained = 0_u32;
        let mut returned = 0_u32;
        GetTokenInformation(
            token.0,
            TokenIsAppContainer,
            Some(std::ptr::from_mut(&mut contained).cast()),
            4,
            &raw mut returned,
        )
        .map_err(|error| format!("query MXC AppContainer token: {error}"))?;
        if returned != 4 || contained != 1 {
            return Err("MXC boundary process is not an AppContainer".to_string());
        }

        // A SID has at most 15 subauthorities. This aligned buffer is larger
        // than TOKEN_APPCONTAINER_INFORMATION plus the largest Windows SID.
        let mut buffer = [0_usize; 32];
        let length = u32::try_from(size_of_val(&buffer)).expect("fixed token buffer fits u32");
        GetTokenInformation(
            token.0,
            TokenAppContainerSid,
            Some(buffer.as_mut_ptr().cast()),
            length,
            &raw mut returned,
        )
        .map_err(|error| format!("query MXC AppContainer SID: {error}"))?;
        if returned < u32::try_from(size_of::<TOKEN_APPCONTAINER_INFORMATION>()).unwrap()
            || returned > length
        {
            return Err("MXC AppContainer SID buffer length is invalid".to_string());
        }
        let info = &*buffer.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>();
        let start = buffer.as_ptr() as usize;
        let end = start + returned as usize;
        let sid = info.TokenAppContainer.0 as usize;
        // Check the fixed SID header before reading its subauthority count.
        if sid < start || sid > end.saturating_sub(8) {
            return Err("MXC AppContainer SID pointer is invalid".to_string());
        }
        let count = *info.TokenAppContainer.0.cast::<u8>().add(1);
        let sid_length = 8 + usize::from(count) * 4;
        if count > 15
            || sid_length > end - sid
            || !IsValidSid(info.TokenAppContainer).as_bool()
            || GetLengthSid(info.TokenAppContainer) as usize != sid_length
        {
            return Err("MXC AppContainer SID is invalid".to_string());
        }
        let mut text = windows::core::PWSTR::null();
        ConvertSidToStringSidW(info.TokenAppContainer, &raw mut text)
            .map_err(|error| format!("format MXC AppContainer SID: {error}"))?;
        let result = text.to_string();
        let _ = LocalFree(Some(HLOCAL(text.0.cast())));
        let sid = result.map_err(|error| format!("decode MXC AppContainer SID: {error}"))?;
        if !sid.starts_with("S-1-15-2-") {
            return Err("MXC token SID is not an AppContainer identity".to_string());
        }
        Ok(sid)
    }
}

/// The measured user identity of the current process token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserIdentity {
    pub user_sid: String,
    pub elevated: bool,
    pub appcontainer: bool,
}

/// Measures the current process token's user SID, elevation, and whether it is
/// an `AppContainer` token. Used for isolation sessions, whose boundary runs as
/// a separate agent user rather than inside an `AppContainer`.
#[allow(unsafe_code)]
pub fn current_user_identity() -> Result<UserIdentity, String> {
    // SAFETY: as in `process_appcontainer_sid`: owned handles are closed by
    // guards, query buffers are sized and aligned for the requested classes and
    // outlive every SID pointer, and the SID extent is validated before use.
    unsafe {
        let process = OwnedHandle(
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                GetCurrentProcessId(),
            )
            .map_err(|error| format!("open MXC process identity: {error}"))?,
        );
        let mut token = HANDLE::default();
        OpenProcessToken(process.0, TOKEN_QUERY, &raw mut token)
            .map_err(|error| format!("open MXC process token: {error}"))?;
        let token = OwnedHandle(token);

        let mut buffer = [0_usize; 32];
        let length = u32::try_from(size_of_val(&buffer)).expect("fixed token buffer fits u32");
        let mut returned = 0_u32;
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            length,
            &raw mut returned,
        )
        .map_err(|error| format!("query MXC token user: {error}"))?;
        if returned < u32::try_from(size_of::<TOKEN_USER>()).unwrap() || returned > length {
            return Err("MXC token user buffer length is invalid".to_string());
        }
        let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
        let start = buffer.as_ptr() as usize;
        let end = start + returned as usize;
        let sid = user.User.Sid.0 as usize;
        if sid < start || sid > end.saturating_sub(8) {
            return Err("MXC token user SID pointer is invalid".to_string());
        }
        let count = *user.User.Sid.0.cast::<u8>().add(1);
        let sid_length = 8 + usize::from(count) * 4;
        if count > 15
            || sid_length > end - sid
            || !IsValidSid(user.User.Sid).as_bool()
            || GetLengthSid(user.User.Sid) as usize != sid_length
        {
            return Err("MXC token user SID is invalid".to_string());
        }
        let mut text = windows::core::PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &raw mut text)
            .map_err(|error| format!("format MXC token user SID: {error}"))?;
        let result = text.to_string();
        let _ = LocalFree(Some(HLOCAL(text.0.cast())));
        let user_sid = result.map_err(|error| format!("decode MXC token user SID: {error}"))?;

        let mut elevation = TOKEN_ELEVATION::default();
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some(std::ptr::from_mut(&mut elevation).cast()),
            u32::try_from(size_of::<TOKEN_ELEVATION>()).unwrap(),
            &raw mut returned,
        )
        .map_err(|error| format!("query MXC token elevation: {error}"))?;

        let mut contained = 0_u32;
        GetTokenInformation(
            token.0,
            TokenIsAppContainer,
            Some(std::ptr::from_mut(&mut contained).cast()),
            4,
            &raw mut returned,
        )
        .map_err(|error| format!("query MXC AppContainer token: {error}"))?;

        Ok(UserIdentity {
            user_sid,
            elevated: elevation.TokenIsElevated != 0,
            appcontainer: contained == 1,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measures_the_current_user_identity() {
        let identity = current_user_identity().expect("host process identity is measurable");
        assert!(identity.user_sid.starts_with("S-1-"), "{identity:?}");
        assert!(!identity.appcontainer);
    }

    #[test]
    fn rejects_uncontained_host_process_identity() {
        assert!(current_appcontainer_sid().is_err());
    }

    #[test]
    fn rejects_invalid_process_identity() {
        assert!(process_appcontainer_sid(0).is_err());
    }

    #[test]
    #[ignore = "requires execution inside a real native MXC ProcessContainer"]
    fn measures_native_appcontainer_identity() {
        let sid = current_appcontainer_sid().expect("native AppContainer SID must be measurable");
        assert!(sid.starts_with("S-1-15-2-"));
    }

    #[test]
    #[ignore = "requires native MXC with all host loopback and egress denied"]
    fn native_same_container_loopback() {
        if std::env::var_os("OPENSHELL_MXC_LOOPBACK_CHILD").is_none() {
            use base64::Engine as _;
            let directory = tempfile::tempdir().unwrap();
            let executable = directory.path().join("native-loopback-test.exe");
            std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
            let system_root = std::env::var("SYSTEMROOT").unwrap();
            let request = serde_json::json!({
                "version": "1.0.0", "containerId": "openshell-native-loopback-test",
                "containment": "processcontainer",
                "process": {
                    "commandLine": format!("\"{}\" --exact identity::tests::native_same_container_loopback --ignored --nocapture", executable.display()),
                    "cwd": directory.path(), "timeout": 60000,
                    "env": [format!("SYSTEMROOT={system_root}"), format!("WINDIR={system_root}"),
                        format!("LOCALAPPDATA={}", directory.path().display()), "OPENSHELL_MXC_LOOPBACK_CHILD=1".to_string()]
                },
                "filesystem": { "readwritePaths": [directory.path()] },
                "network": { "egress": { "default": "deny" },
                    "ingress": { "default": "deny", "hostLoopback": "deny" } }
            });
            let encoded = base64::engine::general_purpose::STANDARD
                .encode(serde_json::to_vec(&request).unwrap());
            let wxc = std::env::var("OPENSHELL_WXC_EXEC_PATH")
                .unwrap_or_else(|_| "C:/Tools/MXC/wxc-exec.exe".into());
            let output = std::process::Command::new(wxc)
                .args(["--config-base64", &encoded])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "native MXC loopback failed: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("1 passed"),
                "child test must execute"
            );
            return;
        }
        current_appcontainer_sid().expect("child must run inside native MXC");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client =
            std::net::TcpStream::connect_timeout(&address, std::time::Duration::from_secs(3))
                .expect("same-container loopback must work without host-loopback permission");
        let (_server, _) = listener.accept().unwrap();
        drop(client);
    }
}
