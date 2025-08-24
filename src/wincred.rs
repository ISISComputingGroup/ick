use crate::credentials::Credential;
use anyhow::{Context, bail};
use log::{debug, warn};
use windows::{
    Win32::Security::Credentials::{
        CRED_FLAGS, CRED_MAX_CREDENTIAL_BLOB_SIZE, CRED_MAX_DOMAIN_TARGET_NAME_LENGTH,
        CRED_MAX_USERNAME_LENGTH, CRED_PERSIST_ENTERPRISE, CRED_TYPE_DOMAIN_PASSWORD, CREDENTIALW,
        CredDeleteW, CredWriteW,
    },
    core::{PCWSTR, PWSTR},
};

fn to_utf16_null_terminated_buffer(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn to_password_buffer(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|e| e.to_le_bytes()).collect()
}

pub fn add_win_cred(cred: &Credential) -> anyhow::Result<()> {
    debug!(
        "Adding credential for user {} on host {}",
        cred.username(),
        cred.host(),
    );

    let mut host_buff = to_utf16_null_terminated_buffer(cred.host());
    let mut username_buff = to_utf16_null_terminated_buffer(cred.username());
    let mut pass_blob = to_password_buffer(cred.password());

    if host_buff.len() > CRED_MAX_DOMAIN_TARGET_NAME_LENGTH.try_into()? {
        bail!(
            "Cannot add a cred, domain too long on host '{}'",
            cred.host(),
        )
    }

    if username_buff.len() > CRED_MAX_USERNAME_LENGTH.try_into()? {
        bail!(
            "Cannot add cred, username too long on host '{}'",
            cred.host(),
        )
    }

    let pass_blob_size: u32 = pass_blob.len().try_into()?;
    if pass_blob_size > CRED_MAX_CREDENTIAL_BLOB_SIZE {
        bail!(
            "Cannot add a cred, password blob too long on host '{}'",
            cred.host()
        );
    }

    let credential = CREDENTIALW {
        Flags: CRED_FLAGS(0),
        Type: CRED_TYPE_DOMAIN_PASSWORD,
        TargetName: PWSTR(host_buff.as_mut_ptr()),
        Comment: PWSTR::null(),
        LastWritten: Default::default(),
        CredentialBlobSize: pass_blob_size,
        CredentialBlob: pass_blob.as_mut_ptr(),
        Persist: CRED_PERSIST_ENTERPRISE,
        AttributeCount: 0,
        Attributes: std::ptr::null_mut(),
        TargetAlias: PWSTR::null(),
        UserName: PWSTR(username_buff.as_mut_ptr()),
    };

    // SAFETY:
    // Windows API requires unsafe. No safe abstraction (yet) to call this function.
    //
    // - TargetName must be a properly null-terminated vec of u16 (wchar)
    // - UserName must be a properly null-terminated vec of u16 (wchar)
    // - CredentialBlobSize must be consistent with CredentialBlob
    // - All raw pointers must be valid & outlive the function call to the Win API
    // - CredentialBlobSize must be less than CRED_MAX_CREDENTIAL_BLOB_SIZE
    // - HostName length must be <= CRED_MAX_DOMAIN_TARGET_NAME_LENGTH
    // - UserName length must be <= CRED_MAX_USERNAME_LENGTH
    let result = unsafe { CredWriteW(&credential, 0) };

    result.with_context(|| {
        format!(
            "Failed to add credential for user {} on host {}",
            cred.username(),
            cred.host()
        )
    })
}

pub fn remove_win_cred(domain: &str) -> anyhow::Result<()> {
    debug!("Removing credential for host {}", domain);
    let host_buff: Vec<u16> = to_utf16_null_terminated_buffer(domain);

    if host_buff.len() > CRED_MAX_DOMAIN_TARGET_NAME_LENGTH.try_into()? {
        bail!("Cannot add cred, domain too long on host '{}'", domain)
    }

    // SAFETY:
    // Windows API requires unsafe. No safe abstraction (yet) to call this function.
    //
    // - targetname must be a properly null-terminated vec of u16 (wchar)
    // - targetname length must be <= CRED_MAX_DOMAIN_TARGET_NAME_LENGTH
    let result =
        unsafe { CredDeleteW(PCWSTR(host_buff.as_ptr()), CRED_TYPE_DOMAIN_PASSWORD, None) };

    // If the credential didn't exist to be removed, warn but continue
    if let Err(err) = result {
        warn!("Failed to remove credential for host '{}': {}", domain, err);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_utf16_null_terminated_buffer_empty_str() {
        let result = to_utf16_null_terminated_buffer("");
        assert_eq!(result, [0])
    }

    #[test]
    fn test_to_utf16_null_terminated_buffer_ascii() {
        let result = to_utf16_null_terminated_buffer("hello");
        assert_eq!(result, [104, 101, 108, 108, 111, 0])
    }

    #[test]
    fn test_to_utf16_null_terminated_buffer_unicode() {
        let result = to_utf16_null_terminated_buffer("💩");
        // Check UTF-16 encoding at e.g. https://en.wikipedia.org/wiki/Poop_emoji#Encoding
        assert_eq!(result, [0xD83D, 0xDCA9, 0])
    }

    #[test]
    fn test_to_password_buffer_empty() {
        let result = to_password_buffer("");
        let expect: &[u8] = &[];
        assert_eq!(result, expect)
    }

    #[test]
    fn test_to_password_buffer_ascii() {
        let result = to_password_buffer("hello");
        assert_eq!(result, [104, 0, 101, 0, 108, 0, 108, 0, 111, 0])
    }

    #[test]
    fn test_to_password_buffer_unicode() {
        let result = to_password_buffer("hello💩");
        assert_eq!(
            result,
            [
                104, 0, 101, 0, 108, 0, 108, 0, 111, 0, 0x3D, 0xD8, 0xA9, 0xDC
            ]
        )
    }
}
