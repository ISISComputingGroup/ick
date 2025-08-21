use crate::credentials::Credential;
use anyhow::{Context, anyhow};
use subprocess::{Exec, ExitStatus, Redirection};

pub fn add_cmdkey_cred(cred: &Credential) -> anyhow::Result<()> {
    let process_result = Exec::cmd("cmdkey")
        .arg(format!("/add:{}", cred.domain))
        .arg(format!("/user:{}", cred.username))
        .arg(format!("/pass:{}", cred.password))
        .stdout(Redirection::Pipe)
        .stderr(Redirection::Merge)
        .capture()
        .with_context(|| "Failed to spawn cmdkey")?;

    match process_result.exit_status {
        ExitStatus::Exited(0) => Ok(()),
        ExitStatus::Exited(errno) => Err(anyhow!("cmdkey /add returned error code {errno}")),
        _ => Err(anyhow!("cmdkey did not exit with a status code")),
    }
}

pub fn remove_cmdkey_cred(domain: &str) -> anyhow::Result<()> {
    let process_result = Exec::cmd("cmdkey")
        .arg(format!("/delete:{}", domain))
        .stdout(Redirection::Pipe)
        .stderr(Redirection::Merge)
        .capture()
        .with_context(|| "Failed to spawn cmdkey")?;

    match process_result.exit_status {
        // Exits with code 1 if credential doesn't exist, that's fine.
        ExitStatus::Exited(0) | ExitStatus::Exited(1) => Ok(()),
        ExitStatus::Exited(errno) => Err(anyhow!("cmdkey /delete returned error code {errno}")),
        _ => Err(anyhow!("cmdkey did not exit with a status code")),
    }
}
