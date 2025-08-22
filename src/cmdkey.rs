use crate::credentials::Credential;
use anyhow::{Context, anyhow};
use log::{debug, info, trace, warn};
use subprocess::{Exec, ExitStatus, Redirection};

pub fn add_cmdkey_cred(cred: &Credential) -> anyhow::Result<()> {
    info!(
        "Running cmdkey /add:{} /user:{} /pass:[hidden]",
        cred.host, cred.username
    );

    let process_result = Exec::cmd("cmdkey")
        .arg(format!("/add:{}", cred.host))
        .arg(format!("/user:{}", cred.username))
        .arg(format!("/pass:{}", cred.password))
        .stdout(Redirection::Pipe)
        .stderr(Redirection::Merge)
        .capture()
        .with_context(|| "Failed to spawn cmdkey")?;

    debug!("Process returned; {:?}", process_result.exit_status);
    trace!(
        "Process output:\n{}",
        String::from_utf8_lossy(&process_result.stdout)
    );

    match process_result.exit_status {
        ExitStatus::Exited(0) => Ok(()),
        ExitStatus::Exited(errno) => Err(anyhow!("cmdkey /add returned error code {errno}")),
        _ => Err(anyhow!("cmdkey did not exit with a status code")),
    }
}

pub fn remove_cmdkey_cred(domain: &str) -> anyhow::Result<()> {
    info!("Running cmdkey /delete:{}", domain);

    let process_result = Exec::cmd("cmdkey")
        .arg(format!("/delete:{}", domain))
        .stdout(Redirection::Pipe)
        .stderr(Redirection::Merge)
        .capture()
        .with_context(|| "Failed to spawn cmdkey")?;

    debug!("Process returned; {:?}", process_result.exit_status);
    trace!(
        "Process output:\n{}",
        String::from_utf8_lossy(&process_result.stdout)
    );

    match process_result.exit_status {
        // Exits with code 1 if credential doesn't exist, that's fine.
        ExitStatus::Exited(0) => Ok(()),
        ExitStatus::Exited(1) => {
            warn!("cmdkey credential removal on host {domain} failed, probably did not exist");
            Ok(())
        }
        ExitStatus::Exited(errno) => Err(anyhow!("cmdkey /delete returned error code {errno}")),
        _ => Err(anyhow!("cmdkey did not exit with a status code")),
    }
}
