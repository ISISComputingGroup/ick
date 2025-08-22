use crate::credentials::Credential;
use anyhow::{Context, bail};
use log::{debug, info, trace};
use ssh2::Session;
use std::io::Read;
use std::net::TcpStream;

const SSH_TIMEOUT_MS: u32 = 5000;

fn create_session(cred: &Credential) -> anyhow::Result<Session> {
    let tcp = TcpStream::connect(format!("{}:22", cred.host))
        .with_context(|| format!("SSH failed to connect to host {} on port 22", cred.host))?;

    let mut sess = Session::new().with_context(|| "Failed to create session")?;

    sess.set_tcp_stream(tcp);
    sess.set_timeout(SSH_TIMEOUT_MS);
    sess.handshake()
        .with_context(|| format!("SSH handshake failed for host {}", cred.host))?;

    sess.userauth_password(&cred.username, &cred.password)
        .with_context(|| {
            format!(
                "SSH failed to successfully authenticate to host {}",
                cred.host
            )
        })?;

    if !sess.authenticated() {
        bail!("SSH not authenticated to host {}", cred.host)
    }
    Ok(sess)
}

fn exec_cmd(sess: &Session, command: &str) -> anyhow::Result<(i32, String)> {
    let mut channel = sess.channel_session()?;

    channel.exec(command)?;

    let mut remote_output = String::new();
    channel.read_to_string(&mut remote_output)?;

    channel.wait_close()?;

    let exit_code = channel.exit_status()?;

    Ok((exit_code, remote_output))
}

pub fn run_ssh_command(
    cred: &Credential,
    command: &str,
    expected_exit_code: Option<i32>,
) -> anyhow::Result<()> {
    info!(
        "Attempting to run command '{}' on host '{}' using user '{}'",
        command, cred.host, cred.username
    );

    let sess = create_session(cred)?;
    trace!("SSH session created successfully");
    let (exit_code, output) = exec_cmd(&sess, command)?;

    info!("Command exited with status {}", exit_code);
    debug!("Command output:\n{}", output);

    if let Some(expected) = expected_exit_code
        && exit_code != expected
    {
        bail!(
            "Command '{}' on host {} returned unexpected exit code {} (expected {})\nOutput: {}",
            command,
            cred.host,
            exit_code,
            expected,
            output,
        )
    }

    Ok(())
}
