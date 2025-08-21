mod cmdkey;
mod credentials;
mod ssh;

pub fn add_creds(instruments: &[String]) -> anyhow::Result<()> {
    credentials::get_credentials(instruments, false)
        .iter()
        .try_for_each(cmdkey::add_cmdkey_cred)
}

pub fn remove_creds(instruments: &[String]) -> anyhow::Result<()> {
    instruments
        .iter()
        .try_for_each(|inst| cmdkey::remove_cmdkey_cred(inst))
}

pub fn run_ssh_command(
    instruments: &[String],
    command: &str,
    expected_exit_code: Option<i32>,
) -> anyhow::Result<()> {
    credentials::get_credentials(instruments, false)
        .iter()
        .try_for_each(|cred| ssh::run_ssh_command(cred, command, expected_exit_code))
}
