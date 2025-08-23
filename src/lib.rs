//! ick - IBEX-credentials-from-keeper/keepass.
//!
//! ick provides a thin wrapper over the windows credential store, injecting appropriate credentials
//! which are acquired from either keeper or keepass.
//!
//! # Installation
//!
//! Put the binary `ick.exe` in a directory on your `PATH`.
//!
//! `ick` requires environment variables in order to acquire credentials:
//! - `ICK_CRED_STORE`, should be set to either `keeper` or `keepass`, describing the
//!   password-manager backend which `ick` will acquire passwords from. This environment
//!   variable can safely be set permanently.
//! - `ICK_KEEPASS_FILE` (keepass only), a path to a keepass (.kdbx) file containing the passwords.
//!   This environment variable can safely be set permanently.
//! - `ICK_KEEPASS_KEY` (keepass only), the decryption password for the keepass database. **This should
//!   not be set as a permanent environment variable**; it should be manually entered as an env variable
//!   into a specific shell, and should be cleared once administration tasks are complete.
//! - `ICK_KEEPER_TOKEN` (keeper only), a token used to access the keeper API. **This should
//!   not be set as a permanent environment variable**; it should be manually entered as an env variable
//!   into a specific shell, and should be cleared once administration tasks are complete.
//!
//! # Usage
//!
//! For a description of available `ick` commands and flags, use:
//! ```
//! ick help
//! ```
//!
//! For help on a specific subcommand, for example `ick add-creds`, use:
//! ```
//! ick help add-creds
//! ```
//!
//! # Examples:
//!
//! Add user-level credentials for `INST1` and `INST2` to the windows credential store, as an unprivileged user or admin user:
//! ```
//! ick add-creds -i NDXINST1,NDXINST2
//! ick add-creds -i NDXINST1,NDXINST2 --admin
//! ```
//!
//! Remove credentials for `INST1` and `INST2` from the windows credential store:
//! ```
//! ick remove-creds -i NDXINST1,NDXINST2
//! ```

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand};
use clap_verbosity_flag::InfoLevel;
use log::{debug, trace};

mod cmdkey;
mod credentials;

#[derive(Debug, Args)]
struct GlobalOpts {
    #[clap(
        long = "instruments",
        short = 'i',
        value_delimiter = ',',
        global = true,
        help = "A comma separated list of machines to apply this command to.
Conflicts with --instruments-file"
    )]
    instruments: Vec<String>,

    #[clap(
        long = "instruments-file",
        short = 'I',
        global = true,
        help = "Path to a line-delimited text file containing instrument names.
Lines beginning with '#' are ignored as comments.
Conflicts with --instruments",
        conflicts_with = "instruments"
    )]
    instruments_file: Option<String>,

    #[clap(
        long = "admin",
        short = 'a',
        global = true,
        action,
        help = "Use admin credentials when adding credentials. 
Defaults to false (unprivileged user), specify this flag to use privileged credentials."
    )]
    admin: bool,
}

#[derive(Parser, Debug)]
#[command(about)]
struct App {
    #[command(flatten)]
    verbosity: clap_verbosity_flag::Verbosity<InfoLevel>,

    #[clap(flatten)]
    global_opts: GlobalOpts,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Add credentials to the windows credential store
    AddCreds {},

    /// Remove credentials from the windows credential store
    RemoveCreds {},
}

fn add_cmdkey_creds(instruments: &[String], admin: bool) -> anyhow::Result<()> {
    if instruments.is_empty() {
        bail!("No instruments specified");
    }
    credentials::get_credentials(instruments, admin, None)?
        .into_iter()
        .try_for_each(cmdkey::add_cmdkey_cred)
}

fn remove_cmdkey_creds(instruments: &[String]) -> anyhow::Result<()> {
    if instruments.is_empty() {
        bail!("No instruments specified");
    }
    instruments
        .iter()
        .try_for_each(|inst| cmdkey::remove_cmdkey_cred(inst))
}

fn load_instruments_from_file(file_contents: &str) -> Vec<String> {
    file_contents
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with("#"))
        .map(|s| s.to_owned())
        .collect()
}

fn get_machines(args: &App) -> anyhow::Result<Vec<String>> {
    let machines: Vec<String> = if let Some(filename) = &args.global_opts.instruments_file {
        let file_contents = std::fs::read_to_string(filename)
            .with_context(|| format!("Instrument list file at '{filename}' could not be read"))?;
        load_instruments_from_file(&file_contents)
    } else {
        args.global_opts.instruments.clone()
    };

    if machines.is_empty() {
        bail!("No machines specified")
    }
    debug!("Instruments: {:?}", machines);
    Ok(machines)
}

#[doc(hidden)]
pub fn run() -> anyhow::Result<()> {
    let args = App::parse();

    // Setup logging
    env_logger::Builder::new()
        .filter_level(args.verbosity.into())
        .init();

    trace!("Logging started");

    let machines = get_machines(&args)?;

    match args.command {
        Commands::AddCreds {} => add_cmdkey_creds(&machines, args.global_opts.admin),
        Commands::RemoveCreds {} => remove_cmdkey_creds(&machines),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap_verbosity_flag::Verbosity;

    #[test]
    fn test_load_instruments_from_file() {
        let file_contents = "
foo
bar
# comment
    baz
    # another_comment

# another comment after a blank line
";
        assert_eq!(
            load_instruments_from_file(&file_contents),
            vec!["foo".to_owned(), "bar".to_owned(), "baz".to_owned()]
        )
    }

    #[test]
    fn test_get_machines_with_no_provided_instruments() {
        let result = get_machines(&App {
            verbosity: Verbosity::default(),
            global_opts: GlobalOpts {
                instruments: vec![],
                instruments_file: None,
                admin: false,
            },
            command: Commands::RemoveCreds {},
        });

        assert!(result.is_err_and(|e| { e.to_string().contains("No machines specified") }));
    }
}
