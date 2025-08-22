use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand};
use clap_verbosity_flag::InfoLevel;
use log::{debug, trace};

mod cmdkey;
mod credentials;
mod ssh;

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
        help = "Use admin credentials when adding credentials or executing commands. 
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

    /// Execute a command over SSH
    Ssh {
        /// The command to execute. If the command contains spaces,
        /// wrap the entire command in quotes
        command: String,

        /// Expected exit status of the remote command. If not specified,
        /// the exit status of the remote command will not be checked.
        #[clap(long = "expected-exit-code", short = 'e')]
        expected_exit_code: Option<i32>,
    },
}

fn add_cmdkey_creds(instruments: &[String], admin: bool) -> anyhow::Result<()> {
    if instruments.is_empty() {
        bail!("No instruments specified");
    }
    credentials::get_credentials(instruments, admin, None)?
        .iter()
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

fn run_ssh_command(
    instruments: &[String],
    command: &str,
    expected_exit_code: Option<i32>,
    admin: bool,
) -> anyhow::Result<()> {
    if instruments.is_empty() {
        bail!("No instruments specified");
    }
    credentials::get_credentials(instruments, admin, None)?
        .iter()
        .try_for_each(|cred| ssh::run_ssh_command(cred, command, expected_exit_code))
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
        Commands::Ssh {
            command,
            expected_exit_code,
        } => run_ssh_command(
            &machines,
            &command,
            expected_exit_code,
            args.global_opts.admin,
        ),
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
