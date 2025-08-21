use clap::{Args, Parser, Subcommand};
use fei::{add_creds, remove_creds, run_ssh_command};
use std::process::ExitCode;

#[derive(Debug, Args)]
struct GlobalOpts {
    #[clap(
        long = "instruments",
        short = 'i',
        value_delimiter = ',',
        global = true,
        help = "A comma separated list of machines to apply this command to."
    )]
    instruments: Vec<String>,

    #[clap(
        long = "admin",
        short = 'a',
        global = true,
        action,
        help = "Use admin credentials when adding credentials or executing commands"
    )]
    admin: bool,
}

#[derive(Parser, Debug)]
#[command(about)]
struct App {
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

    /// Execute a command, using SSH
    Ssh {
        /// The command to execute. If the command contains spaces,
        /// wrap the entire command in quotes
        command: String,

        /// Expected exit status of the remote command. If not specified,
        /// the exit status of the remote command will not be checked.
        #[clap(long = "expected-exit-code", short = 'e')]
        expected_exit_code: Option<i32>,
    },

    Login { },

    Logout { },
}

fn main() -> ExitCode {
    let args = App::parse();

    let result = match args.command {
        Commands::AddCreds {} => add_creds(&args.global_opts.instruments),
        Commands::RemoveCreds {} => remove_creds(&args.global_opts.instruments),
        Commands::Ssh {
            command,
            expected_exit_code,
        } => run_ssh_command(&args.global_opts.instruments, &command, expected_exit_code),
        Commands::Login {  } => { Ok(())},
        Commands::Logout {  } => { Ok(())},
    };

    match result {
        Ok(_) => ExitCode::SUCCESS,
        Err(s) => {
            eprintln!("Error: {s}");
            ExitCode::FAILURE
        }
    }
}
