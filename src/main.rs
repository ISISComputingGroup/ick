use log::{error, trace};
use std::process::ExitCode;

/// Run the main program.
fn main() -> ExitCode {
    match ick::run() {
        Ok(_) => {
            trace!("Exiting successfully");
            ExitCode::SUCCESS
        }
        Err(s) => {
            error!("{s}");
            ExitCode::FAILURE
        }
    }
}
