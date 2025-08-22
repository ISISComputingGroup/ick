use log::error;
use std::process::ExitCode;

fn main() -> ExitCode {
    match ick::run() {
        Ok(_) => ExitCode::SUCCESS,
        Err(s) => {
            error!("{s}");
            ExitCode::FAILURE
        }
    }
}
