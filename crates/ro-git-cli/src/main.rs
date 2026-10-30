#![forbid(unsafe_code)]

use std::io;
use std::process::ExitCode;

use ro_git_cli::{run_with_env, CliEnv};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let env = CliEnv::from_process();
    let mut stdout = io::stdout().lock();
    if let Err(err) = run_with_env(args, &env, &mut stdout) {
        eprintln!("ro-git-cli: {err}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
