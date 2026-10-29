#![forbid(unsafe_code)]

use std::env;
use std::process;

use ro_git_server::{run_server, run_worker_stdio, ServerConfig};

fn main() {
    let raw_args: Vec<String> = env::args().skip(1).collect();
    if raw_args.first().map(String::as_str) == Some("git-worker") {
        if let Err(err) = run_worker_stdio() {
            eprintln!("git-worker error: {err}");
            process::exit(1);
        }
        return;
    }

    let config = ServerConfig::from_env().with_cli_args(&raw_args);
    if let Err(err) = run_server(config) {
        eprintln!("ro-git-server error: {err}");
        process::exit(1);
    }
}

