#![forbid(unsafe_code)]

use std::env;
use std::process;

use ro_git_server::{run_server, run_worker_stdio, ServerConfig};

fn main() {
    let mut args = env::args();
    let _bin = args.next();
    if args.next().as_deref() == Some("git-worker") {
        if let Err(err) = run_worker_stdio() {
            eprintln!("git-worker error: {err}");
            process::exit(1);
        }
        return;
    }

    let config = ServerConfig::from_env();
    if let Err(err) = run_server(config) {
        eprintln!("ro-git-server error: {err}");
        process::exit(1);
    }
}

