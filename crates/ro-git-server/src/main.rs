use std::env;
use std::process;

use ro_git_server::{run_worker_stdio, GitServiceHandler, ServerConfig};

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
    let _service = GitServiceHandler::new(config).into_server();
}
