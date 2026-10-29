use ro_git_server::{GitServiceHandler, ServerConfig};

fn main() {
    let config = ServerConfig::from_env();
    let _service = GitServiceHandler::new(config).into_server();
}
