use std::net::SocketAddr;

use netscanner_server::{default_port, run_server_with_shutdown};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = SocketAddr::from(([0, 0, 0, 0], default_port()));
    run_server_with_shutdown(addr, std::future::pending()).await
}
