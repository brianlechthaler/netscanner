pub mod app;
pub mod state;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use netscanner_core::{ScanConfig, ScanEngine, TcpHostChecker};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

pub use app::build_app;
use state::AppState;

pub fn default_port() -> u16 {
    std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080)
}

pub async fn run_server_with_shutdown(
    addr: SocketAddr,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("netscanner_server=info".parse()?),
        )
        .try_init();

    let checker = Arc::new(TcpHostChecker::new(Duration::from_millis(500)));
    let engine = Arc::new(ScanEngine::new(
        checker,
        ScanConfig::default().with_concurrency(128),
    ));
    let state = AppState::new(engine);

    let app = build_app(state);
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("netscanner listening on http://{addr}");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}

#[cfg(test)]
mod run_server_tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn restore_port(saved: Option<String>) {
        match saved {
            Some(value) => std::env::set_var("PORT", value),
            None => std::env::remove_var("PORT"),
        }
    }

    #[test]
    fn default_port_resolution() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("PORT", "1234");
        let saved = std::env::var("PORT").ok();
        std::env::remove_var("PORT");
        assert_eq!(default_port(), 8080);
        std::env::set_var("PORT", "9090");
        assert_eq!(default_port(), 9090);
        restore_port(saved);
        assert_eq!(std::env::var("PORT").unwrap(), "1234");
    }

    #[test]
    fn default_port_resolution_without_existing_port() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("PORT");
        let saved = std::env::var("PORT").ok();
        assert_eq!(default_port(), 8080);
        restore_port(saved);
    }

    #[tokio::test]
    async fn run_from_env_invokes_server() {
        let _guard = ENV_LOCK.lock().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        std::env::set_var("PORT", port.to_string());

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let addr = SocketAddr::from(([0, 0, 0, 0], default_port()));
        let handle = tokio::spawn(async move {
            let _ = run_server_with_shutdown(addr, async move {
                let _ = shutdown_rx.await;
            })
            .await;
        });

        tokio::time::sleep(Duration::from_millis(150)).await;
        let _ = shutdown_tx.send(());
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        std::env::remove_var("PORT");
    }

    #[tokio::test]
    async fn run_server_accepts_connections() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let _ = run_server_with_shutdown(addr, async {
                let _ = shutdown_rx.await;
            })
            .await;
        });

        tokio::time::sleep(Duration::from_millis(300)).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /api/health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 256];
        let n = stream.read(&mut buf).await.unwrap();
        let body = String::from_utf8_lossy(&buf[..n]);
        assert!(body.contains("200"));

        shutdown_tx.send(()).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
    }

    #[tokio::test]
    async fn production_server_exposes_all_api_routes() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let _ = run_server_with_shutdown(addr, async move {
                let _ = shutdown_rx.await;
            })
            .await;
        });

        tokio::time::sleep(Duration::from_millis(250)).await;

        let health = TcpStream::connect(addr).await.unwrap();
        drop(health);

        let mut get = TcpStream::connect(addr).await.unwrap();
        get.write_all(b"GET /api/hosts HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 512];
        let _ = get.read(&mut buf).await.unwrap();

        let mut status = TcpStream::connect(addr).await.unwrap();
        status
            .write_all(b"GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let _ = status.read(&mut buf).await.unwrap();

        let mut local = TcpStream::connect(addr).await.unwrap();
        local
            .write_all(
                b"POST /api/scan/local HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
            )
            .await
            .unwrap();
        let _ = local.read(&mut buf).await.unwrap();

        let body = br#"{"target":"127.0.0.1"}"#;
        let request = format!(
            "POST /api/scan/target HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            std::str::from_utf8(body).unwrap()
        );
        let mut target = TcpStream::connect(addr).await.unwrap();
        target.write_all(request.as_bytes()).await.unwrap();
        let _ = target.read(&mut buf).await.unwrap();

        shutdown_tx.send(()).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
    }
}
