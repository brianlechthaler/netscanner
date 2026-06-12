use async_trait::async_trait;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;

/// Checks whether a host responds on a given port.
#[async_trait]
pub trait HostChecker: Send + Sync {
    async fn is_reachable(&self, ip: IpAddr, port: u16) -> bool;
}

/// TCP connect-based host checker for production use.
#[derive(Debug, Default, Clone)]
pub struct TcpHostChecker {
    connect_timeout: Duration,
}

impl TcpHostChecker {
    pub fn new(connect_timeout: Duration) -> Self {
        Self { connect_timeout }
    }

    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }
}

#[async_trait]
impl HostChecker for TcpHostChecker {
    async fn is_reachable(&self, ip: IpAddr, port: u16) -> bool {
        let addr = SocketAddr::new(ip, port);
        timeout(self.connect_timeout, TcpStream::connect(addr))
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false)
    }
}

/// Mock checker for deterministic tests.
#[derive(Debug, Default, Clone)]
pub struct MockHostChecker {
    reachable: HashSet<(IpAddr, u16)>,
}

impl MockHostChecker {
    pub fn new() -> Self {
        Self {
            reachable: HashSet::new(),
        }
    }

    pub fn with_reachable(mut self, ip: IpAddr, port: u16) -> Self {
        self.reachable.insert((ip, port));
        self
    }

    pub fn is_marked_reachable(&self, ip: IpAddr, port: u16) -> bool {
        self.reachable.contains(&(ip, port))
    }
}

#[async_trait]
impl HostChecker for MockHostChecker {
    async fn is_reachable(&self, ip: IpAddr, port: u16) -> bool {
        self.reachable.contains(&(ip, port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn mock_checker_respects_marked_hosts() {
        let ip = IpAddr::from_str("127.0.0.1").unwrap();
        let checker = MockHostChecker::new().with_reachable(ip, 8080);
        assert!(checker.is_reachable(ip, 8080).await);
        assert!(!checker.is_reachable(ip, 80).await);
    }

    #[test]
    fn mock_checker_is_marked_reachable() {
        let ip = IpAddr::from_str("10.0.0.1").unwrap();
        let checker = MockHostChecker::new().with_reachable(ip, 443);
        assert!(checker.is_marked_reachable(ip, 443));
        assert!(!checker.is_marked_reachable(ip, 80));
    }

    #[test]
    fn tcp_checker_default_timeout() {
        let checker = TcpHostChecker::new(Duration::from_millis(100));
        assert_eq!(checker.connect_timeout(), Duration::from_millis(100));
    }

    #[tokio::test]
    async fn tcp_checker_unreachable_host() {
        let checker = TcpHostChecker::new(Duration::from_millis(50));
        let ip = IpAddr::from_str("192.0.2.1").unwrap(); // TEST-NET-1, should be unreachable
        assert!(!checker.is_reachable(ip, 65535).await);
    }

    #[tokio::test]
    async fn tcp_checker_detects_open_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        tokio::time::sleep(Duration::from_millis(20)).await;

        let checker = TcpHostChecker::new(Duration::from_millis(500));
        assert!(checker.is_reachable(addr.ip(), addr.port()).await);
        let _ = accept_task.await;
    }
}
