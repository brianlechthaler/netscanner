use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use netscanner_core::{
    active_hosts, DiscoveredHost, HostChecker, ScanEngine, ScanKind, ScanSummary,
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    Idle,
    Running,
    Completed,
    Failed,
}

impl Default for ScanStatus {
    fn default() -> Self {
        Self::Idle
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanRecord {
    pub id: Uuid,
    pub kind: ScanKindDto,
    pub target: String,
    pub status: ScanStatus,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub error: Option<String>,
    pub hosts_found: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ScanKindDto {
    Local,
    External,
}

impl From<ScanKind> for ScanKindDto {
    fn from(value: ScanKind) -> Self {
        match value {
            ScanKind::Local => Self::Local,
            ScanKind::External => Self::External,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostsResponse {
    pub hosts: Vec<DiscoveredHost>,
    pub last_scan: Option<ScanRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusResponse {
    pub status: ScanStatus,
    pub current_scan: Option<ScanRecord>,
    pub hosts_count: usize,
}

#[derive(Debug, Default)]
struct InnerState {
    hosts: Vec<DiscoveredHost>,
    last_scan: Option<ScanRecord>,
    current_scan: Option<ScanRecord>,
    status: ScanStatus,
}

pub struct AppState<C: HostChecker + 'static> {
    inner: RwLock<InnerState>,
    engine: Arc<ScanEngine<C>>,
}

impl<C: HostChecker + 'static> AppState<C> {
    pub fn new(engine: Arc<ScanEngine<C>>) -> Arc<Self> {
        Arc::new(Self {
            inner: RwLock::new(InnerState::default()),
            engine,
        })
    }

    pub fn engine(&self) -> Arc<ScanEngine<C>> {
        Arc::clone(&self.engine)
    }

    pub async fn hosts_response(&self) -> HostsResponse {
        let inner = self.inner.read().await;
        HostsResponse {
            hosts: inner.hosts.clone(),
            last_scan: inner.last_scan.clone(),
        }
    }

    pub async fn status_response(&self) -> StatusResponse {
        let inner = self.inner.read().await;
        StatusResponse {
            status: inner.status.clone(),
            current_scan: inner.current_scan.clone(),
            hosts_count: inner.hosts.len(),
        }
    }

    pub async fn begin_scan(&self, kind: ScanKindDto, target: String) -> Result<Uuid, String> {
        let mut inner = self.inner.write().await;
        if inner.status == ScanStatus::Running {
            return Err("scan already in progress".into());
        }

        let id = Uuid::new_v4();
        let record = ScanRecord {
            id,
            kind,
            target: target.clone(),
            status: ScanStatus::Running,
            started_at: now_epoch_secs(),
            finished_at: None,
            error: None,
            hosts_found: 0,
        };
        inner.status = ScanStatus::Running;
        inner.current_scan = Some(record);
        Ok(id)
    }

    pub async fn complete_scan(&self, summary: ScanSummary) {
        let mut inner = self.inner.write().await;
        inner.hosts = netscanner_core::merge_hosts(&inner.hosts, &summary.hosts);
        let finished_at = now_epoch_secs();
        if let Some(current) = inner.current_scan.as_mut() {
            current.status = ScanStatus::Completed;
            current.finished_at = Some(finished_at);
            current.hosts_found = active_hosts(&summary.hosts).len();
        }
        inner.last_scan = inner.current_scan.clone();
        inner.current_scan = None;
        inner.status = ScanStatus::Completed;
    }

    pub async fn fail_scan(&self, error: String) {
        let mut inner = self.inner.write().await;
        let finished_at = now_epoch_secs();
        if let Some(current) = inner.current_scan.as_mut() {
            current.status = ScanStatus::Failed;
            current.finished_at = Some(finished_at);
            current.error = Some(error);
        }
        inner.last_scan = inner.current_scan.clone();
        inner.current_scan = None;
        inner.status = ScanStatus::Failed;
    }

    pub async fn set_hosts(&self, hosts: Vec<DiscoveredHost>) {
        let mut inner = self.inner.write().await;
        inner.hosts = hosts;
    }
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use netscanner_core::{HostStatus, MockHostChecker, ScanConfig, ScanEngine};
    use std::net::IpAddr;
    use std::str::FromStr;

    fn test_state() -> Arc<AppState<MockHostChecker>> {
        let checker = Arc::new(MockHostChecker::new());
        let engine = Arc::new(ScanEngine::new(checker, ScanConfig::default()));
        AppState::new(engine)
    }

    #[tokio::test]
    async fn begin_scan_sets_running() {
        let state = test_state();
        let id = state
            .begin_scan(ScanKindDto::Local, "192.168.1.0/24".into())
            .await
            .unwrap();
        let status = state.status_response().await;
        assert_eq!(status.status, ScanStatus::Running);
        assert_eq!(status.current_scan.unwrap().id, id);
    }

    #[tokio::test]
    async fn begin_scan_rejects_when_running() {
        let state = test_state();
        state
            .begin_scan(ScanKindDto::Local, "192.168.1.0/24".into())
            .await
            .unwrap();
        let err = state
            .begin_scan(ScanKindDto::External, "8.8.8.8".into())
            .await
            .unwrap_err();
        assert_eq!(err, "scan already in progress");
    }

    #[tokio::test]
    async fn complete_scan_updates_hosts() {
        let state = test_state();
        state
            .begin_scan(ScanKindDto::External, "1.1.1.1".into())
            .await
            .unwrap();
        let host = DiscoveredHost::new(
            IpAddr::from_str("1.1.1.1").unwrap(),
            HostStatus::Up,
            vec![443],
            Some(10),
        );
        let summary = ScanSummary {
            kind: ScanKind::External,
            target: "1.1.1.1".into(),
            hosts: vec![host.clone()],
            duration_ms: 50,
        };
        state.complete_scan(summary).await;
        let resp = state.hosts_response().await;
        assert_eq!(resp.hosts.len(), 1);
        assert_eq!(resp.hosts[0], host);
        assert_eq!(state.status_response().await.status, ScanStatus::Completed);
    }

    #[tokio::test]
    async fn fail_scan_sets_failed_status() {
        let state = test_state();
        state
            .begin_scan(ScanKindDto::Local, "bad".into())
            .await
            .unwrap();
        state.fail_scan("invalid target".into()).await;
        let status = state.status_response().await;
        assert_eq!(status.status, ScanStatus::Failed);
        let last = state.hosts_response().await.last_scan.unwrap();
        assert_eq!(last.error, Some("invalid target".into()));
    }

    #[tokio::test]
    async fn engine_accessor_returns_shared_engine() {
        let state = test_state();
        let engine = state.engine();
        assert_eq!(Arc::strong_count(&engine), 2);
    }

    #[test]
    fn scan_kind_from_core() {
        assert_eq!(ScanKindDto::from(ScanKind::Local), ScanKindDto::Local);
        assert_eq!(ScanKindDto::from(ScanKind::External), ScanKindDto::External);
    }

    #[tokio::test]
    async fn complete_scan_merges_existing_hosts() {
        let state = test_state();
        let ip = IpAddr::from_str("10.0.0.2").unwrap();
        state
            .set_hosts(vec![DiscoveredHost::new(
                ip,
                HostStatus::Down,
                vec![],
                None,
            )])
            .await;
        state
            .begin_scan(ScanKindDto::External, "10.0.0.2".into())
            .await
            .unwrap();
        let summary = ScanSummary {
            kind: ScanKind::External,
            target: "10.0.0.2".into(),
            hosts: vec![DiscoveredHost::new(ip, HostStatus::Up, vec![80], Some(3))],
            duration_ms: 1,
        };
        state.complete_scan(summary).await;
        assert!(state.hosts_response().await.hosts[0].is_up());
    }

    #[tokio::test]
    async fn set_hosts_directly() {
        let state = test_state();
        let host = DiscoveredHost::new(
            IpAddr::from_str("10.0.0.1").unwrap(),
            HostStatus::Up,
            vec![22],
            None,
        );
        state.set_hosts(vec![host.clone()]).await;
        assert_eq!(state.hosts_response().await.hosts, vec![host]);
    }

    #[tokio::test]
    async fn tcp_checker_state_roundtrip() {
        use netscanner_core::TcpHostChecker;
        let checker = Arc::new(TcpHostChecker::new(std::time::Duration::from_millis(200)));
        let engine = Arc::new(ScanEngine::new(checker, ScanConfig::default()));
        let state = AppState::new(engine);
        state
            .begin_scan(ScanKindDto::External, "127.0.0.1".into())
            .await
            .unwrap();
        let summary = state
            .engine()
            .scan_target("127.0.0.1", ScanKind::External)
            .await
            .unwrap();
        state.complete_scan(summary).await;
        assert_eq!(state.status_response().await.status, ScanStatus::Completed);
    }
}
