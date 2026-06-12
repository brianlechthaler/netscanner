use async_trait::async_trait;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::enrich::{lookup_hostname, probe_os};
use crate::error::{ScanError, ScanResult};
use crate::host::{DiscoveredHost, HostStatus, OpenPort};
use crate::network::expand_target;
use crate::scanner::HostChecker;

const DEFAULT_PORTS: &[u16] = &[22, 80, 443, 8080, 8443];
const DEFAULT_TIMEOUT: Duration = Duration::from_millis(500);
const DEFAULT_CONCURRENCY: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanKind {
    Local,
    External,
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub ports: Vec<u16>,
    pub timeout: Duration,
    pub concurrency: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            ports: DEFAULT_PORTS.to_vec(),
            timeout: DEFAULT_TIMEOUT,
            concurrency: DEFAULT_CONCURRENCY,
        }
    }
}

impl ScanConfig {
    pub fn with_ports(mut self, ports: Vec<u16>) -> Self {
        self.ports = ports;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency.max(1);
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanProgress {
    pub total: usize,
    pub completed: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanSummary {
    pub kind: ScanKind,
    pub target: String,
    pub hosts: Vec<DiscoveredHost>,
    pub duration_ms: u64,
}

pub struct ScanEngine<C: HostChecker> {
    checker: Arc<C>,
    config: ScanConfig,
}

impl<C: HostChecker + 'static> ScanEngine<C> {
    pub fn new(checker: Arc<C>, config: ScanConfig) -> Self {
        Self { checker, config }
    }

    pub fn config(&self) -> &ScanConfig {
        &self.config
    }

    pub async fn scan_target(&self, target: &str, kind: ScanKind) -> ScanResult<ScanSummary> {
        let ips = ensure_has_ips(expand_target(target)?)?;

        let started = Instant::now();
        let hosts = self.scan_ips(ips).await?;
        let duration_ms = started.elapsed().as_millis() as u64;

        Ok(ScanSummary {
            kind,
            target: target.trim().to_string(),
            hosts,
            duration_ms,
        })
    }

    pub async fn scan_ips(&self, ips: Vec<IpAddr>) -> ScanResult<Vec<DiscoveredHost>> {
        let semaphore = Arc::new(Semaphore::new(self.config.concurrency));
        let mut handles = Vec::with_capacity(ips.len());

        for ip in ips {
            let checker = Arc::clone(&self.checker);
            let ports = self.config.ports.clone();
            let timeout_dur = self.config.timeout;
            let permit = Arc::clone(&semaphore)
                .acquire_owned()
                .await
                .expect("scan semaphore closed");

            handles.push(tokio::spawn(async move {
                let _permit = permit;
                probe_host(checker.as_ref(), ip, &ports, timeout_dur).await
            }));
        }

        let mut hosts = Vec::new();
        for handle in handles {
            let host = handle.await.expect("scan task panicked");
            hosts.push(host);
        }

        hosts.sort_by_key(|h| h.ip);
        Ok(hosts)
    }
}

fn ensure_has_ips(ips: Vec<IpAddr>) -> ScanResult<Vec<IpAddr>> {
    if ips.is_empty() {
        Err(ScanError::invalid_target("target contains no addresses"))
    } else {
        Ok(ips)
    }
}

async fn probe_host<C: HostChecker>(
    checker: &C,
    ip: IpAddr,
    ports: &[u16],
    timeout_dur: Duration,
) -> DiscoveredHost {
    let started = Instant::now();
    let mut open_ports = Vec::new();

    for &port in ports {
        let reachable = timeout(timeout_dur, checker.is_reachable(ip, port))
            .await
            .unwrap_or(false);
        if reachable {
            open_ports.push(port);
        }
    }

    let latency_ms = if open_ports.is_empty() {
        None
    } else {
        Some(started.elapsed().as_millis() as u64)
    };

    let status = if open_ports.is_empty() {
        HostStatus::Down
    } else {
        HostStatus::Up
    };

    if status == HostStatus::Down {
        return DiscoveredHost::new(ip, status, vec![], latency_ms);
    }

    let enrich_timeout = timeout_dur + timeout_dur;
    let (hostname, os) = tokio::join!(
        lookup_hostname(ip, enrich_timeout),
        probe_os(ip, &open_ports, enrich_timeout),
    );
    let port_details: Vec<OpenPort> = open_ports
        .iter()
        .copied()
        .map(OpenPort::from_port)
        .collect();

    DiscoveredHost::with_details(ip, hostname, os, status, port_details, latency_ms)
}

/// Select the best local subnet from interface list.
pub fn pick_local_subnet(interfaces: &[(IpAddr, u8)]) -> ScanResult<String> {
    let candidates = crate::network::local_subnet_candidates(interfaces);
    candidates
        .into_iter()
        .next()
        .ok_or(ScanError::NoLocalNetwork)
}

/// Collect unique UP hosts from scan results.
pub fn active_hosts(hosts: &[DiscoveredHost]) -> Vec<&DiscoveredHost> {
    hosts.iter().filter(|h| h.is_up()).collect()
}

/// Merge host lists keeping the latest scan result per IP.
pub fn merge_hosts(
    existing: &[DiscoveredHost],
    incoming: &[DiscoveredHost],
) -> Vec<DiscoveredHost> {
    let mut seen: HashSet<IpAddr> = HashSet::new();
    let mut merged = Vec::new();

    for host in incoming.iter().chain(existing.iter()) {
        if seen.insert(host.ip) {
            merged.push(host.clone());
        }
    }

    merged.sort_by_key(|h| h.ip);
    merged
}

#[async_trait]
pub trait InterfaceProvider: Send + Sync {
    fn interfaces(&self) -> Vec<(IpAddr, u8)>;
}

pub struct SystemInterfaceProvider;

impl InterfaceProvider for SystemInterfaceProvider {
    fn interfaces(&self) -> Vec<(IpAddr, u8)> {
        detect_system_interfaces()
    }
}

fn collect_interfaces_from_output(stdout: &str) -> Vec<(IpAddr, u8)> {
    let mut result = Vec::new();
    for line in stdout.lines() {
        if let Some(parsed) = parse_ip_addr_line(line) {
            result.push(parsed);
        }
    }
    result
}

fn detect_system_interfaces() -> Vec<(IpAddr, u8)> {
    let mut result = Vec::new();

    #[cfg(unix)]
    {
        if let Ok(output) = std::process::Command::new("ip")
            .args(["-4", "-o", "addr", "show", "scope", "global"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            result = collect_interfaces_from_output(&stdout);
        }
    }

    result
}

fn parse_ip_addr_line(line: &str) -> Option<(IpAddr, u8)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    let inet_idx = parts.iter().position(|p| *p == "inet")?;
    let cidr = parts.get(inet_idx + 1)?;
    let network: ipnetwork::IpNetwork = cidr.parse().ok()?;
    Some((network.ip(), network.prefix()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::OpenPort;
    use crate::scanner::{MockHostChecker, TcpHostChecker};
    use std::str::FromStr;

    #[test]
    fn scan_config_default() {
        let cfg = ScanConfig::default();
        assert!(!cfg.ports.is_empty());
        assert_eq!(cfg.concurrency, DEFAULT_CONCURRENCY);
    }

    #[test]
    fn scan_config_builders() {
        let cfg = ScanConfig::default()
            .with_ports(vec![80])
            .with_timeout(Duration::from_secs(1))
            .with_concurrency(0);
        assert_eq!(cfg.ports, vec![80]);
        assert_eq!(cfg.timeout, Duration::from_secs(1));
        assert_eq!(cfg.concurrency, 1);
    }

    #[tokio::test]
    async fn scan_target_finds_up_hosts() {
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let checker = Arc::new(MockHostChecker::new().with_reachable(ip, 80));
        let engine = ScanEngine::new(checker, ScanConfig::default().with_concurrency(2));

        let summary = engine
            .scan_target("192.168.1.1", ScanKind::External)
            .await
            .unwrap();

        assert_eq!(summary.kind, ScanKind::External);
        assert_eq!(summary.hosts.len(), 1);
        assert!(summary.hosts[0].is_up());
    }

    #[tokio::test]
    async fn scan_target_marks_down_hosts() {
        let checker = Arc::new(MockHostChecker::new());
        let engine = ScanEngine::new(checker, ScanConfig::default());

        let summary = engine
            .scan_target("192.168.1.2", ScanKind::Local)
            .await
            .unwrap();

        assert!(!summary.hosts[0].is_up());
    }

    #[tokio::test]
    async fn scan_target_rejects_invalid() {
        let checker = Arc::new(MockHostChecker::new());
        let engine = ScanEngine::new(checker, ScanConfig::default());
        assert!(engine.scan_target("", ScanKind::Local).await.is_err());
    }

    #[test]
    fn pick_local_subnet_returns_first() {
        let ip = IpAddr::from_str("192.168.1.5").unwrap();
        let subnet = pick_local_subnet(&[(ip, 24)]).unwrap();
        assert_eq!(subnet, "192.168.1.0/24");
    }

    #[test]
    fn pick_local_subnet_errors_when_empty() {
        assert_eq!(
            pick_local_subnet(&[]).unwrap_err(),
            ScanError::NoLocalNetwork
        );
    }

    #[test]
    fn active_hosts_filters_down() {
        let up = DiscoveredHost::new(
            IpAddr::from_str("1.1.1.1").unwrap(),
            HostStatus::Up,
            vec![OpenPort::from_port(443)],
            None,
        );
        let down = DiscoveredHost::new(
            IpAddr::from_str("1.1.1.2").unwrap(),
            HostStatus::Down,
            vec![],
            None,
        );
        let hosts = [up.clone(), down];
        let active = active_hosts(&hosts);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].ip, up.ip);
    }

    #[test]
    fn merge_hosts_prefers_incoming() {
        let ip = IpAddr::from_str("10.0.0.1").unwrap();
        let old = DiscoveredHost::new(ip, HostStatus::Down, vec![], None);
        let new = DiscoveredHost::new(ip, HostStatus::Up, vec![OpenPort::from_port(80)], Some(1));
        let merged = merge_hosts(&[old], &[new.clone()]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0], new);
    }

    #[test]
    fn parse_ip_addr_line_valid() {
        let line = "2: eth0    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0";
        let parsed = parse_ip_addr_line(line).unwrap();
        assert_eq!(parsed.1, 24);
    }

    #[test]
    fn parse_ip_addr_line_invalid() {
        assert!(parse_ip_addr_line("garbage").is_none());
    }

    struct StaticInterfaces(Vec<(IpAddr, u8)>);

    impl InterfaceProvider for StaticInterfaces {
        fn interfaces(&self) -> Vec<(IpAddr, u8)> {
            self.0.clone()
        }
    }

    #[test]
    fn static_interface_provider() {
        let ip = IpAddr::from_str("172.16.0.1").unwrap();
        let provider = StaticInterfaces(vec![(ip, 24)]);
        assert_eq!(provider.interfaces().len(), 1);
    }

    #[test]
    fn scan_progress_default() {
        let p = ScanProgress::default();
        assert_eq!(p.total, 0);
        assert_eq!(p.completed, 0);
    }

    #[test]
    fn scan_summary_fields() {
        let summary = ScanSummary {
            kind: ScanKind::Local,
            target: "192.168.0.0/24".into(),
            hosts: vec![],
            duration_ms: 100,
        };
        assert_eq!(summary.target, "192.168.0.0/24");
    }

    #[test]
    fn engine_exposes_config() {
        let checker = Arc::new(MockHostChecker::new());
        let cfg = ScanConfig::default().with_concurrency(4);
        let engine = ScanEngine::new(checker, cfg.clone());
        assert_eq!(engine.config().concurrency, 4);
    }

    #[tokio::test]
    async fn scan_cidr_batch() {
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let checker = Arc::new(MockHostChecker::new().with_reachable(ip, 80));
        let engine = ScanEngine::new(checker, ScanConfig::default().with_concurrency(2));
        let summary = engine
            .scan_target("192.168.1.0/30", ScanKind::Local)
            .await
            .unwrap();
        assert_eq!(summary.hosts.len(), 4);
    }

    #[test]
    fn ensure_has_ips_rejects_empty() {
        assert!(ensure_has_ips(vec![]).is_err());
    }

    #[test]
    fn ensure_has_ips_accepts_nonempty() {
        let ip = IpAddr::from_str("1.1.1.1").unwrap();
        assert_eq!(ensure_has_ips(vec![ip]).unwrap(), vec![ip]);
    }

    #[test]
    fn system_interface_provider_runs() {
        let ifaces = SystemInterfaceProvider.interfaces();
        assert!(ifaces.iter().all(|(_, prefix)| *prefix <= 128));
    }

    #[test]
    fn collect_interfaces_from_output_parses_lines() {
        let sample = "2: eth0    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0\n";
        let ifaces = collect_interfaces_from_output(sample);
        assert_eq!(ifaces.len(), 1);
        assert_eq!(ifaces[0].1, 24);
    }

    #[tokio::test]
    async fn tcp_engine_scans_loopback() {
        let checker = Arc::new(TcpHostChecker::new(Duration::from_millis(200)));
        let engine = ScanEngine::new(checker, ScanConfig::default());
        let summary = engine
            .scan_target("127.0.0.1", ScanKind::External)
            .await
            .unwrap();
        assert_eq!(summary.hosts.len(), 1);
    }

    #[test]
    fn merge_hosts_is_used_in_exports() {
        let ip = IpAddr::from_str("192.168.0.1").unwrap();
        let left = vec![DiscoveredHost::new(ip, HostStatus::Down, vec![], None)];
        let right = vec![DiscoveredHost::new(
            ip,
            HostStatus::Up,
            vec![OpenPort::from_port(443)],
            Some(1),
        )];
        let merged = merge_hosts(&left, &right);
        assert_eq!(merged.len(), 1);
        assert!(merged[0].is_up());
    }
}
