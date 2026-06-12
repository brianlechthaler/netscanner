use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostStatus {
    Up,
    Down,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredHost {
    pub ip: IpAddr,
    pub status: HostStatus,
    pub open_ports: Vec<u16>,
    pub latency_ms: Option<u64>,
}

impl DiscoveredHost {
    pub fn new(
        ip: IpAddr,
        status: HostStatus,
        open_ports: Vec<u16>,
        latency_ms: Option<u64>,
    ) -> Self {
        Self {
            ip,
            status,
            open_ports,
            latency_ms,
        }
    }

    pub fn is_up(&self) -> bool {
        self.status == HostStatus::Up
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn discovered_host_is_up() {
        let host = DiscoveredHost::new(
            IpAddr::from_str("192.168.1.1").unwrap(),
            HostStatus::Up,
            vec![80, 443],
            Some(12),
        );
        assert!(host.is_up());
        assert_eq!(host.open_ports, vec![80, 443]);
        assert_eq!(host.latency_ms, Some(12));
    }

    #[test]
    fn discovered_host_is_down() {
        let host = DiscoveredHost::new(
            IpAddr::from_str("192.168.1.2").unwrap(),
            HostStatus::Down,
            vec![],
            None,
        );
        assert!(!host.is_up());
    }

    #[test]
    fn host_status_serializes_lowercase() {
        let json = serde_json::to_string(&HostStatus::Up).unwrap();
        assert_eq!(json, "\"up\"");
    }

    #[test]
    fn discovered_host_roundtrip_json() {
        let host = DiscoveredHost::new(
            IpAddr::from_str("10.0.0.5").unwrap(),
            HostStatus::Up,
            vec![22],
            Some(5),
        );
        let json = serde_json::to_string(&host).unwrap();
        let parsed: DiscoveredHost = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, host);
    }
}
