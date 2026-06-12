use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::services::port_info;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostStatus {
    Up,
    Down,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenPort {
    pub port: u16,
    pub service: String,
    pub description: String,
}

impl OpenPort {
    pub fn from_port(port: u16) -> Self {
        port_info(port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredHost {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub status: HostStatus,
    pub open_ports: Vec<OpenPort>,
    pub latency_ms: Option<u64>,
}

impl DiscoveredHost {
    pub fn new(
        ip: IpAddr,
        status: HostStatus,
        open_ports: Vec<OpenPort>,
        latency_ms: Option<u64>,
    ) -> Self {
        Self {
            ip,
            hostname: None,
            os: None,
            status,
            open_ports,
            latency_ms,
        }
    }

    pub fn with_details(
        ip: IpAddr,
        hostname: Option<String>,
        os: Option<String>,
        status: HostStatus,
        open_ports: Vec<OpenPort>,
        latency_ms: Option<u64>,
    ) -> Self {
        Self {
            ip,
            hostname,
            os,
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
            vec![OpenPort::from_port(80), OpenPort::from_port(443)],
            Some(12),
        );
        assert!(host.is_up());
        assert_eq!(host.open_ports.len(), 2);
        assert_eq!(host.open_ports[0].port, 80);
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
        let host = DiscoveredHost::with_details(
            IpAddr::from_str("10.0.0.5").unwrap(),
            Some("router.local".into()),
            Some("Linux / Unix / macOS (TTL 64)".into()),
            HostStatus::Up,
            vec![OpenPort::from_port(22)],
            Some(5),
        );
        let json = serde_json::to_string(&host).unwrap();
        let parsed: DiscoveredHost = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, host);
    }
}
