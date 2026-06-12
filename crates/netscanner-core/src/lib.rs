//! Core network scanning library for netscanner.

pub mod error;
pub mod host;
pub mod network;
pub mod scan;
pub mod scanner;

pub use error::{ScanError, ScanResult};
pub use host::{DiscoveredHost, HostStatus};
pub use network::{expand_target, local_subnet_candidates};
pub use scan::{
    active_hosts, merge_hosts, pick_local_subnet, InterfaceProvider, ScanConfig, ScanEngine,
    ScanKind, ScanProgress, ScanSummary, SystemInterfaceProvider,
};
pub use scanner::{HostChecker, MockHostChecker, TcpHostChecker};
