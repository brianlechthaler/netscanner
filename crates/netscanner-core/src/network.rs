use std::net::IpAddr;

use ipnetwork::IpNetwork;

use crate::error::{ScanError, ScanResult};

/// Expand a scan target into individual host addresses.
///
/// Accepts a single IP or CIDR notation (e.g. `192.168.1.0/24`).
pub fn expand_target(target: &str) -> ScanResult<Vec<IpAddr>> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return Err(ScanError::invalid_target("target must not be empty"));
    }

    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }

    let network: IpNetwork = trimmed
        .parse()
        .map_err(|_| ScanError::invalid_target(format!("'{trimmed}' is not a valid IP or CIDR")))?;

    if network.prefix() < 16 {
        return Err(ScanError::invalid_target(
            "CIDR prefix must be /16 or larger (max 65536 hosts)",
        ));
    }

    Ok(network.iter().collect())
}

/// Build /24 subnet candidates from local IPv4 addresses (RFC1918 and link-local).
pub fn local_subnet_candidates(interfaces: &[(IpAddr, u8)]) -> Vec<String> {
    let mut subnets = Vec::new();

    for (ip, prefix) in interfaces {
        if let IpAddr::V4(ipv4) = ip {
            if !is_private_or_link_local(*ipv4) {
                continue;
            }
            if *prefix > 24 {
                continue;
            }
            let octets = ipv4.octets();
            let cidr = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
            if !subnets.contains(&cidr) {
                subnets.push(cidr);
            }
        }
    }

    subnets
}

fn is_private_or_link_local(ip: std::net::Ipv4Addr) -> bool {
    ip.is_private() || ip.is_link_local()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[test]
    fn expand_single_ip() {
        let ips = expand_target("192.168.1.10").unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], IpAddr::from_str("192.168.1.10").unwrap());
    }

    #[test]
    fn expand_cidr_slash_30() {
        let ips = expand_target("10.0.0.0/30").unwrap();
        assert_eq!(ips.len(), 4);
    }

    #[test]
    fn expand_rejects_empty() {
        assert_eq!(
            expand_target("").unwrap_err(),
            ScanError::invalid_target("target must not be empty")
        );
    }

    #[test]
    fn expand_rejects_invalid() {
        let err = expand_target("not-an-ip").unwrap_err();
        assert!(matches!(err, ScanError::InvalidTarget(_)));
    }

    #[test]
    fn expand_rejects_large_cidr() {
        let err = expand_target("10.0.0.0/8").unwrap_err();
        assert!(matches!(err, ScanError::InvalidTarget(_)));
    }

    #[test]
    fn local_subnet_candidates_builds_slash_24() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 42));
        let subnets = local_subnet_candidates(&[(ip, 24)]);
        assert_eq!(subnets, vec!["192.168.5.0/24".to_string()]);
    }

    #[test]
    fn local_subnet_candidates_skips_public_ips() {
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let subnets = local_subnet_candidates(&[(ip, 24)]);
        assert!(subnets.is_empty());
    }

    #[test]
    fn local_subnet_candidates_deduplicates() {
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 5));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 99));
        let subnets = local_subnet_candidates(&[(ip1, 24), (ip2, 24)]);
        assert_eq!(subnets.len(), 1);
    }

    #[test]
    fn is_private_or_link_local_accepts_link_local() {
        let ip = Ipv4Addr::new(169, 254, 1, 1);
        assert!(is_private_or_link_local(ip));
    }

    #[test]
    fn local_subnet_skips_narrow_prefix() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let subnets = local_subnet_candidates(&[(ip, 32)]);
        assert!(subnets.is_empty());
    }

    #[test]
    fn local_subnet_skips_ipv6() {
        let ip = IpAddr::from_str("fe80::1").unwrap();
        let subnets = local_subnet_candidates(&[(ip, 64)]);
        assert!(subnets.is_empty());
    }
}
