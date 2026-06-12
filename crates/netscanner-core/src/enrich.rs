//! Host enrichment: reverse DNS, OS hints, and banner probing.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Reverse DNS lookup with a timeout. Returns `None` on failure or timeout.
pub async fn lookup_hostname(ip: IpAddr, lookup_timeout: Duration) -> Option<String> {
    let result = timeout(lookup_timeout, tokio::task::spawn_blocking(move || {
        dns_lookup::lookup_addr(&ip).ok()
    }))
    .await
    .ok()?
    .ok()??;

    let hostname = result.trim().to_string();
    if hostname.is_empty() || hostname == ip.to_string() {
        None
    } else {
        Some(hostname)
    }
}

/// Best-effort OS guess from ping TTL and service banners on open ports.
pub async fn probe_os(ip: IpAddr, open_ports: &[u16], probe_timeout: Duration) -> Option<String> {
    if let Some(ttl_os) = guess_os_from_ttl(ip, probe_timeout).await {
        return Some(ttl_os);
    }

    if open_ports.contains(&22) {
        if let Some(banner) = read_tcp_banner(ip, 22, probe_timeout).await {
            if let Some(os) = os_from_ssh_banner(&banner) {
                return Some(os);
            }
        }
    }

    for &port in &[80u16, 8080] {
        if open_ports.contains(&port) {
            if let Some(banner) = read_http_server(ip, port, probe_timeout).await {
                return Some(banner);
            }
        }
    }

    None
}

async fn guess_os_from_ttl(ip: IpAddr, probe_timeout: Duration) -> Option<String> {
    let ip_str = ip.to_string();

    let output = timeout(
        probe_timeout + Duration::from_millis(200),
        tokio::task::spawn_blocking(move || {
            #[cfg(unix)]
            {
                std::process::Command::new("ping")
                    .args(["-c", "1", "-W", "1", &ip_str])
                    .output()
                    .ok()
            }
            #[cfg(not(unix))]
            {
                let timeout_ms = probe_timeout.as_millis().max(500) as u64;
                std::process::Command::new("ping")
                    .args(["-n", "1", "-w", &timeout_ms.to_string(), &ip_str])
                    .output()
                    .ok()
            }
        }),
    )
    .await
    .ok()?
    .ok()??;

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_ttl_os(&stdout)
}

fn parse_ttl_os(output: &str) -> Option<String> {
    let lower = output.to_lowercase();
    let ttl = lower
        .split_whitespace()
        .find_map(|token| token.strip_prefix("ttl="))?
        .trim_end_matches(',')
        .parse::<u8>()
        .ok()?;

    let guess = match ttl {
        0..=64 => "Linux / Unix / macOS",
        65..=128 => "Windows",
        129..=255 => "Network device / router",
    };

    Some(format!("{guess} (TTL {ttl})"))
}

async fn read_tcp_banner(ip: IpAddr, port: u16, probe_timeout: Duration) -> Option<String> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = timeout(probe_timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let mut buf = vec![0u8; 512];
    let n = timeout(probe_timeout, stream.read(&mut buf)).await.ok()?.ok()?;
    if n == 0 {
        return None;
    }

    let text = String::from_utf8_lossy(&buf[..n]).trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

fn os_from_ssh_banner(banner: &str) -> Option<String> {
    // e.g. SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
    let comment = banner.split_whitespace().nth(1)?;
    let distro_token = comment.split('-').next()?.to_lowercase();

    let label = match distro_token.as_str() {
        s if s.contains("ubuntu") => "Ubuntu Linux",
        s if s.contains("debian") => "Debian Linux",
        s if s.contains("centos") => "CentOS Linux",
        s if s.contains("fedora") => "Fedora Linux",
        s if s.contains("rhel") || s.contains("redhat") => "Red Hat Linux",
        s if s.contains("darwin") || s.contains("macos") => "macOS",
        s if s.contains("freebsd") => "FreeBSD",
        s if s.contains("windows") => "Windows",
        _ => return Some(format!("SSH ({comment})")),
    };

    Some(format!("{label} (SSH banner)"))
}

async fn read_http_server(ip: IpAddr, port: u16, probe_timeout: Duration) -> Option<String> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = timeout(probe_timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let request = "GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    timeout(probe_timeout, stream.write_all(request.as_bytes()))
        .await
        .ok()?
        .ok()?;

    let mut buf = vec![0u8; 1024];
    let n = timeout(probe_timeout, stream.read(&mut buf)).await.ok()?.ok()?;
    if n == 0 {
        return None;
    }

    let response = String::from_utf8_lossy(&buf[..n]);
    response
        .lines()
        .find(|line| line.to_lowercase().starts_with("server:"))
        .map(|line| {
            let server = line.split_once(':').map(|(_, v)| v.trim()).unwrap_or(line);
            format!("HTTP server: {server}")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ttl_os_linux() {
        let sample = "64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=1.2 ms";
        let os = parse_ttl_os(sample).unwrap();
        assert!(os.contains("Linux"));
        assert!(os.contains("64"));
    }

    #[test]
    fn parse_ttl_os_windows() {
        let sample = "Reply from 10.0.0.1: bytes=32 time=1ms TTL=128";
        let os = parse_ttl_os(sample).unwrap();
        assert!(os.contains("Windows"));
    }

    #[test]
    fn ssh_banner_extracts_ubuntu() {
        let banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6";
        let os = os_from_ssh_banner(banner).unwrap();
        assert!(os.contains("Ubuntu"));
    }

    #[test]
    fn ssh_banner_extracts_debian() {
        let banner = "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2";
        let os = os_from_ssh_banner(banner).unwrap();
        assert!(os.contains("Debian"));
    }
}
