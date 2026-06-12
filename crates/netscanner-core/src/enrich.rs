//! Host enrichment: reverse DNS, OS hints, and banner probing.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Reverse DNS lookup with a timeout. Returns `None` on failure or timeout.
pub async fn lookup_hostname(ip: IpAddr, lookup_timeout: Duration) -> Option<String> {
    let result = timeout(
        lookup_timeout,
        tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip).ok()),
    )
    .await
    .ok()?
    .ok()??;

    normalize_hostname(ip, &result)
}

fn normalize_hostname(ip: IpAddr, raw: &str) -> Option<String> {
    let hostname = raw.trim().to_string();
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

    probe_os_from_banners(ip, open_ports, probe_timeout).await
}

async fn probe_os_from_banners(
    ip: IpAddr,
    open_ports: &[u16],
    probe_timeout: Duration,
) -> Option<String> {
    if open_ports.contains(&22) {
        if let Some(os) = read_tcp_banner(ip, 22, probe_timeout)
            .await
            .and_then(|banner| os_from_ssh_banner(&banner))
        {
            return Some(os);
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

pub(crate) async fn guess_os_from_ttl(ip: IpAddr, probe_timeout: Duration) -> Option<String> {
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
    let n = timeout(probe_timeout, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    if n == 0 {
        return None;
    }

    let text = String::from_utf8_lossy(&buf[..n]).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
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
    let n = timeout(probe_timeout, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
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
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[test]
    fn normalize_hostname_rejects_ip_echo() {
        let ip = IpAddr::from_str("10.0.0.1").unwrap();
        assert_eq!(normalize_hostname(ip, "10.0.0.1"), None);
        assert_eq!(normalize_hostname(ip, "  "), None);
        assert_eq!(
            normalize_hostname(ip, "router.local"),
            Some("router.local".into())
        );
    }

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

    #[test]
    fn parse_ttl_os_network_device() {
        let sample = "64 bytes from 10.0.0.1: icmp_seq=1 ttl=200 time=1.2 ms";
        let os = parse_ttl_os(sample).unwrap();
        assert!(os.contains("Network device"));
        assert!(os.contains("200"));
    }

    #[test]
    fn ssh_banner_extracts_other_distros() {
        let cases = [
            ("SSH-2.0-OpenSSH_7.4 CentOS-7", "CentOS"),
            ("SSH-2.0-OpenSSH_8.0 Fedora-33", "Fedora"),
            ("SSH-2.0-OpenSSH_8.0 RHEL-8", "Red Hat"),
            ("SSH-2.0-OpenSSH_8.0 Darwin-21.0", "macOS"),
            ("SSH-2.0-OpenSSH_8.0 FreeBSD-13", "FreeBSD"),
            ("SSH-2.0-OpenSSH_8.0 Windows-10", "Windows"),
        ];
        for (banner, expected) in cases {
            let os = os_from_ssh_banner(banner).unwrap();
            assert!(os.contains(expected), "banner: {banner}");
        }
    }

    #[test]
    fn ssh_banner_generic_fallback() {
        let banner = "SSH-2.0-OpenSSH_8.0 CustomThing";
        let os = os_from_ssh_banner(banner).unwrap();
        assert_eq!(os, "SSH (CustomThing)");
    }

    #[tokio::test]
    async fn read_tcp_banner_reads_ssh_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream
                .write_all(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
                .await
                .unwrap();
        });

        let banner = read_tcp_banner(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert!(banner.contains("SSH-2.0"));
    }

    #[tokio::test]
    async fn read_tcp_banner_whitespace_only_returns_none() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"   \r\n").await.unwrap();
        });

        assert!(read_tcp_banner(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            Duration::from_secs(2)
        )
        .await
        .is_none());
    }

    #[tokio::test]
    async fn read_http_server_parses_server_header() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream
                .write_all(b"HTTP/1.0 200 OK\r\nServer: test-nginx\r\n\r\n")
                .await
                .unwrap();
        });

        let server = read_http_server(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(server, "HTTP server: test-nginx");
    }

    #[tokio::test]
    async fn read_http_server_empty_response_returns_none() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
        });

        assert!(read_http_server(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            Duration::from_secs(2)
        )
        .await
        .is_none());
    }

    #[tokio::test]
    async fn guess_os_from_ttl_localhost() {
        let os = guess_os_from_ttl(IpAddr::V4(Ipv4Addr::LOCALHOST), Duration::from_secs(2)).await;
        assert!(os.unwrap().contains("TTL"));
    }

    #[tokio::test]
    async fn probe_os_from_banners_uses_ssh_and_http() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let timeout = Duration::from_secs(2);

        {
            let listener = TcpListener::bind("127.0.0.1:22").await.unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                stream.write_all(b"SSH-2.0\r\n").await.unwrap();
            });
            assert!(probe_os_from_banners(ip, &[22], timeout).await.is_none());
            server.await.unwrap();
        }

        tokio::time::sleep(Duration::from_millis(50)).await;

        {
            let listener = TcpListener::bind("127.0.0.1:22").await.unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                stream
                    .write_all(b"SSH-2.0-OpenSSH_8.0 Fedora-33\r\n")
                    .await
                    .unwrap();
            });
            let ssh_os = probe_os_from_banners(ip, &[22], timeout).await.unwrap();
            assert!(ssh_os.contains("Fedora"));
            server.await.unwrap();
        }

        {
            let listener = TcpListener::bind("127.0.0.1:80").await.unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                stream
                    .write_all(b"HTTP/1.0 200 OK\r\nServer: probe-test\r\n\r\n")
                    .await
                    .unwrap();
            });
            let http_os = probe_os_from_banners(ip, &[80], timeout).await.unwrap();
            assert!(http_os.contains("probe-test"));
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn lookup_hostname_returns_none_on_timeout() {
        let result = lookup_hostname(
            IpAddr::from_str("192.0.2.1").unwrap(),
            Duration::from_nanos(1),
        )
        .await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn lookup_hostname_resolves_localhost() {
        let result = lookup_hostname(IpAddr::V4(Ipv4Addr::LOCALHOST), Duration::from_secs(2)).await;
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn probe_os_returns_ttl_guess() {
        let os = probe_os(IpAddr::V4(Ipv4Addr::LOCALHOST), &[], Duration::from_secs(2)).await;
        assert!(os.unwrap().contains("TTL"));
    }

    #[tokio::test]
    async fn read_tcp_banner_zero_bytes_returns_none() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            drop(stream);
        });

        assert!(read_tcp_banner(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            Duration::from_secs(2)
        )
        .await
        .is_none());
    }

    #[tokio::test]
    async fn read_http_server_zero_bytes_returns_none() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 256];
            let _ = stream.read(&mut buf).await;
            drop(stream);
        });

        assert!(read_http_server(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            Duration::from_secs(2)
        )
        .await
        .is_none());
    }
}
