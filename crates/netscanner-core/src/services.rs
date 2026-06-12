//! Well-known port to service name and description mappings.

use crate::host::OpenPort;

/// Returns service metadata for a port number.
pub fn port_info(port: u16) -> OpenPort {
    let (service, description) = match port {
        20 => ("ftp-data", "FTP data transfer"),
        21 => ("ftp", "File Transfer Protocol"),
        22 => ("ssh", "Secure Shell remote login"),
        23 => ("telnet", "Unencrypted remote login"),
        25 => ("smtp", "Simple Mail Transfer Protocol"),
        53 => ("dns", "Domain Name System"),
        67 => ("dhcp", "DHCP server"),
        68 => ("dhcp", "DHCP client"),
        69 => ("tftp", "Trivial File Transfer Protocol"),
        80 => ("http", "Hypertext Transfer Protocol (web)"),
        110 => ("pop3", "Post Office Protocol v3"),
        123 => ("ntp", "Network Time Protocol"),
        143 => ("imap", "Internet Message Access Protocol"),
        161 => ("snmp", "Simple Network Management Protocol"),
        389 => ("ldap", "Lightweight Directory Access Protocol"),
        443 => ("https", "HTTP over TLS/SSL (secure web)"),
        445 => ("smb", "Microsoft SMB file sharing"),
        465 => ("smtps", "SMTP over TLS"),
        587 => ("submission", "Mail submission agent"),
        636 => ("ldaps", "LDAP over TLS"),
        993 => ("imaps", "IMAP over TLS"),
        995 => ("pop3s", "POP3 over TLS"),
        1433 => ("mssql", "Microsoft SQL Server"),
        1521 => ("oracle", "Oracle database listener"),
        3306 => ("mysql", "MySQL/MariaDB database"),
        3389 => ("rdp", "Remote Desktop Protocol"),
        5432 => ("postgresql", "PostgreSQL database"),
        5900 => ("vnc", "Virtual Network Computing"),
        6379 => ("redis", "Redis in-memory data store"),
        8080 => ("http-alt", "Alternative HTTP (proxy or dev server)"),
        8443 => ("https-alt", "Alternative HTTPS (proxy or dev server)"),
        27017 => ("mongodb", "MongoDB database"),
        _ => ("unknown", "Unrecognized service"),
    };
    OpenPort {
        port,
        service: service.into(),
        description: description.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_ports_have_descriptions() {
        let ssh = port_info(22);
        assert_eq!(ssh.service, "ssh");
        assert!(ssh.description.contains("Shell"));

        let https = port_info(443);
        assert_eq!(https.service, "https");
    }

    #[test]
    fn unknown_port_is_labeled() {
        let info = port_info(9999);
        assert_eq!(info.service, "unknown");
    }
}
