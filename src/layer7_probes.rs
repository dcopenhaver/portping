// Layer 7 protocol detection functions
// These are used to probe ambiguous timeout/timeout cases

use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use rustls::ClientConfig;
use tokio_rustls::TlsConnector;
use rustls_pki_types::ServerName;

/// Try TLS handshake - covers HTTPS, LDAPS, IMAPS, SMTPS, etc.
pub async fn try_tls_handshake(dest: &str, port: u16, timeout_ms: u64) -> Option<String> {
    let addr = format!("{}:{}", dest, port);
    let dur = Duration::from_millis(timeout_ms);
    
    // Create a TLS config that accepts invalid certificates (we just want to test connectivity)
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    
    let connector = TlsConnector::from(Arc::new(config));
    
    // Try to connect
    let stream = match timeout(dur, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };
    
    // Try TLS handshake - we need a valid ServerName
    let server_name = match ServerName::try_from(dest.to_string()) {
        Ok(sn) => sn,
        Err(_) => {
            // If dest is IP, use a dummy hostname
            match ServerName::try_from("localhost".to_string()) {
                Ok(sn) => sn,
                Err(_) => return None,
            }
        }
    };
    
    match timeout(dur, connector.connect(server_name, stream)).await {
        Ok(Ok(_)) => Some("TLS".to_string()),
        _ => None,
    }
}

/// Certificate verifier that accepts all certificates (for testing only)
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Try HTTP GET request
pub async fn try_http_request(dest: &str, port: u16, timeout_ms: u64) -> Option<String> {
    let addr = format!("{}:{}", dest, port);
    let dur = Duration::from_millis(timeout_ms);
    
    let mut stream = match timeout(dur, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };
    
    // Send HTTP GET request
    let request = format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", dest);
    
    if timeout(dur, stream.write_all(request.as_bytes())).await.is_err() {
        return None;
    }
    
    // Try to read response
    let mut buf = [0u8; 256];
    match timeout(dur, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            // Check if response looks like HTTP
            let response = String::from_utf8_lossy(&buf[..n]);
            if response.starts_with("HTTP/") {
                Some("HTTP".to_string())
            } else {
                None
            }
        },
        _ => None,
    }
}

/// Try MySQL handshake - MySQL is server-first, so just wait for greeting
pub async fn try_mysql_handshake(dest: &str, port: u16, timeout_ms: u64) -> Option<String> {
    let addr = format!("{}:{}", dest, port);
    let dur = Duration::from_millis(timeout_ms);
    
    let mut stream = match timeout(dur, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };
    
    // MySQL server sends greeting packet immediately
    let mut buf = [0u8; 256];
    match timeout(dur, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 4 => {
            // MySQL greeting starts with packet length (3 bytes) + sequence (1 byte)
            // Followed by protocol version (usually 10 for MySQL 5.x+)
            // Check for protocol version 10 at position 4
            if n > 5 && buf[4] == 10 {
                Some("MySQL".to_string())
            } else {
                None
            }
        },
        _ => None,
    }
}

/// Try PostgreSQL startup message
pub async fn try_postgres_handshake(dest: &str, port: u16, timeout_ms: u64) -> Option<String> {
    let addr = format!("{}:{}", dest, port);
    let dur = Duration::from_millis(timeout_ms);
    
    let mut stream = match timeout(dur, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };
    
    // PostgreSQL startup message (protocol version 3.0)
    // Format: length (4 bytes) + protocol version (4 bytes) + parameters
    let startup_msg = vec![
        0x00, 0x00, 0x00, 0x08,  // Length: 8 bytes
        0x00, 0x03, 0x00, 0x00,  // Protocol version 3.0
    ];
    
    if timeout(dur, stream.write_all(&startup_msg)).await.is_err() {
        return None;
    }
    
    // Try to read response
    let mut buf = [0u8; 256];
    match timeout(dur, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            // PostgreSQL responds with 'R' (authentication request) or 'E' (error)
            if buf[0] == b'R' || buf[0] == b'E' {
                Some("PostgreSQL".to_string())
            } else {
                None
            }
        },
        _ => None,
    }
}

/// Extended probe - aggressive last-resort check with multiple probe strings
/// Sends multiple patterns to trigger response from slow or stubborn services
/// If service closes at any point, proves it's working (just slow)
/// If stays open through all probes, truly ambiguous (receive-only OR dead)
pub async fn try_extended_probe(dest: &str, port: u16, timeout_ms: u64) -> Option<String> {
    let addr = format!("{}:{}", dest, port);
    let connect_dur = Duration::from_millis(timeout_ms);
    
    let mut stream = match timeout(connect_dur, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };
    
    // Probe strings to try - common disconnect commands and generic data
    let probes = [
        b"\r\n" as &[u8],           // Single enter
        b"\r\n\r\n",                 // Double enter (like hitting enter twice)
        b"QUIT\r\n",
        b"EXIT\r\n",
        b"BYE\r\n",
    ];
    
    let pause_duration = Duration::from_millis(200);
    let mut buf = [0u8; 64];
    
    // Send each probe with pauses
    for probe in &probes {
        // Send probe
        if timeout(pause_duration, stream.write_all(probe)).await.is_err() {
            // Write error or timeout
            return None;
        }
        
        // Check if service responded or closed
        match timeout(pause_duration, stream.read(&mut buf)).await {
            Ok(Ok(0)) => {
                // Connection closed - service processed our data and closed
                // This proves it's a working service (just slow/stubborn)
                return Some("Responsive".to_string());
            },
            Ok(Ok(_)) => {
                // Got response - proves working service
                return Some("Responsive".to_string());
            },
            Err(_) => {
                // Timeout - no response yet, try next probe
                continue;
            },
            Ok(Err(_)) => {
                // Read error
                return None;
            }
        }
    }
    
    // Stayed open through all probes with no response
    // Still ambiguous - could be receive-only service OR dead proxy
    None
}

/// Probe all Layer 7 protocols in order, returning first match
pub async fn layer7_probe(dest: &str, port: u16, timeout_ms: u64) -> Option<String> {
    // Try TLS first - covers most modern services
    if let Some(protocol) = try_tls_handshake(dest, port, timeout_ms).await {
        return Some(protocol);
    }
    
    // Try HTTP
    if let Some(protocol) = try_http_request(dest, port, timeout_ms).await {
        return Some(protocol);
    }
    
    // Try MySQL (server-first)
    if let Some(protocol) = try_mysql_handshake(dest, port, timeout_ms).await {
        return Some(protocol);
    }
    
    // Try PostgreSQL
    if let Some(protocol) = try_postgres_handshake(dest, port, timeout_ms).await {
        return Some(protocol);
    }
    
    // Extended probe - last resort aggressive check
    // Sends multiple probe strings to trigger response from slow/stubborn services
    if let Some(protocol) = try_extended_probe(dest, port, timeout_ms).await {
        return Some(protocol);
    }
    
    // No protocol matched - truly ambiguous
    None
}
