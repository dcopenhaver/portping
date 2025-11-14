// Import external crates (libraries) that we'll use
use clap::{Arg, Command};  // For parsing command-line arguments
use tokio::net::TcpStream;  // For TCP network connections (async)
use tokio::time::{timeout, Duration};  // For handling timeouts
use ctable::{Table, Column, Justification};  // For creating formatted tables
use std::net::{IpAddr, ToSocketAddrs};  // For IP address handling
use tokio::io::AsyncReadExt;  // For async I/O operations

// Layer 7 protocol detection module
mod layer7_probes;

/// Parse a string of ports into a vector of port numbers
/// 
/// This function handles three formats:
/// - Single port: "80"
/// - Comma-separated list: "80,443,8080"
/// - Port ranges: "1000-1010" (inclusive)
/// 
/// Returns a Result - Ok(Vec<u16>) on success, Err(String) on failure
fn parse_ports(port_arg: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();  // Create an empty vector to store port numbers
    
    // Split the input by commas to handle multiple ports
    for part in port_arg.split(',') {
        // Check if this part contains a range (has a dash)
        if let Some((start, end)) = part.split_once('-') {
            // Parse the start port number
            let start: u16 = start.trim().parse().map_err(|_| format!("Invalid port: {}", start))?;
            // Parse the end port number
            let end: u16 = end.trim().parse().map_err(|_| format!("Invalid port: {}", end))?;
            
            // Validate that start is not greater than end
            if start > end {
                return Err(format!("Invalid port range: {}-{}", start, end));
            }
            
            // Add all ports in the range (inclusive) to our vector
            ports.extend(start..=end);
        } else {
            // This is a single port, parse it directly
            let port: u16 = part.trim().parse().map_err(|_| format!("Invalid port: {}", part))?;
            ports.push(port);
        }
    }
    Ok(ports)  // Return the vector of ports
}

/// Result of a port check, including potential interception detection
#[derive(Debug)]
struct PortCheckResult {
    status: String,                // "open", "closed", or "filtered"
    peer_addr: Option<IpAddr>,     // Actual IP that responded (if connection succeeded)
    connect_time_ms: Option<u128>, // Connection time in milliseconds
    // Inspection data (only populated when inspect=true)
    ip_matches: Option<bool>,      // Does peer IP match intended destination?
    timing_suspicious: Option<bool>, // Is connection timing suspicious?
    read_bytes: Option<usize>,     // Number of bytes read during read test
    read_result: Option<String>,   // Result of read test: "data", "closed", "timeout", "error"
    write_bytes: Option<usize>,    // Number of bytes read during write test
    write_result: Option<String>,  // Result of write test: "data", "closed", "timeout", "error"
    banner_preview: Option<String>, // First few bytes if data received
    layer7_protocol: Option<String>, // Protocol detected via Layer 7 probing (for ambiguous cases)
}

/// Check if a specific port is open on a destination host
/// 
/// This is an async function that:
/// 1. Attempts to establish a TCP connection
/// 2. Returns "open" if connection succeeds, with the actual peer IP
/// 3. Returns "closed" if connection is refused
/// 4. Returns "filtered" if connection times out
/// 5. Optionally detects if the responder differs from the intended destination
async fn check_port(dest: &str, port: u16, timeout_ms: u64, inspect: bool) -> PortCheckResult {
    // Construct the full address (host:port)
    let addr = format!("{}:{}", dest, port);
    
    // Convert milliseconds to a Duration for the timeout
    let dur = Duration::from_millis(timeout_ms);
    
    // Try to resolve the intended destination to IP addresses
    let intended_ips: Vec<IpAddr> = addr.to_socket_addrs()
        .ok()
        .map(|addrs| addrs.map(|sa| sa.ip()).collect())
        .unwrap_or_default();
    
    // Measure connection time to detect suspiciously fast local proxy connections
    let start = std::time::Instant::now();
    
    // Try to connect with a timeout
    match timeout(dur, TcpStream::connect(&addr)).await {
        Ok(Ok(stream)) => {
            let connect_time = start.elapsed();
            
            // Connection successful - get the actual peer address
            if let Ok(peer_socket_addr) = stream.peer_addr() {
                let peer_ip = peer_socket_addr.ip();
                
                // Perform inspection if requested
                let (ip_matches, timing_suspicious, read_bytes, read_result, write_bytes, write_result, banner_preview, layer7_protocol) = if inspect {
                    // Check if the peer IP matches any of the intended IPs
                    let ip_match = intended_ips.is_empty() || intended_ips.contains(&peer_ip);
                    
                    // Probe the connection to detect proxy behavior
                    let inspection = inspect_connection(dest, port, timeout_ms, connect_time, &peer_ip).await;
                    
                    // If ambiguous (timeout/timeout), perform Layer 7 probing
                    let l7_proto = if inspection.read_result == "timeout" && inspection.write_result == "timeout" {
                        // Use shorter timeout for Layer 7 probes (1000ms)
                        layer7_probes::layer7_probe(dest, port, 1000).await
                    } else {
                        None
                    };
                    
                    (Some(ip_match), Some(inspection.timing_suspicious), 
                     Some(inspection.read_bytes), Some(inspection.read_result),
                     Some(inspection.write_bytes), Some(inspection.write_result),
                     inspection.banner_preview, l7_proto)
                } else {
                    (None, None, None, None, None, None, None, None)
                };
                
                PortCheckResult {
                    status: "open".to_string(),
                    peer_addr: Some(peer_ip),
                    connect_time_ms: Some(connect_time.as_millis()),
                    ip_matches,
                    timing_suspicious,
                    read_bytes,
                    read_result,
                    write_bytes,
                    write_result,
                    banner_preview,
                    layer7_protocol,
                }
            } else {
                // Couldn't get peer address (shouldn't happen, but handle gracefully)
                PortCheckResult {
                    status: "open".to_string(),
                    peer_addr: None,
                    connect_time_ms: Some(connect_time.as_millis()),
                    ip_matches: None,
                    timing_suspicious: None,
                    read_bytes: None,
                    read_result: None,
                    write_bytes: None,
                    write_result: None,
                    banner_preview: None,
                    layer7_protocol: None,
                }
            }
        },
        Ok(Err(_)) => PortCheckResult {
            status: "closed".to_string(),
            peer_addr: None,
            connect_time_ms: None,
            ip_matches: None,
            timing_suspicious: None,
            read_bytes: None,
            read_result: None,
            write_bytes: None,
            write_result: None,
            banner_preview: None,
            layer7_protocol: None,
        },
        Err(_) => PortCheckResult {
            status: "filtered".to_string(),
            peer_addr: None,
            connect_time_ms: None,
            ip_matches: None,
            timing_suspicious: None,
            read_bytes: None,
            read_result: None,
            write_bytes: None,
            write_result: None,
            banner_preview: None,
            layer7_protocol: None,
        },
    }
}

/// Inspection result with detailed data
struct InspectionResult {
    timing_suspicious: bool,        // True if timing itself is suspicious
    read_bytes: usize,              // Bytes from read test
    read_result: String,            // Result of read test
    write_bytes: usize,             // Bytes from write test
    write_result: String,           // Result of write test
    banner_preview: Option<String>, // Data from either test
}

/// Test connection by attempting to read (banner grab)
/// Returns: (result_status, bytes_read, data_preview)
async fn test_read_connection(stream: &mut TcpStream) -> (String, usize, Option<String>) {
    let mut buf = [0u8; 256];  // Read up to 256 bytes for banner
    let read_timeout = Duration::from_millis(100);
    
    match timeout(read_timeout, stream.read(&mut buf)).await {
        Ok(Ok(0)) => {
            // Connection closed immediately
            ("closed".to_string(), 0, None)
        },
        Ok(Ok(n)) => {
            // Got data - likely a real service with a banner (e.g., SSH, SMTP)
            let preview = String::from_utf8_lossy(&buf[..n])
                .chars()
                .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                .take(50)
                .collect::<String>();
            
            let preview = if preview.is_empty() {
                None
            } else {
                Some(preview.trim().to_string())
            };
            
            ("data".to_string(), n, preview)
        },
        Ok(Err(_)) => {
            // Read error
            ("error".to_string(), 0, None)
        },
        Err(_) => {
            // Timeout - connection is waiting, which is normal behavior
            ("timeout".to_string(), 0, None)
        },
    }
}

/// Test connection by writing data then reading response
/// Returns: (result_status, bytes_read, data_preview)
async fn test_write_connection(stream: &mut TcpStream) -> (String, usize, Option<String>) {
    use tokio::io::AsyncWriteExt;
    
    // Send generic probe data twice to trigger response from stubborn services
    let probe_data = b"\x00\x00\r\n";
    
    // First probe
    if let Err(_) = stream.write_all(probe_data).await {
        return ("error".to_string(), 0, None);
    }
    
    // Small pause before second probe
    tokio::time::sleep(Duration::from_millis(50)).await;
    
    // Second probe
    if let Err(_) = stream.write_all(probe_data).await {
        return ("error".to_string(), 0, None);
    }
    
    // Try to read response
    let mut buf = [0u8; 256];
    let read_timeout = Duration::from_millis(100);
    
    match timeout(read_timeout, stream.read(&mut buf)).await {
        Ok(Ok(0)) => {
            // Connection closed after write
            ("closed".to_string(), 0, None)
        },
        Ok(Ok(n)) => {
            // Got response data
            let preview = String::from_utf8_lossy(&buf[..n])
                .chars()
                .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                .take(50)
                .collect::<String>();
            
            let preview = if preview.is_empty() {
                None
            } else {
                Some(preview.trim().to_string())
            };
            
            ("data".to_string(), n, preview)
        },
        Ok(Err(_)) => {
            // Read error
            ("error".to_string(), 0, None)
        },
        Err(_) => {
            // Timeout - no response to our write
            ("timeout".to_string(), 0, None)
        },
    }
}

/// Inspect connection for suspicious proxy behavior
/// Performs both read and write tests on separate connections
/// Returns detailed inspection data
/// 
/// Detection methods:
/// 1. Timing: Suspiciously fast connections to remote IPs
/// 2. Read test: Passive banner grab
/// 3. Write test: Active probe with data
async fn inspect_connection(
    dest: &str,
    port: u16,
    timeout_ms: u64,
    connect_time: std::time::Duration,
    peer_ip: &IpAddr
) -> InspectionResult {
    // Check 1: Suspiciously fast connection time
    let is_localhost = match peer_ip {
        IpAddr::V4(ip) => ip.octets()[0] == 127,
        IpAddr::V6(ip) => ip.is_loopback(),
    };
    
    let timing_suspicious = if !is_localhost {
        let is_private = match peer_ip {
            IpAddr::V4(ip) => {
                let octets = ip.octets();
                // RFC1918: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
                octets[0] == 10
                    || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                    || (octets[0] == 192 && octets[1] == 168)
            },
            IpAddr::V6(_) => false,
        };
        
        let timing_threshold_ms = if is_private { 1 } else { 5 };
        connect_time.as_millis() < timing_threshold_ms
    } else {
        false
    };
    
    // Check 2: Perform read test (on new connection)
    let addr = format!("{}:{}", dest, port);
    let dur = Duration::from_millis(timeout_ms);
    
    let (read_result, read_bytes, mut banner_preview) = 
        match timeout(dur, TcpStream::connect(&addr)).await {
            Ok(Ok(mut stream)) => test_read_connection(&mut stream).await,
            _ => ("error".to_string(), 0, None),
        };
    
    // Check 3: Perform write test (on new connection)
    // Skip if read test already confirmed real service with banner
    let (write_result, write_bytes, write_preview) = 
        if read_result == "data" {
            // Already confirmed real service - skip write test
            ("skipped".to_string(), 0, None)
        } else {
            match timeout(dur, TcpStream::connect(&addr)).await {
                Ok(Ok(mut stream)) => test_write_connection(&mut stream).await,
                _ => ("error".to_string(), 0, None),
            }
        };
    
    // Use banner from either test (prefer read test banner)
    if banner_preview.is_none() {
        banner_preview = write_preview;
    }
    
    InspectionResult {
        timing_suspicious,
        read_bytes,
        read_result,
        write_bytes,
        write_result,
        banner_preview,
    }
}

/// Main function - this is where the program starts
/// 
/// The #[tokio::main] attribute tells Rust to use the tokio runtime
/// which enables async/await functionality
#[tokio::main]
async fn main() {
    // Set up command-line argument parsing using clap
    let matches = Command::new("portping")
        .about("A simple TCP port checker.")
        .arg(
            Arg::new("port")
                .short('p')                    // -p flag
                .long("port")                  // --port flag
                .required(false)               // Not required if --help-inspect is used
                .help("Port(s) to check: single, comma list, or range (e.g. 80,443,1000-1010)")
                .value_parser(clap::value_parser!(String)),
        )
        .arg(
            Arg::new("dest")
                .short('d')                    // -d flag
                .long("dest")                  // --dest flag
                .required(false)               // Not required if --help-inspect is used
                .help("Destination IP or hostname")
                .value_parser(clap::value_parser!(String)),
        )
        .arg(
            Arg::new("n")
                .short('n')                    // -n flag
                .value_parser(clap::value_parser!(String))
                .help("Number of probes per port (default 1)"),
        )
        .arg(
            Arg::new("timeout")
                .short('t')                    // -t flag
                .value_parser(clap::value_parser!(String))
                .help("Timeout in milliseconds (default 3000)"),
        )
        .arg(
            Arg::new("inspect")
                .long("inspect")               // --inspect flag
                .action(clap::ArgAction::SetTrue)
                .help("Enable deep inspection to detect proxies/interception"),
        )
        .arg(
            Arg::new("help-inspect")
                .long("help-inspect")          // --help-inspect flag
                .action(clap::ArgAction::SetTrue)
                .help("Show detailed information about --inspect mode"),
        )
        .get_matches();  // Parse the command-line arguments

    // Check if --help-inspect was requested
    if matches.get_flag("help-inspect") {
        println!("\n{}\n", "=".repeat(80));
        println!("INSPECTION MODE (--inspect) - Detailed Information");
        println!("{}\n", "=".repeat(80));
        
        println!("WHAT IT DOES:");
        println!("  The --inspect flag enables deep analysis to detect proxy interception,");
        println!("  firewall filtering, and other network anomalies that may cause the");
        println!("  initial TCP connection status to be misleading, such as ZTNA solutions.");
        println!("  These can interfere with your own internal port checking of your own");
        println!("  company network depending on how they are configured. E.g. reporting");
        println!("  \"open\" when in fact they are not.\n");
        
        println!("HOW IT WORKS:");
        println!("  For each open port, two separate connection tests are performed:\n");
        println!("  1. Rx Test (Receive/Read Test):");
        println!("     - Establishes connection and passively waits for data (banner grab)");
        println!("     - Detects services that send banners immediately (SSH, SMTP, FTP, etc.)");
        println!("     - Timeout: 100ms\n");
        println!("  2. Tx Test (Transmit/Write Test):");
        println!("     - Establishes new connection and sends probe data (twice)");
        println!("     - Reads response to detect how service reacts to unexpected input");
        println!("     - Skipped if Rx test already confirmed real service with banner");
        println!("     - Timeout: 100ms\n");
        println!("  3. Layer 7 Protocol Probing (if timeout/timeout at Layer 4):");
        println!("     - Only runs for ambiguous timeout/timeout cases");
        println!("     - Tries: TLS, HTTP, MySQL, PostgreSQL handshakes");
        println!("     - Stops at first successful protocol detection");
        println!("     - Timeout: 1000ms per protocol\n");
        println!("  4. Extended Probe (last resort if all Layer 7 checks fail):");
        println!("     - Sends multiple probe strings: \\r\\n, QUIT, EXIT, BYE");
        println!("     - Waits 200ms after each probe");
        println!("     - If service closes or responds → proves working (just slow)");
        println!("     - If stays silent → truly ambiguous (receive-only OR dead)\n");
        
        println!("SUSPICIOUS DETECTION (Three Confidence Levels):\n");
        
        println!("  YES - High Confidence Suspicious:");
        println!("    • IP Mismatch: Responding IP differs from intended destination");
        println!("    • Fast Timing: Connection time suspiciously fast for remote IP");
        println!("                   (< 1ms for private IPs, < 5ms for public IPs)");
        println!("    • Rx Closed: Connection closed immediately on read attempt");
        println!("                 (before any data exchange → proxy rejecting)");
        println!("    • I/O Errors: Persistent errors on both tests");
        println!("    • Inconsistent: Error/timeout/closed mix patterns\n");
        
        println!("  POSSIBLE - Ambiguous (Layer 4 and Layer 7 both inconclusive):");
        println!("    • No Response: Both Rx and Tx timeout");
        println!("      → Could be: client-first protocol (syslog) OR proxy without backend");
        println!("    • Layer 7 probing attempted but no protocols matched");
        println!("    • Still ambiguous - requires manual verification\n");
        
        println!("  NO - Not Suspicious (End-to-End Confirmed):");
        println!("    • Data received: Service sends banner or responds to probe");
        println!("    • Protocol validation: Rx timeout + Tx closed");
        println!("      → Server received probe, validated format, closed connection");
        println!("      → Proves end-to-end connectivity (HTTP/HTTPS, etc.)\n");
        
        println!("EXAMPLE SCENARIOS:");
        println!("  • Real SSH service:");
        println!("    Rx: data (banner) | Tx: skipped → Suspicious? NO");
        println!("  • Real HTTP/HTTPS (validates protocol):");
        println!("    Rx: timeout | Tx: closed → Suspicious? NO (protocol validation)");
        println!("  • Real HTTPS (client-first with Layer 7 detection):");
        println!("    Rx: timeout | Tx: timeout | Layer7: TLS → Suspicious? NO (TLS)");
        println!("  • Real MySQL (server-first with Layer 7 detection):");
        println!("    Rx: timeout | Tx: timeout | Layer7: MySQL → Suspicious? NO (MySQL)");
        println!("  • Slow service (responds to extended probe):");
        println!("    Rx: timeout | Tx: timeout | Layer7: none | Extended: closes → NO (Working)");
        println!("  • Receive-only service (stays silent through all probes):");
        println!("    Rx: timeout | Tx: timeout | Layer7: none | Extended: open → POSSIBLE");
        println!("  • Proxy WITHOUT backend (ZTNA/Netskope):");
        println!("    Rx: timeout | Tx: timeout | Layer7: none → Suspicious? POSSIBLE");
        println!("  • Proxy that immediately rejects:");
        println!("    Rx: closed | Tx: (not run) → Suspicious? YES (rx closed)");
        println!("  • Firewall that drops packets:");
        println!("    Status: filtered (timeout on connect) → Not in --inspect\n");
        println!("NOTE: POSSIBLE verdicts require manual verification - check if the service");
        println!("      is expected at that port to determine if suspicious or legitimate.\n");
        
        println!("{}\n", "=".repeat(80));
        std::process::exit(0);
    }

    // Extract values from the parsed arguments
    // Validate that port and dest are provided (unless --help-inspect was used, which exits above)
    let port_arg = matches.get_one::<String>("port");
    let dest = matches.get_one::<String>("dest");
    
    if port_arg.is_none() || dest.is_none() {
        eprintln!("Error: --port and --dest are required arguments.");
        eprintln!("For more information, try '--help'.");
        std::process::exit(1);
    }
    
    let port_arg = port_arg.expect("port argument should be present after validation");
    let dest = dest.expect("dest argument should be present after validation");
    let n = matches.get_one::<String>("n")                      // Get number of probes
        .map(|s| s.parse::<u32>().unwrap_or(1))                 // Parse to u32, default to 1
        .unwrap_or(1);                                          // If no value, use 1
    let timeout = matches.get_one::<String>("timeout")          // Get timeout value
        .map(|s| s.parse::<u64>().unwrap_or(3000))              // Parse to u64, default to 3000
        .unwrap_or(3000);                                       // If no value, use 3000
    
    // Validate timeout bounds
    if timeout < 1 {
        eprintln!("Error: Timeout must be at least 1 millisecond.");
        std::process::exit(1);
    }
    if timeout > 300000 {  // 5 minutes
        eprintln!("Error: Timeout cannot exceed 300000 milliseconds (5 minutes).");
        std::process::exit(1);
    }
    
    let inspect = matches.get_flag("inspect");                  // Get inspect flag

    // Parse the port string into a vector of port numbers
    let ports = match parse_ports(port_arg) {
        Ok(ports) => ports,  // Success - use the parsed ports
        Err(e) => {
            eprintln!("Error parsing ports: {}", e);  // Print error to stderr
            std::process::exit(1);                    // Exit with error code 1
        }
    };

    // Validate that we don't have multiple ports when n > 1
    if n > 1 && ports.len() > 1 {
        eprintln!("Error: When -n is greater than 1, only one port can be specified.");
        std::process::exit(1);
    }

    // Validate that -n and --inspect are not used together
    if n > 1 && inspect {
        eprintln!("Error: -n (multiple probes) and --inspect cannot be used together.");
        std::process::exit(1);
    }

    // Validate DNS resolution before attempting any port checks
    // Use first port to test resolution (any port will do for DNS check)
    let test_addr = format!("{}:{}", dest, ports[0]);
    if let Err(e) = test_addr.to_socket_addrs() {
        eprintln!("Error: DNS resolution failed for '{}': {}", dest, e);
        eprintln!("Please check the hostname or IP address and try again.");
        std::process::exit(1);
    }

    // Main logic - handle single probe vs multiple probes differently
    if n == 1 {
        // Single probe mode: check all ports in parallel for efficiency
        
        // Create a vector to hold all the async tasks
        let mut handles = Vec::new();
        
        // Spawn a separate async task for each port
        for &port in &ports {
            let dest = dest.clone();  // Clone the destination string for this task
            handles.push(tokio::spawn(async move {
                // This closure runs in a separate task
                let result = check_port(&dest, port, timeout, inspect).await;
                (port, result)  // Return port and result
            }));
        }
        
        // Collect all the results
        let mut results = Vec::new();
        let mut failed_ports = Vec::new();
        for h in handles {
            match h.await {
                Ok(res) => results.push(res),
                Err(e) => {
                    // Task panicked - extract port info if possible
                    eprintln!("Warning: Task failed with error: {}", e);
                    if e.is_panic() {
                        eprintln!("  A port check task panicked unexpectedly.");
                    }
                    failed_ports.push("unknown");
                }
            }
        }
        
        // Report if any tasks failed
        if !failed_ports.is_empty() {
            eprintln!("\nWarning: {} port check(s) failed to complete.\n", failed_ports.len());
        }
        
        // Display results in a nice table format
        let mut columns = vec![
            Column::new("Destination", 0, Justification::Left).unwrap(),
            Column::new("Port", 0, Justification::Left).unwrap(),
            Column::new("Status", 0, Justification::Left).unwrap(),
            Column::new("Responding IP", 0, Justification::Left).unwrap(),
            Column::new("Time(ms)", 0, Justification::Right).unwrap(),
        ];
        
        if inspect {
            columns.push(Column::new("Rx Test", 0, Justification::Left).unwrap());
            columns.push(Column::new("Tx Test", 0, Justification::Left).unwrap());
            columns.push(Column::new("Banner", 0, Justification::Left).unwrap());
            columns.push(Column::new("Suspicious?", 0, Justification::Left).unwrap());
        }
        let mut table = Table::new(columns).unwrap();
        
        // Add each result as a row in the table
        for (port, result) in results {
            let peer_str = result.peer_addr
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "-".to_string());
            
            let time_str = result.connect_time_ms
                .map(|t| t.to_string())
                .unwrap_or_else(|| "-".to_string());
            
            let mut row = vec![
                dest.to_string(),
                port.to_string(),
                result.status.clone(),
                peer_str,
                time_str,
            ];
            
            if inspect {
                // Rx Result column (with byte count if applicable)
                let read_result_str = match (result.read_result.as_ref(), result.read_bytes) {
                    (Some(result_val), Some(bytes)) if bytes > 0 => {
                        format!("{} ({} bytes)", result_val, bytes)
                    },
                    (Some(result_val), _) => result_val.to_string(),
                    _ => "-".to_string(),
                };
                row.push(read_result_str);
                
                // Tx Result column (with byte count if applicable)
                let write_result_str = match (result.write_result.as_ref(), result.write_bytes) {
                    (Some(result_val), Some(bytes)) if bytes > 0 => {
                        format!("{} ({} bytes)", result_val, bytes)
                    },
                    (Some(result_val), _) => result_val.to_string(),
                    _ => "-".to_string(),
                };
                row.push(write_result_str);
                
                // Banner column
                let banner_str = result.banner_preview.as_ref()
                    .map(|s| s.as_str())
                    .unwrap_or("-");
                row.push(banner_str.to_string());
                
                // Suspicious? column - analyze combined recv and send results
                if result.status == "open" {
                    let mut reasons = Vec::new();
                    
                    // Check IP mismatch
                    if result.ip_matches == Some(false) {
                        reasons.push("IP mismatch");
                    }
                    
                    // Check timing
                    if result.timing_suspicious == Some(true) {
                        reasons.push("fast timing");
                    }
                    
                    // Analyze rx and tx results together
                    let rx = result.read_result.as_deref();
                    let tx = result.write_result.as_deref();
                    
                    let mut ambiguous = false;
                    
                    match (rx, tx) {
                        // Definitive proof of real end-to-end service
                        // Any data received (rx or tx) proves connection works
                        (Some("data"), _) | (_, Some("data")) => {
                            // No suspicion - data proves end-to-end connectivity
                        },
                        
                        // Protocol validation = proof of working connection
                        // Server received probe, validated protocol, closed connection
                        // This proves end-to-end connectivity even if data was invalid
                        (Some("timeout"), Some("closed")) => {
                            // No suspicion - server processed our data (HTTP/HTTPS validation)
                        },
                        
                        // HIGH CONFIDENCE SUSPICIOUS: immediate close or errors
                        // Rx closed = connection accepted then immediately closed (proxy rejecting)
                        (Some("closed"), _) => {
                            reasons.push("rx closed");
                        },
                        (Some("error"), Some("error")) => {
                            reasons.push("I/O errors");
                        },
                        (Some("error"), _) | (_, Some("error")) => {
                            reasons.push("inconsistent");
                        },
                        
                        // LOW CONFIDENCE: ambiguous timeout/timeout
                        // Could be client-first protocol (syslog) OR proxy without backend
                        // Check if Layer 7 probing resolved the ambiguity
                        (Some("timeout"), Some("timeout")) => {
                            // If Layer 7 detected a protocol, it's proven working
                            if result.layer7_protocol.is_none() {
                                ambiguous = true;
                            }
                            // else: Layer 7 proved connectivity, treat as "No"
                        },
                        
                        _ => {}
                    }
                    
                    let suspicious_str = if !reasons.is_empty() {
                        format!("Yes ({})", reasons.join(", "))
                    } else if ambiguous {
                        "Possible (ambiguous)".to_string()
                    } else {
                        // Show Layer 7 protocol if detected for clarity
                        if let Some(ref protocol) = result.layer7_protocol {
                            format!("No ({})", protocol)
                        } else {
                            "No".to_string()
                        }
                    };
                    row.push(suspicious_str);
                } else {
                    row.push("-".to_string());
                }
            }
            
            table.add_row(row).unwrap();
        }
        
        // Print the formatted table
        println!("\n{}", table);
        
    } else {
        // Multiple probe mode: check the same port multiple times
        
        let port = ports[0];  // We know there's only one port when n > 1
        
        // Run n probes sequentially
        println!(); 
        for i in 1..=n {
            let result = check_port(dest, port, timeout, inspect).await;
            let peer_info = result.peer_addr
                .map(|ip| format!(" [peer: {}]", ip))
                .unwrap_or_default();
            let time_info = result.connect_time_ms
                .map(|t| format!(" [{}ms]", t))
                .unwrap_or_default();
            
            println!("probe {}: {}:{} -> {}{}{}", i, dest, port, result.status, peer_info, time_info);
        }
        println!();
    }
}
