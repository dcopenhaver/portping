// Import external crates (libraries) that we'll use
use clap::{Arg, Command};  // For parsing command-line arguments
use tokio::net::TcpStream;  // For TCP network connections (async)
use tokio::time::{timeout, Duration};  // For handling timeouts
use ctable::{Table, Column, Justification};  // For creating formatted tables

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

/// Check if a specific port is open on a destination host
/// 
/// This is an async function that:
/// 1. Attempts to establish a TCP connection
/// 2. Returns "open" if connection succeeds
/// 3. Returns "closed" if connection is refused
/// 4. Returns "filtered" if connection times out
async fn check_port(dest: &str, port: u16, timeout_ms: u64) -> String {
    // Construct the full address (host:port)
    let addr = format!("{}:{}", dest, port);
    
    // Convert milliseconds to a Duration for the timeout
    let dur = Duration::from_millis(timeout_ms);
    
    // Try to connect with a timeout
    match timeout(dur, TcpStream::connect(&addr)).await {
        Ok(Ok(_stream)) => "open".to_string(),      // Connection successful
        Ok(Err(_)) => "closed".to_string(),         // Connection refused
        Err(_) => "filtered".to_string(),           // Timeout occurred
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
        .about("A simple TCP port checker, like a minimal nmap.")
        .arg(
            Arg::new("port")
                .short('p')                    // -p flag
                .long("port")                  // --port flag
                .required(true)                // This argument is mandatory
                .help("Port(s) to check: single, comma list, or range (e.g. 80,443,1000-1010)")
                .value_parser(clap::value_parser!(String)),
        )
        .arg(
            Arg::new("dest")
                .short('d')                    // -d flag
                .long("dest")                  // --dest flag
                .required(true)                // This argument is mandatory
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
                .help("Timeout in milliseconds (default 5000)"),
        )
        .get_matches();  // Parse the command-line arguments

    // Extract values from the parsed arguments
    let port_arg = matches.get_one::<String>("port").unwrap();  // Get the port argument
    let dest = matches.get_one::<String>("dest").unwrap();      // Get the destination
    let n = matches.get_one::<String>("n")                      // Get number of probes
        .map(|s| s.parse::<u32>().unwrap_or(1))                 // Parse to u32, default to 1
        .unwrap_or(1);                                          // If no value, use 1
    let timeout = matches.get_one::<String>("timeout")          // Get timeout value
        .map(|s| s.parse::<u64>().unwrap_or(5000))              // Parse to u64, default to 5000
        .unwrap_or(5000);                                       // If no value, use 5000

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
                let result = check_port(&dest, port, timeout).await;
                (dest, port, result)  // Return a tuple with all the info
            }));
        }
        
        // Collect all the results
        let mut results = Vec::new();
        for h in handles {
            if let Ok(res) = h.await {  // Wait for each task to complete
                results.push(res);
            }
        }
        
        // Display results in a nice table format
        let columns = vec![
            Column::new("Destination", 0, Justification::Left).unwrap(),
            Column::new("Port", 0, Justification::Left).unwrap(),
            Column::new("Result", 0, Justification::Left).unwrap(),
        ];
        let mut table = Table::new(columns).unwrap();
        
        // Add each result as a row in the table
        for (dest, port, result) in results {
            table.add_row(vec![dest, port.to_string(), result]).unwrap();
        }
        
        // Print the formatted table
        println!("\n{}", table);
        
    } else {
        // Multiple probe mode: check the same port multiple times
        
        let port = ports[0];  // We know there's only one port when n > 1
        
        // Run n probes sequentially
        println!(); 
        for i in 1..=n {
            let result = check_port(dest, port, timeout).await;
            println!("probe {}: {}:{} -> {}", i, dest, port, result);
        }
        println!();
    }
}
