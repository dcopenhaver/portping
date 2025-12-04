# portping

A fast, parallel TCP port scanner with some limited inspection capabilities to detect proxy interception and network anomalies.

NOTE: Built and intended for internal IT diagnostics, purpose built to solve a problem I was having, only scans one single target host at a time. If you want a comprehensive port scanner, use nmap, not this.

**portping** goes beyond basic port scanning with the --inspect option by performing some Layer 4 and Layer 7 analysis to determine if ports are genuinely open or potentially being intercepted by proxies (like ZTNA solutions). This is particularly useful for validating internal network connectivity and detecting scenarios that may report ports as "open" when they're actually being blocked or proxied.

## Features

- **Parallel Port Scanning**: Check multiple ports simultaneously for fast results
- **Clean Table Output**: Results displayed in formatted tables for easy reading
- **Inspection Mode**: Detect proxy interception and network anomalies with `--inspect`
  - **Layer 7 Protocol Detection**: Automatically identifies TLS, HTTP, MySQL, PostgreSQL, RDP, and more
  - **Banner Grabbing**: Captures service banners for identification
  - **Timing Analysis**: Detects suspiciously fast connections that indicate local proxies
  - **IP Verification**: Confirms responding IP matches intended destination
  - **Extended Probing**: Aggressive last-resort checks for slow or stubborn services


## Installation
Requires Rust 1.70 or later:

```bash
git clone https://github.com/yourusername/portping.git
cd portping
cargo build --release
```

The binary will be available at `target/release/portping` (or `target/release/portping.exe` on Windows).

## Usage

### Basic Port Scanning

```bash
# Check a single port
portping -d example.com -p 443

# Check multiple ports
portping -d example.com -p 80,443,8080

# Check a port range
portping -d example.com -p 1000-1010

# Check mixed ports and ranges
portping -d 192.168.1.1 -p 22,80,443,3000-3005
```

### Multiple Probes

```bash
# Send 5 probes to a single port
portping -d example.com -p 443 -n 5
```

**Note**: Multiple probes (`-n`) can only be used with a single port and cannot be combined with `--inspect`.

### Custom Timeout

```bash
# Set timeout to 5 seconds (5000ms)
portping -d example.com -p 80,443 -t 5000
```

Default timeout is 3000ms (3 seconds). Valid range: 1-300000ms (5 minutes).

### Inspection Mode

Enable inspection to detect proxy interception and validate end-to-end connectivity:

```bash
# Basic inspection
portping -d example.com -p 443 --inspect

# Inspect multiple ports
portping -d 192.168.1.100 -p 22,80,443,3306,5432 --inspect
```

#### What Inspection Mode Does

Inspection mode performs testing on each port reported open:

1. **Rx Test (Receive)**: Passively waits for service banners (100ms timeout)
2. **Tx Test (Transmit)**: Sends probe data and reads response (100ms timeout)
3. **Layer 7 Probing**: Tests TLS, HTTP, MySQL, PostgreSQL, RDP protocols (1000ms per protocol)
4. **Extended Probe**: Sends 5 probe strings to trigger slow services (200ms per probe)

#### Suspicious Detection Levels

**YES - High Confidence Suspicious**
- IP mismatch: Responding IP differs from destination
- Fast timing: Connection < 1ms (private) or < 5ms (public)
- Rx closed: Connection closed immediately on read
- I/O errors: Persistent errors on both tests
- Inconsistent: Mixed error/timeout/closed patterns

**POSSIBLE - Ambiguous**
- Both Rx and Tx timeout with no Layer 7 protocol detected
- Could be legitimate client-first protocol or dead proxy
- Requires manual verification

**NO - Not Suspicious**
- Service sends banner or responds to probes
- Protocol validation successful (e.g., HTTP closes after invalid request)
- Layer 7 protocol detected (TLS, HTTP, MySQL, PostgreSQL, RDP)
- Extended probe confirms service is responsive

#### Example Output

```
Destination      Port   Status   Responding IP    Time(ms)   Rx Test        Tx Test        Banner                      Suspicious?
example.com      22     open     93.184.216.34    45         data (23 bytes) skipped       SSH-2.0-OpenSSH_8.2p1       No
example.com      80     open     93.184.216.34    42         timeout        closed         -                           No (protocol validation)
example.com      443    open     93.184.216.34    43         timeout        timeout        -                           No (TLS)
example.com      3306   open     93.184.216.34    44         timeout        timeout        -                           No (MySQL)
example.com      8080   open     127.0.0.1        1          timeout        timeout        -                           Yes (IP mismatch, fast timing)
```

### Get Detailed Help

```bash
# Show detailed inspection mode documentation
portping --help-inspect

# Show general help
portping --help
```

## Command-Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--dest` | `-d` | Destination IP address or hostname (required) |
| `--port` | `-p` | Port(s) to check: single, comma-separated, or range (required) |
| `-n` | `-n` | Number of probes per port (default: 1, single port only) |
| `--timeout` | `-t` | Timeout in milliseconds (default: 3000, range: 1-300000) |
| `--inspect` | | Enable deep inspection to detect proxies/interception |
| `--help-inspect` | | Show detailed information about inspection mode |
| `--help` | `-h` | Show help information |

## License

MIT License - see LICENSE file for details

## Author

David Copenhaver

---

## Disclaimer

**THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.**

**USE AT YOUR OWN RISK.** The author(s) make no guarantees about the fitness of this software for any particular purpose. You are solely responsible for determining the appropriateness of using this software and assume all risks associated with its use, including but not limited to network disruption, security vulnerabilities, data loss, or any other damages.

By using this software, you acknowledge that you have read this disclaimer and agree to its terms.
