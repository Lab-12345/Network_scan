# Network Port Scanner

A Python script to perform network reconnaissance using Nmap, scanning for open ports and services on a local network. The script automates IP range detection, runs multiple Nmap scan types, and saves results as text, HTML, and XML files.

## Features
- **Automatic IP Range Detection**: Identifies the local network range (e.g., `192.168.1.0/24`).
- **Multiple Scan Types**:
  - TCP Connect (`-sT`): Full TCP connection scan.
  - UDP (`-sU`): Scans UDP ports (e.g., DNS, SNMP).
  - Service Version (`-sV`): Detects service versions on open ports.
  - OS Detection (`-O`): Identifies operating systems.
  - Verbose Fragmented (`-sS -v -f`): TCP SYN scan with verbose output and packet fragmentation.
- **User-Friendly Interface**: Select scans via numbers or run all scans.
- **Output Formats**: Saves results as text, HTML, and XML for analysis.
- **Error Handling**: Manages Nmap errors, missing dependencies, and user interrupts.
- **Guidance**: Provides next steps for analyzing results and identifying risks.

## Requirements
- **Python 3.x**: For running the script.
- **Nmap**: Install from [nmap.org](https://nmap.org/download.html).
- **Admin/Root Privileges**: Required for most scans (`-sS`, `-sU`, `-O`, `-f`).
- **Operating System**: Compatible with Windows, Linux, and macOS.

## Installation
1. **Install Nmap**:
   - Windows: Download and install from [nmap.org](https://nmap.org/download.html).
   - Linux: `sudo apt-get install nmap` (Ubuntu/Debian) or equivalent for your distro.
   - macOS: `brew install nmap` (with Homebrew) or download from [nmap.org](https://nmap.org/download.html).
2. **Clone the Repository**:
   ```bash
   git clone https://github.com/<your-username>/network-port-scanner.git
   cd network-port-scanner
   ```
3. **Ensure Python is Installed**:
   - Verify with `python3 --version` or `python --version`.
   - Install Python from [python.org](https://www.python.org/downloads/) if needed.

## Usage
1. **Run the Script**:
   ```bash
   sudo python3 network_scan.py
   ```
   - Use `sudo` (Linux/macOS) or run as administrator (Windows) for privileged scans.
2. **Select Scans**:
   - The script detects the local IP range (e.g., `192.168.1.0/24`).
   - Choose scan types by entering numbers (e.g., `1,3`) or `all`:
     ```
     Available scan types:
     1. TCP Connect
     2. UDP
     3. Service Version
     4. OS Detection
     5. Verbose Fragmented
     Enter scan numbers (e.g., 1,2,3) or 'all' for all scans:
     ```
3. **Confirm and Scan**:
   - Confirm the IP range and selected scans with `y`.
   - Results are saved as:
     - Text: `<scan_type>_results_<timestamp>.txt`
     - HTML: `<scan_type>_results_<timestamp>.html`
     - XML: `<prefix>_results.xml`
4. **Analyze Results**:
   - Review open ports (e.g., 80=HTTP, 22=SSH, 53=DNS).
   - Check service versions and OS details for vulnerabilities.
   - Use Wireshark to analyze fragmented packets or traffic.
   - Identify risks like outdated services or open Telnet.

## Example Output
```bash
Network Port Scanner v2.2
Ensure you have permission to scan the target network.
Detected local IP range: 192.168.1.0/24

Available scan types:
1. TCP Connect
2. UDP
3. Service Version
4. OS Detection
5. Verbose Fragmented
Enter scan numbers (e.g., 1,2,3) or 'all' for all scans: 1,5

Selected scans: TCP Connect, Verbose Fragmented
Scan 192.168.1.0/24 with these options? (y/n): y
Starting Nmap TCP Connect scan on 192.168.1.0/24...
TCP Connect scan completed successfully.

tcp_connect scan results saved as:
- Text file: tcp_connect_results_20250623_111400.txt
- HTML file: tcp_connect_results_20250623_111400.html

Starting Nmap Verbose Fragmented scan...
[... more results ...]
```

## Scan Types Explained
- **TCP Connect (`-sT`)**: Establishes full TCP connections to detect open ports. Works without root privileges but is less stealthy.
- **UDP (`-sU`)**: Scans UDP ports, useful for services like DNS or SNMP. Slower due to UDP's connectionless nature.
- **Service Version (`-sV`)**: Probes open ports to identify service versions (e.g., Apache 2.4.41).
- **OS Detection (`-O`)**: Identifies operating systems based on TCP/IP stack characteristics.
- **Verbose Fragmented (`-sS -v -f`)**: Performs a stealthy TCP SYN scan with verbose output and packet fragmentation to evade some firewalls.

## Important Notes
- **Legal Warning**: Only scan networks you own or have explicit permission to scan. Unauthorized scanning is illegal in many jurisdictions.
- **Performance**:
  - UDP scans and OS detection are slower.
  - Fragmented scans may be affected by firewalls.
  - Scan duration depends on network size and selected scans.
- **Security**:
  - Review results for unexpected open ports (e.g., Telnet on 23).
  - Check service versions for known vulnerabilities.
  - Ensure devices aren't exposing sensitive services.
- **Dependencies**: Nmap must be in your system's PATH.

## Extending the Script
To add more Nmap scans, modify the `scan_types` list in `network_scan.py`:
```python
scan_types = [
    ...,
    {"name": "Custom Scan", "options": "-sS -p 80,443", "prefix": "custom"}
]
```

## Contributing
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/new-scan`).
3. Commit changes (`git commit -m "Add new scan type"`).
4. Push to the branch (`git push origin feature/new-scan`).
5. Open a pull request.

## License
This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgments
- Built with [Nmap](https://nmap.org/), a powerful network scanning tool.
- Inspired by the need to learn network reconnaissance and security auditing.