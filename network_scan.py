import subprocess
import datetime
import os
import sys
import re

def get_local_ip_range():
    """Detect the local IP range for scanning."""
    try:
        cmd = ['ip', 'addr'] if os.name != 'nt' else ['ipconfig']
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = result.stdout
        ip_pattern = r'(192\.168\.\d+\.\d+/24|10\.\d+\.\d+\.\d+/24|172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+/24)'
        match = re.search(ip_pattern, output)
        return match.group(0) if match else "192.168.1.0/24"
    except (subprocess.CalledProcessError, Exception) as e:
        print(f"Error detecting IP range: {e}", file=sys.stderr)
        return "192.168.1.0/24"

def run_nmap_scan(ip_range, scan_type, scan_options, output_prefix):
    """Execute Nmap scan with specified options and return results."""
    try:
        print(f"Starting Nmap {scan_type} scan on {ip_range}...")
        xml_output = f"{output_prefix}_results.xml"
        result = subprocess.run(
            ['nmap'] + scan_options.split() + [ip_range, '-oX', xml_output],
            capture_output=True, text=True, check=True
        )
        print(f"{scan_type} scan completed successfully.")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Nmap {scan_type} scan failed: {e.stderr}", file=sys.stderr)
        return ""
    except FileNotFoundError:
        print("Nmap not found. Please install Nmap from https://nmap.org/", file=sys.stderr)
        return ""

def save_results(scan_output, scan_type, timestamp):
    """Save scan results as text and HTML files."""
    if not scan_output:
        print(f"No {scan_type} scan results to save.")
        return None, None

    txt_filename = f"{scan_type}_results_{timestamp}.txt"
    try:
        with open(txt_filename, 'w', encoding='utf-8') as f:
            f.write(scan_output)
    except IOError as e:
        print(f"Error saving {scan_type} text file: {e}", file=sys.stderr)
        return None, None

    html_filename = f"{scan_type}_results_{timestamp}.html"
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Nmap {scan_type} Scan Results - {timestamp}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; background: #fff; }}
            h1 {{ color: #333; }}
            pre {{ background: #f8f8f8; padding: 15px; border: 1px solid #ddd; border-radius: 5px; white-space: pre-wrap; }}
        </style>
    </head>
    <body>
        <h1>Nmap {scan_type} Scan Results - {timestamp}</h1>
        <pre>{scan_output}</pre>
    </body>
    </html>
    """
    try:
        with open(html_filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
    except IOError as e:
        print(f"Error saving {scan_type} HTML file: {e}", file=sys.stderr)
        return txt_filename, None

    return txt_filename, html_filename

def main():
    """Main function to orchestrate the network scans."""
    print("Network Port Scanner v2.2")
    print("Ensure you have permission to scan the target network.")
    
    ip_range = get_local_ip_range()
    print(f"Detected local IP range: {ip_range}")
    
    scan_types = [
        {"name": "TCP Connect", "options": "-sT", "prefix": "tcp_connect"},
        {"name": "UDP", "options": "-sU", "prefix": "udp"},
        {"name": "Service Version", "options": "-sV", "prefix": "service_version"},
        {"name": "OS Detection", "options": "-O", "prefix": "os_detection"},
        {"name": "Verbose Fragmented", "options": "-sS -v -f", "prefix": "verbose_fragmented"}
    ]
    
    print("\nAvailable scan types:")
    for i, scan in enumerate(scan_types, 1):
        print(f"{i}. {scan['name']}")
    selected = input(f"Enter scan numbers (e.g., 1,2,3) or 'all' for all scans: ").strip().lower()
    
    if selected == 'all':
        selected_scans = scan_types
    else:
        try:
            indices = [int(i) - 1 for i in selected.split(',')]
            selected_scans = [scan_types[i] for i in indices if 0 <= i < len(scan_types)]
        except ValueError:
            print("Invalid input. Running TCP Connect scan only.")
            selected_scans = [scan_types[0]]
    
    print(f"\nSelected scans: {', '.join([scan['name'] for scan in selected_scans])}")
    proceed = input(f"Scan {ip_range} with these options? (y/n): ").strip().lower()
    if proceed != 'y':
        print("Scan aborted.")
        return

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    for scan in selected_scans:
        scan_output = run_nmap_scan(ip_range, scan['name'], scan['options'], scan['prefix'])
        if scan_output:
            txt_file, html_file = save_results(
                scan_output, scan['name'].lower().replace(" ", "_"), timestamp
            )
            if txt_file or html_file:
                print(f"\n{scan['name']} scan results saved as:")
                if txt_file:
                    print(f"- Text file: {txt_file}")
                if html_file:
                    print(f"- HTML file: {html_file}")
    
    print("\nRecommended next steps:")
    print("1. Review open ports (e.g., 80=HTTP, 22=SSH, 53=DNS for UDP)")
    print("2. Check service versions and OS details for vulnerabilities")
    print("3. Use Wireshark to analyze fragmented packets or network traffic")
    print("4. Identify security risks (e.g., outdated services, open Telnet)")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        sys.exit(1)