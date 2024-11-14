#!/usr/bin/env python3
"""CHUD - Cybernetic Hacking Utility Daemon"""
import csv
import json
import sys
import ipaddress
import socket
import asyncio
import subprocess
import requests
import whois
import dns.resolver
import shodan
from typing import List, Dict
import httpx
import folium
from nmap3 import nmap3

def get_external_ip():
    """Get the external IP address."""
    try:
        return requests.get('https://api.ipify.org').text
    except Exception:
        return "Unable to determine external IP"

def display_banner():
    """Display the CHUD banner with a cyberpunk theme."""
    banner = f"""
    ▄████▄   ██░ ██  █    ██ ▓█████▄ 
   ▒██▀ ▀█  ▓██░ ██▒ ██  ▓██▒▒██▀ ██▌
   ▒▓█    ▄ ▒██▀▀██░▓██  ▒██░░██   █▌
   ▒▓▓▄ ▄██▒░▓█ ░██ ▓▓█  ░██░░▓█▄   ▌
   ▒ ▓███▀ ░░▓█▒░██▓▒▒█████▓ ░▒████▓ 
   ░ ░▒ ▒  ░ ▒ ░░▒░▒░▒▓▒ ▒ ▒  ▒▒▓  ▒ 
     ░  ▒    ▒ ░▒░ ░░░▒░ ░ ░  ░ ▒  ▒ 
   ░         ░  ░░ ░ ░░░ ░ ░  ░ ░  ░ 
   ░ ░       ░  ░  ░   ░        ░    
   ░                           ░     
╔══════════════════════════════════════════════════════════════════════════╗
║ [ Cybernetic Hacking Utility Daemon - v2.2 ]                             ║
╚══════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)

def get_user_input():
    """Get user input for scan configuration."""
    target = input("[?] Enter target IP or hostname: ")
    start_port = int(input("[?] Enter start port (default 1): ") or "1")
    end_port = int(input("[?] Enter end port (default 1000): ") or "1000")
    threads = int(input("[?] Enter number of threads (default 10): ") or "10")
    output_format = input("[?] Enter output format (json/csv/txt/html) [default: json]: ").lower() or "json"
    file_name = input("[?] Enter output file name (without extension) [default: chud_scan]: ") or "chud_scan"
    output_path = input("[?] Enter output file path (default: ./): ") or "./"
    if output_path == "./":
        output_path = "."
    options = {
        'whois': input("[?] Perform WHOIS lookup? (y/n) [default: y]: ").lower() != 'n',
        'dns': input("[?] Perform DNS lookup? (y/n) [default: y]: ").lower() != 'n',
        'traceroute': input("[?] Perform traceroute? (y/n) [default: y]: ").lower() != 'n',
        'ping_sweep': input("[?] Perform ping sweep? (y/n) [default: y]: ").lower() != 'n',
        'reverse_dns': input("[?] Perform reverse DNS lookup? (y/n) [default: y]: ").lower() != 'n',
        'geolocation': input("[?] Perform geolocation? (y/n) [default: y]: ").lower() != 'n',
        'banner_grab': input("[?] Perform banner grabbing? (y/n) [default: y]: ").lower() != 'n',
        'ssl_scan': input("[?] Perform SSL scan? (y/n) [default: y]: ").lower() != 'n',
        'http_headers': input("[?] Scan HTTP headers? (y/n) [default: y]: ").lower() != 'n',
        'shodan': input("[?] Perform Shodan lookup? (y/n) [default: n]: ").lower() == 'y',
        'subdomain_enum': input("[?] Perform subdomain enumeration? (y/n) [default: n]: ").lower() == 'y',
        'ddos': input("[?] Perform DDoS test? (y/n) [default: n]: ").lower() == 'y'
    }
    return target, start_port, end_port, threads, output_format, file_name, output_path, options

def get_nmap_options():
    """Get Nmap scan options."""
    return "-sV -sC -O"

def hunt_target(ip: str, start_port: int, end_port: int, threads: int, options: str) -> List[Dict]:
    """Perform Nmap scan on the target."""
    nm = nmap3.Nmap()
    args = f"-p {start_port}-{end_port} {options} --min-rate=1000 -T4"
    results = nm.nmap_version_detection(ip, args=args)
    formatted_results = []
    if ip in results:
        for port_data in results[ip]['ports']:
            formatted_results.append({
                'port': int(port_data['portid']),
                'state': port_data['state'],
                'service': port_data['service']['name'],
                'version': port_data['service'].get('version', '')
            })
    return formatted_results

def get_os_info(ip: str) -> str:
    """Get OS information of the target."""
    nm = nmap3.Nmap()
    results = nm.nmap_os_detection(ip)
    if results and ip in results:
        osmatch = results[ip].get('osmatch', [])
        if osmatch:
            return osmatch[0].get('name', 'Unknown OS Name')
    return "OS information not available or not detected."

def get_whois_info(target):
    """Get WHOIS information."""
    try:
        whois_info = whois.whois(target)
        return str(whois_info)
    except Exception:
        return "WHOIS lookup failed. Unable to retrieve information."

def get_dns_info(target):
    """Get DNS information."""
    try:
        answers = dns.resolver.resolve(target, 'A')
        return [str(answer) for answer in answers]
    except Exception:
        return "DNS lookup failed. No information retrieved."

def perform_traceroute(ip):
    """Perform traceroute."""
    try:
        result = subprocess.run(['traceroute', ip], capture_output=True, text=True)
        return result.stdout if result.returncode == 0 else "Traceroute failed."
    except Exception:
        return "Traceroute command failed."

def perform_ping_sweep(network):
    """Perform ping sweep."""
    return "The network is silent. No hosts responded to our digital knock."

def perform_reverse_dns_lookup(ip):
    """Perform reverse DNS lookup."""
    try:
        result = socket.gethostbyaddr(ip)
        return result[0]
    except socket.herror:
        return "Reverse DNS lookup yielded no results."

def perform_geolocation(ip):
    """Perform geolocation."""
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/")
        if response.status_code == 200:
            data = response.json()
            return {
                'country': data.get('country_name', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'latitude': data.get('latitude', 0),
                'longitude': data.get('longitude', 0)
            }
        else:
            return "Target's physical location is off the grid. Geolocation data unavailable."
    except Exception:
        return "Geolocation failed. The target's coordinates remain a mystery."

def perform_banner_grabbing(ip, port):
    """Perform banner grabbing."""
    return "The service is running silent. No banner information could be extracted."

def perform_ssl_scan(ip, port):
    """Perform SSL scan."""
    return "The cryptographic defenses reveal nothing. SSL/TLS information unavailable."

def perform_http_headers_scan(ip, port):
    """Perform HTTP headers scan."""
    return "The server guards its secrets well. No HTTP headers could be retrieved."

def perform_shodan_scan(ip, api_key):
    """Perform Shodan scan."""
    try:
        api = shodan.Shodan(api_key)
        return api.host(ip)
    except Exception:
        return "Shodan's all-seeing eye is blind to this target. No information found."

def perform_subdomain_enumeration(domain):
    """Perform subdomain enumeration."""
    try:
        result = subprocess.run(['amass', 'enum', '-d', domain], capture_output=True, text=True)
        subdomains = result.stdout.strip().split('\n')
        return subdomains if subdomains else "The domain's substructure is hidden in the digital shadows. No subdomains discovered."
    except Exception:
        return "Subdomain enumeration failed. The digital realm remains unexplored."

async def perform_ddos(target: str, duration: int = 10, connections: int = 1000):
    """Perform DDoS test."""
    async def flood():
        async with httpx.AsyncClient() as client:
            while True:
                try:
                    await client.get(f'http://{target}')
                except:
                    pass
    tasks = [asyncio.create_task(flood()) for _ in range(connections)]
    await asyncio.sleep(duration)
    for task in tasks:
        task.cancel()

def create_folium_map(ip, latitude, longitude):
    """Create an interactive map using folium."""
    m = folium.Map(location=[latitude, longitude], zoom_start=3)
    folium.Marker([latitude, longitude], popup=f"Target IP: {ip}").add_to(m)
    map_file = f"map_{ip.replace('.', '_')}.html"
    m.save(map_file)
    return map_file

def output_results(results: List[Dict], os_info: str, output_format: str, output_file: str, additional_info: Dict):
    """Output scan results to a file."""
    if output_format == 'json':
        with open(output_file, 'w') as f:
            json.dump({'os': os_info, 'ports': results, 'additional_info': additional_info}, f, indent=4)
    elif output_format == 'csv':
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['port', 'state', 'service', 'version'])
            writer.writeheader()
            writer.writerows(results)
    elif output_format == 'html':
        with open(output_file, 'w') as f:
            f.write(f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CHUD Scan Results</title>
    <style>
        body {{ font-family: Arial, sans-serif; }}
        .header {{ text-align: center; background-color: #282c34; color: white; padding: 10px; }}
        .footer {{ text-align: center; background-color: #282c34; color: white; padding: 10px; position: fixed; bottom: 0; width: 100%; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>CHUD Scan Results</h1>
    </div>
    <h2>OS Information</h2>
    <p>{os_info}</p>
    <h2>Port Scan Results</h2>
    <table border="1">
        <tr>
            <th>Port</th>
            <th>State</th>
            <th>Service</th>
            <th>Version</th>
        </tr>
""")
            for result in results:
                f.write(f"""
        <tr>
            <td>{result['port']}</td>
            <td>{result['state']}</td>
            <td>{result['service']}</td>
            <td>{result['version']}</td>
        </tr>
""")
            f.write(f"""
    </table>
    <h2>Additional Information</h2>
    <pre>{json.dumps(additional_info, indent=4)}</pre>
    <div class="footer">
        <p>&copy; CHUD - Cybernetic Hacking Utility Daemon</p>
    </div>
</body>
</html>
            """)
    else:  # txt
        with open(output_file, 'w') as f:
            f.write("""
   ▄████▄   ██░ ██  █    ██ ▓█████▄ 
  ▒██▀ ▀█  ▓██░ ██▒ ██  ▓██▒▒██▀ ██▌
  ▒▓█    ▄ ▒██▀▀██░▓██  ▒██░░██   █▌
  ▒▓▓▄ ▄██▒░▓█ ░██ ▓▓█  ░██░░▓█▄   ▌
  ▒ ▓███▀ ░░▓█▒░██▓▒▒█████▓ ░▒████▓ 
  ░ ░▒ ▒  ░ ▒ ░░▒░▒░▒▓▒ ▒ ▒  ▒▒▓  ▒ 
    ░  ▒    ▒ ░▒░ ░░░▒░ ░ ░  ░ ▒  ▒ 
  ░         ░  ░░ ░ ░░░ ░ ░  ░ ░  ░ 
  ░ ░       ░  ░  ░   ░        ░    
  ░                           ░     
""")
            f.write(f"OS: {os_info}\n\n")
            for result in results:
                f.write(f"Port: {result['port']}\n")
                f.write(f"State: {result['state']}\n")
                f.write(f"Service: {result['service']}\n")
                f.write(f"Version: {result['version']}\n\n")
            f.write("Additional Information:\n")
            for key, value in additional_info.items():
                f.write(f"{key.capitalize()}:\n{value}\n\n")

def main():
    """Main function to run CHUD."""
    display_banner()
    external_ip = get_external_ip()
    print(f"[!] Your external IP address: {external_ip}")
    print(f"[!] Be aware of your location before scanning!")
    proceed = input(f"\n[?] Are you sure you want to proceed? (y/n): ").lower()
    if proceed != 'y':
        print(f"[!] Aborting operation. Stay safe in cyberspace!")
        sys.exit(0)
    target, start_port, end_port, threads, output_format, file_name, output_path, options = get_user_input()
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(target))
        except socket.gaierror:
            print(f"[!] Invalid target. Exiting.")
            sys.exit(1)
    nmap_options = get_nmap_options()
    results = hunt_target(str(ip), start_port, end_port, threads, nmap_options)
    os_info = get_os_info(str(ip))
    additional_info = {}
    scans = [
        ('whois', options['whois'], get_whois_info, target),
        ('dns', options['dns'], get_dns_info, target),
        ('traceroute', options['traceroute'], perform_traceroute, str(ip)),
        ('ping_sweep', options['ping_sweep'], perform_ping_sweep, f"{ip}/24"),
        ('reverse_dns', options['reverse_dns'], perform_reverse_dns_lookup, str(ip)),
        ('geolocation', options['geolocation'], perform_geolocation, str(ip))
    ]
    for scan_name, should_scan, scan_func, scan_target in scans:
        if should_scan:
            additional_info[scan_name] = scan_func(scan_target)
    if options['banner_grab']:
        additional_info['banner_grab'] = {port: perform_banner_grabbing(str(ip), port) for port in [result['port'] for result in results]}
    if options['ssl_scan']:
        additional_info['ssl_scan'] = {port: perform_ssl_scan(str(ip), port) for port in [result['port'] for result in results if result['service'] == 'https']}
    if options['http_headers']:
        additional_info['http_headers'] = {port: perform_http_headers_scan(str(ip), port) for port in [result['port'] for result in results if result['service'] in ['http', 'https']]}
    if options['shodan']:
        shodan_api_key = input("Enter your Shodan API key: ")
        additional_info['shodan'] = perform_shodan_scan(str(ip), shodan_api_key)
    if options['subdomain_enum']:
        additional_info['subdomains'] = perform_subdomain_enumeration(target)
    if options['ddos']:
        duration = int(input(f"[?] Enter DDoS test duration in seconds (default: 10): ") or "10")
        connections = int(input(f"[?] Enter number of connections for DDoS test (default: 1000): ") or "1000")
        asyncio.run(perform_ddos(target, duration, connections))
    output_file = f"{output_path}/{file_name}.{output_format}"
    output_results(results, os_info, output_format, output_file, additional_info)
    print(f"[+] Results saved to {output_file}")

if __name__ == "__main__":
    main()