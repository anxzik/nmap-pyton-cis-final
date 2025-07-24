#Landing for my Python NMAP project
import nmap3
import netifaces
import ipaddress
import os
from datetime import datetime


# Initialize NmapScanTechniques
nm = nmap3.NmapScanTechniques()

# File paths for IP storage
IP_FILE = "ip.txt"
IP_HISTORY_FILE = "ip_history.txt"

# Default target IP
DEFAULT_TARGET_IP = "127.0.0.1" # You can change this default IP

def get_network_info():
    """Gathers and returns network interface information including IPs and gateways."""
    network_info = {}
    interfaces = netifaces.interfaces()

    for iface in interfaces:
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            ipv4_info = addrs[netifaces.AF_INET]
            network_info[iface] = {
                "ipv4_addresses": [addr['addr'] for addr in ipv4_info if 'addr' in addr],
                "netmasks": [addr['netmask'] for addr in ipv4_info if 'netmask' in addr]
            }
            # Try to get gateway
            gws = netifaces.gateways()
            if 'default' in gws and netifaces.AF_INET in gws['default']:
                gateway_ip = gws['default'][netifaces.AF_INET][0]
                network_info[iface]["gateway"] = gateway_ip
    return network_info

def get_suggested_ips():
    """Generates a list of suggested IPs based on network information."""
    suggestions = []
    net_info = get_network_info()

    for iface, data in net_info.items():
        for ip in data.get("ipv4_addresses", []):
            try:
                # Add the interface's own IP
                suggestions.append(ip)
                # If it's a private IP, suggest the network address
                ip_obj = ipaddress.ip_interface(f"{ip}/{data['netmasks'][0]}")
                network_address = str(ip_obj.network.network_address)
                if network_address not in suggestions and not ipaddress.ip_address(network_address).is_loopback:
                    suggestions.append(network_address)
            except (ValueError, IndexError):
                pass # Handle cases where netmask might be missing or invalid

        if "gateway" in data and data["gateway"] not in suggestions:
            suggestions.append(data["gateway"])

    # Add common local IPs if not already present
    if "127.0.0.1" not in suggestions:
        suggestions.append("127.0.0.1")
    if "localhost" not in suggestions:
        suggestions.append("localhost")

    # Remove duplicates and sort
    return sorted(list(set(suggestions)))

def set_default_target(ip_address):
    """
    Saves the input IP address to ip.txt and maintains a history in ip_history.txt.
    """
    global DEFAULT_TARGET_IP

    # Read current ip.txt content if it exists
    current_ip_content = ""
    if os.path.exists(IP_FILE):
        with open(IP_FILE, 'r') as f:
            current_ip_content = f.read().strip()

    # If there was content in ip.txt, append it to ip_history.txt
    if current_ip_content:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(IP_HISTORY_FILE, 'a') as f:
            f.write(f"{timestamp}: {current_ip_content}\n")

    # Overwrite ip.txt with the new IP address
    with open(IP_FILE, 'w') as f:
        f.write(ip_address)

    DEFAULT_TARGET_IP = ip_address
    print(f"Default target IP updated to: {DEFAULT_TARGET_IP}")


def greeting():
    global DEFAULT_TARGET_IP
    print("Hello, Welcome to my NMAP Scanner!")

    # Load default IP from file if it exists
    if os.path.exists(IP_FILE):
        with open(IP_FILE, 'r') as f:
            file_ip = f.read().strip()
            if file_ip:
                DEFAULT_TARGET_IP = file_ip
    
    print(f"Current default target IP: {DEFAULT_TARGET_IP}")

    print("\nHere are some suggested target IPs based on your network configuration:")
    suggested_ips = get_suggested_ips()
    for i, ip in enumerate(suggested_ips):
        print(f"{i+1}. {ip}")

    while True:
        user_input = input(f"\nEnter a target IP address (e.g., 127.0.0.1) or select a number from the suggestions above (1-{len(suggested_ips)}): ").strip()
        if user_input.isdigit() and 1 <= int(user_input) <= len(suggested_ips):
            selected_ip = suggested_ips[int(user_input) - 1]
            set_default_target(selected_ip)
            break
        elif user_input:
            set_default_target(user_input)
            break
        else:
            print("Invalid input. Please enter a valid IP or select a number.")

    print(f"\nDefault target IP set to: {DEFAULT_TARGET_IP}")
    print("\nYou can now perform scans using the functions:")
    print("  - perform_syn_scan()")
    print("  - perform_tcp_scan()")
    print("  - perform_fin_scan()")
    print("\nExample: results = perform_syn_scan()")
    print("         print(results)")
