import os
import sys
import json
import subprocess
import scapy.all as scapy
import pyshark
import psutil
import socket
import nmap
from datetime import datetime
from collections import Counter
import networkx as nx
import matplotlib.pyplot as plt
from scapy.all import ARP, arping
import netifaces

def get_network_cidr(interface="eth0"):
    try:
        addrs = netifaces.ifaddresses(interface)
        ip_info = addrs[netifaces.AF_INET][0]
        ip = ip_info['addr']
        netmask = ip_info['netmask']
        cidr = sum([bin(int(x)).count('1') for x in netmask.split('.')])
        return f"{ip}/{cidr}"
    except Exception as e:
        print(f"[!] Failed to get network range: {e}")
        return "192.168.1.0/24"

def get_available_interfaces():
    try:
        output = subprocess.check_output(["tshark", "-D"], timeout=5).decode()
        interfaces = []
        for line in output.strip().split("\n"):
            parts = line.split(". ", 1)
            if len(parts) == 2:
                interfaces.append(parts[1].split(" ")[0])
        return interfaces
    except Exception as e:
        print(f"[!] Failed to list interfaces: {e}")
        return []

def get_default_interface():
    interfaces = psutil.net_if_addrs()
    for name, addrs in interfaces.items():
        if name == "lo":
            continue
        for addr in addrs:
            if addr.family == socket.AF_INET:
                return name
    return "eth0"

def check_interface_exists(interface):
    return interface in get_available_interfaces()

def check_interface_permission(interface):
    try:
        subprocess.run(["tshark", "-i", interface, "-c", "1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=True)
        return True
    except subprocess.CalledProcessError:
        return False
    except FileNotFoundError:
        print("[!] tshark is not installed.")
        sys.exit(1)

def port_scan(ip, detect_os=False):
    try:
        scanner = nmap.PortScanner()
        args = '-T4 -F'
        if detect_os:
            args += ' -O'
        scanner.scan(ip, arguments=args)
        ports = {}
        os_info = None
        if ip in scanner.all_hosts():
            for port in scanner[ip].get('tcp', {}):
                state = scanner[ip]['tcp'][port]['state']
                name = scanner[ip]['tcp'][port].get('name', '')
                ports[port] = {"state": state, "service": name}
            if detect_os and 'osmatch' in scanner[ip]:
                matches = scanner[ip]['osmatch']
                if matches:
                    os_info = matches[0].get('name')
        return {"ports": ports, "os": os_info} if detect_os else ports
    except Exception as e:
        return {"error": str(e)}

def is_private_ip(ip):
    try:
        return ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.")
    except:
        return False

def scan_network(interface="eth0", use_nmap=False, detect_os=False):
    print(f"[+] Scanning network on interface: {interface}")
    network_range = get_network_cidr(interface)
    arp_request = scapy.ARP(pdst=network_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    clients = []
    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        client_info = {"ip": ip, "mac": mac}
        if use_nmap and is_private_ip(ip):
            print(f"[+] Scanning ports on {ip} with nmap {'and detecting OS' if detect_os else ''}")
            scan_result = port_scan(ip, detect_os=detect_os)
            if detect_os:
                client_info["open_ports"] = scan_result.get("ports", {})
                if scan_result.get("os"):
                    client_info["os"] = scan_result["os"]
            else:
                client_info["open_ports"] = scan_result
        clients.append(client_info)
    return clients

def sniff_packets(interface="eth0", packet_count=100, save_pcap=True):
    print(f"[+] Sniffing {packet_count} packets on {interface}")
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    os.makedirs("output", exist_ok=True)
    pcap_file = f"output/capture_{timestamp}.pcap" if save_pcap else None

    protocol_counter = Counter()
    packets_info = []

    try:
        capture = pyshark.LiveCapture(interface=interface, output_file=pcap_file)
        capture.sniff(packet_count=packet_count)
    except Exception as e:
        print(f"[!] Error during packet capture: {e}")
        return [{"error": str(e)}], {}, None

    for pkt in capture:
        try:
            if not hasattr(pkt, 'ip'):
                continue
            proto = pkt.highest_layer
            protocol_counter[proto] += 1
            info = {
                "src": pkt.ip.src,
                "dst": pkt.ip.dst,
                "protocol": proto,
                "length": pkt.length
            }
            if "DNS" in pkt:
                info["dns_query"] = getattr(pkt.dns, "qry_name", None)
            if "HTTP" in pkt:
                if hasattr(pkt.http, "cookie"):
                    info["http_cookie"] = pkt.http.cookie
                if hasattr(pkt.http, "authorization"):
                    info["http_auth"] = pkt.http.authorization
            packets_info.append(info)
        except Exception:
            continue

    if pcap_file and not os.path.exists(pcap_file):
        print(f"[!] Warning: Expected pcap file '{pcap_file}' was not created.")
        pcap_file = None

    return packets_info, dict(protocol_counter), pcap_file

def save_to_file(data, module_name):
    os.makedirs("output", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"output/{module_name}-{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"[+] Output saved to {filename}")
    return filename

def visualize_network_topology(devices, output_path):
    G = nx.Graph()
    gateway_node = "Gateway"
    G.add_node(gateway_node)
    for device in devices:
        ip = device.get("ip")
        mac = device.get("mac")
        label = f"{ip}\n{mac}"
        G.add_node(label)
        G.add_edge(gateway_node, label)
        ports = device.get("open_ports", {})
        for port, info in ports.items():
            port_label = f"{ip}:{port}\n{info.get('service', '')}"
            G.add_node(port_label)
            G.add_edge(label, port_label)
    pos = nx.spring_layout(G, seed=42)
    plt.figure(figsize=(12, 8))
    nx.draw(G, pos, with_labels=True, node_color='skyblue', edge_color='gray', node_size=2000, font_size=9)
    plt.title("Network Topology Visualization")
    plt.tight_layout()
    image_path = output_path.replace(".json", ".png")
    plt.savefig(image_path)
    plt.show()

def detect_arp_spoofing(network="192.168.1.0/24"):
    print("[*] Checking for ARP spoofing (scapy)...")
    try:
        answered, _ = arping(network, timeout=2, verbose=False)
        ip_mac_map = {}
        suspicious = []
        for snd, rcv in answered:
            ip = rcv.psrc
            mac = rcv.hwsrc
            if ip not in ip_mac_map:
                ip_mac_map[ip] = set()
            ip_mac_map[ip].add(mac)
        for ip, macs in ip_mac_map.items():
            if len(macs) > 1:
                suspicious.append((ip, list(macs)))
        if suspicious:
            print("\033[91m[!!] Potential ARP Spoofing Detected!\033[0m")
            for ip, macs in suspicious:
                print(f"\033[91m - IP {ip} has multiple MACs: {', '.join(macs)}\033[0m")
            return True
        else:
            print("[+] No ARP spoofing detected.")
            return False
    except Exception as e:
        print(f"[!] ARP spoofing detection error: {e}")
        return False

def run(target, args, use_nmap=False, detect_os=False):
    print("[*] Running Network Module...")
    interface = args.interface if args.interface else get_default_interface()
    packet_count = args.packets if args.packets else 100
    if detect_arp_spoofing():
        print("\n\033[91m[!] ARP spoofing attack detected. Aborting further scans for safety.\033[0m")
        sys.exit(1)
    if not args.interface:
        print(f"[+] Auto-detected interface: {interface}")
    print(f"[+] Using interface: {interface}")
    print(f"[+] Capturing {packet_count} packets...")
    if not check_interface_exists(interface):
        print(f"[!] Interface '{interface}' not found.")
        available = get_available_interfaces()
        print("\n[+] Available interfaces:")
        for i, iface in enumerate(available, 1):
            print(f"  {i}. {iface}")
        print("\n[→] Please choose a valid interface using --interface")
        sys.exit(1)
    if not check_interface_permission(interface):
        print(f"[!] Permission denied: Cannot capture on interface '{interface}'")
        print("→ Either run with sudo or ensure dumpcap is configured.\n")
        sys.exit(1)
    network_clients = scan_network(interface, use_nmap=use_nmap, detect_os=detect_os)
    sniffed_packets, protocol_stats, pcap_path = sniff_packets(interface, packet_count)
    results = {
        "network_devices": network_clients,
        "sniffed_packets": sniffed_packets if sniffed_packets else [{"warning": "No packets captured"}],
        "protocol_stats": protocol_stats,
        "pcap_saved_to": pcap_path if pcap_path else "not created"
    }
    json_file = save_to_file(results, "network")
    visualize_network_topology(network_clients, json_file)
