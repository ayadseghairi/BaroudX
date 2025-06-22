#!/usr/bin/env python3

import os
import sys
import site
from pathlib import Path

# أضف مجلدات مكتبات المستخدم إلى sys.path إذا لم تكن موجودة
user_site = str(Path.home() / ".local/lib/python3/site-packages")
if user_site not in sys.path:
    sys.path.append(user_site)

import argparse
import logging
from dotenv import load_dotenv
def print_banner():
    banner = r"""
        ▄▄▄▄▄▄▄▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄         ▄  ▄▄▄▄▄▄▄▄▄▄  ▄       ▄ 
        ▐░░░░░░░░░░▌ ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░░░░░░░░░░▌▐░▌     ▐░▌
        ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░▌       ▐░▌▐░█▀▀▀▀▀▀▀█░▌▐░▌   ▐░▌ 
        ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌ ▐░▌ ▐░▌  
        ▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌  ▐░▐░▌   
        ▐░░░░░░░░░░▌ ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌   ▐░▌    
        ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀█░█▀▀ ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌  ▐░▌░▌   
        ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌     ▐░▌  ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌ ▐░▌ ▐░▌  
        ▐░█▄▄▄▄▄▄▄█░▌▐░▌       ▐░▌▐░▌      ▐░▌ ▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌▐░▌   ▐░▌ 
        ▐░░░░░░░░░░▌ ▐░▌       ▐░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░▌▐░▌     ▐░▌
        ▀▀▀▀▀▀▀▀▀▀   ▀         ▀  ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀  ▀       ▀ 
                                                                                                
                        Cyber Vuln Analyzer - Offensive Security Toolkit
                    Developed by: Ayad Seghairi  |  github.com/ayadseghairi
  """
    print(banner)

# تحميل متغيرات البيئة
load_dotenv()

# إعداد سجل الأحداث
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    filename='logs/execution.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# استيراد جميع الوحدات
from core import recon, network, exploit, crypto_tools, memory_analysis, webcam , ddos

# تنفيذ الوحدة المطلوبة
def run_module(module, target, args):
    logging.info(f"Running module: {module} on target: {target}")

    if module == "recon":
        recon.run(target)
    elif module == "network":
        network.run(target, args, use_nmap=args.nmap_scan, detect_os=args.detect_os)
    elif module == "exploit":
        exploit.run(
            target,
            usernames=args.usernames,
            passwords=args.passwords
        )
    elif module == "crypto":
        crypto_tools.run(target, wordlist=args.wordlist)
    elif module == "memory":
        memory_analysis.run(target)
    elif module == "webcam":
        webcam.run(target)
    elif module == "ddos":
        
        ddos.run(target, args)

    else:
        print("[!] Invalid module name.")
        sys.exit(1)

# الوظيفة الرئيسية
def main():
    print_banner()
    logging.info("Cyber Vuln Analyzer started.")
    parser = argparse.ArgumentParser(description="Cyber Vuln Analyzer - Offensive Security Toolkit")

    # الخيارات العامة
    parser.add_argument('--target', required=True, help='Target IP/domain/file depending on module')
    parser.add_argument('--module', required=True, help='Module to run: recon | network | exploit | crypto | memory | webcam')

    # network module
    parser.add_argument('--interface', help='Network interface (e.g., eth0, wlan0) [for network module]')
    parser.add_argument('--packets', type=int, help='Number of packets to sniff [for network module]')
    parser.add_argument('--nmap-scan', action='store_true', help='Use nmap to scan ports [network module]')
    parser.add_argument('--detect-os', action='store_true', help='Use nmap -O to detect OS [network module]')

    # exploit module
    parser.add_argument('--usernames', help='Comma-separated usernames or path to file')
    parser.add_argument('--passwords', help='Comma-separated passwords or path to file')

    # crypto module
    parser.add_argument('--wordlist', help='Path to wordlist for hash cracking [crypto module]')

    parser.add_argument('--ddos-type', choices=['tcp', 'udp', 'http'], help='Type of DDoS attack [ddos module]')
    parser.add_argument('--port', type=int, help='Port to target [default: 80]')
    parser.add_argument('--duration', type=int, help='Attack duration in seconds [default: 30]')
    parser.add_argument('--threads', type=int, help='Number of threads [default: 50]')


    args = parser.parse_args()

    print(f"[+] Target: {args.target}")
    print(f"[+] Module: {args.module}")

    run_module(args.module.lower(), args.target, args)

# نقطة البداية
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Unhandled exception: {e}")
        print(f"[!] Error: {e}")
        sys.exit(1)
