import os
import cv2
import subprocess
import socket
import threading
from time import sleep
from scapy.all import ARP, Ether, srp
from datetime import datetime


# قراءة بيانات OUI لتحديد نوع الجهاز من MAC
def load_oui_data(path="config/oui.txt"):
    vendor_map = {}
    if not os.path.isfile(path):
        return vendor_map

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "(base 16)" in line:
                parts = line.strip().split("(base 16)")
                if len(parts) == 2:
                    mac_prefix = parts[0].strip().replace("-", ":").upper()
                    vendor = parts[1].strip()
                    vendor_map[mac_prefix] = vendor
    return vendor_map


# تحديد ما إذا كان MAC يعود لكاميرا معروفة
def is_ip_camera(mac, vendor_map):
    prefix = mac.upper()[:8]
    return any(kw in vendor_map.get(prefix, "").lower() for kw in ["hikvision", "axis", "dahua", "ubiquiti", "sony", "cisco", "mobotix", "bosch", "netvue", "tp-link"])


def detect_local_webcams(max_devices=10):
    """فحص الكاميرات المحلية (USB)"""
    print("[+] Checking local webcams...")
    available = []
    for i in range(max_devices):
        cap = cv2.VideoCapture(i)
        if cap is not None and cap.read()[0]:
            print(f"  [✔] Local webcam detected at index {i}")
            available.append(i)
        cap.release()
    return available


def scan_ip_cameras(network="192.168.1.0/24", oui_path="config/oui.txt"):
    """مسح الشبكة لاكتشاف كاميرات IP عبر ARP"""
    print("[+] Scanning network for IP cameras...")
    vendor_map = load_oui_data(oui_path)
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    ans, _ = srp(request, timeout=2, verbose=0)
    devices = []
    for _, rcv in ans:
        ip = rcv.psrc
        mac = rcv.hwsrc
        if is_ip_camera(mac, vendor_map):
            print(f"  [✔] Possible IP camera found: {ip} ({mac})")
            devices.append({"ip": ip, "mac": mac, "vendor": vendor_map.get(mac[:8].upper(), "Unknown")})
    return devices


def try_open_camera(index_or_url):
    """فتح كاميرا محلية أو IP"""
    try:
        cap = cv2.VideoCapture(index_or_url)
        if cap.isOpened():
            print(f"  [✔] Camera stream accessible: {index_or_url}")
            ret, frame = cap.read()
            if ret:
                timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                filename = f"output/cam_{str(index_or_url).replace(':', '_')}_{timestamp}.jpg"
                cv2.imwrite(filename, frame)
                print(f"    [💾] Frame saved: {filename}")
            cap.release()
        else:
            print(f"  [✖] Failed to open camera: {index_or_url}")
    except Exception as e:
        print(f"  [!] Error: {e}")


def run(target_network="192.168.1.0/24"):
    print(f"[webcam] Running on target network: {target_network}")
    os.makedirs("output", exist_ok=True)

    # 1. كاميرات USB المحلية
    local_cams = detect_local_webcams()

    # 2. كاميرات IP على الشبكة
    ip_cams = scan_ip_cameras(network=target_network)

    # 3. محاولة فتح جميع الكاميرات
    print("\n[+] Attempting to access all detected cameras...")

    threads = []
    for cam in local_cams:
        t = threading.Thread(target=try_open_camera, args=(cam,))
        t.start()
        threads.append(t)

    for cam in ip_cams:
        rtsp_url = f"rtsp://{cam['ip']}/"  # قابل للتخصيص حسب الشركة
        t = threading.Thread(target=try_open_camera, args=(rtsp_url,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("[✓] Camera analysis completed.")
