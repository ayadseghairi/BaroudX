import os
import json
import subprocess
from datetime import datetime
from colorama import Fore, Style

# Optional dependencies
try:
    import magic
except ImportError:
    magic = None

# ------------------------
# Color Output Utilities
# ------------------------
def success(msg):
    print(Fore.GREEN + "[+] " + msg + Style.RESET_ALL)

def error(msg):
    print(Fore.RED + "[!] " + msg + Style.RESET_ALL)

def warn(msg):
    print(Fore.YELLOW + "[!] " + msg + Style.RESET_ALL)

def info(msg):
    print(Fore.CYAN + "[*] " + msg + Style.RESET_ALL)

# ------------------------
# Timestamp Filename
# ------------------------
def timestamped_filename(prefix, ext=".json"):
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{prefix}-{timestamp}{ext}"

# ------------------------
# Save to JSON
# ------------------------
def save_json(data, filename, folder="output"):
    os.makedirs(folder, exist_ok=True)
    filepath = os.path.join(folder, filename)
    try:
        with open(filepath, "w") as f:
            json.dump(data, f, indent=4)
        success(f"Saved: {filepath}")
    except Exception as e:
        error(f"Failed to save JSON: {e}")
    return filepath

# ------------------------
# Run Shell Command
# ------------------------
def run_command(cmd):
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
        return output
    except subprocess.CalledProcessError:
        error(f"Command failed: {' '.join(cmd)}")
        return ""
    except Exception as e:
        error(f"Unexpected error: {e}")
        return ""

# ------------------------
# File Type Detection
# ------------------------
def get_file_type(filepath):
    if not magic:
        return "python-magic not installed"
    try:
        return magic.from_file(filepath)
    except Exception as e:
        return f"Error: {e}"

# ------------------------
# Validate IP Address
# ------------------------
def is_valid_ip(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except:
        return False

# ------------------------
# Extract Strings from Binary
# ------------------------
def extract_strings_from_binary(path):
    try:
        result = subprocess.check_output(["strings", path]).decode()
        return result.splitlines()
    except Exception as e:
        error(f"Could not extract strings: {e}")
        return []

# ------------------------
# OUI Lookup from MAC
# ------------------------
def load_oui_database(path="config/oui.txt"):
    db = {}
    try:
        with open(path, "r") as f:
            for line in f:
                if line.strip() and "\t" in line:
                    prefix, vendor = line.strip().split("\t", 1)
                    db[prefix.upper()] = vendor.strip()
    except Exception as e:
        error(f"Failed to load OUI DB: {e}")
    return db

def lookup_vendor(mac, oui_db):
    if not mac:
        return "Unknown"
    prefix = mac.upper().replace(":", "")[:6]
    return oui_db.get(prefix, "Unknown Vendor")

# ------------------------
# Entrypoint
# ------------------------
def run(target):
    print(f"[utils] Running on target: {target}")
    print("[!] This module provides utility functions and is not intended for standalone execution.")
