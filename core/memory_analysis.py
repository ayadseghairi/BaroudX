import os
import subprocess
import json
from datetime import datetime
from pathlib import Path
import lief
import yara
import uncompyle6
import binascii
import capstone


def run(target):
    print(f"[Memory Analysis] Running on target: {target}")

    if not os.path.exists(target):
        print("[!] File does not exist.")
        return

    file_type = auto_detect_file_type(target)

    if file_type == "memory_image":
        results = analyze_memory_image(target)
    elif file_type == "binary":
        results = analyze_binary(target)
    elif file_type == "python_bytecode":
        results = analyze_python_bytecode(target)
    elif file_type == "shellcode":
        results = analyze_shellcode(target)
    else:
        print("[!] Unsupported or unknown file type.")
        return

    save_results(results)


def auto_detect_file_type(path):
    try:
        with open(path, 'rb') as f:
            header = f.read(20)
            if header.startswith(b'MZ') or header.startswith(b'\x7fELF'):
                return "binary"
            elif b'VolatilityService' in header or b'Linux' in header:
                return "memory_image"
            elif path.endswith(".pyc"):
                return "python_bytecode"
            elif len(header) < 10:
                return "shellcode"
    except Exception as e:
        print(f"[!] Detection error: {e}")
    return "unknown"


def analyze_memory_image(path):
    print("[*] Analyzing memory image using Volatility3")
    try:
        result = subprocess.check_output([
            "volatility3", "-f", path, "windows.info"
        ]).decode(errors='ignore')
        return {"type": "memory_image", "volatility_info": result}
    except Exception as e:
        return {"error": f"Volatility failed: {str(e)}"}


def analyze_binary(path):
    print("[*] Analyzing binary using LIEF, YARA and Capstone")
    results = {"type": "binary"}

    try:
        binary = lief.parse(path)
        results["binary_info"] = {
            "format": str(binary.format),
            "arch": str(binary.header.machine_type),
            "entrypoint": hex(binary.entrypoint)
        }
    except Exception as e:
        results["lief_error"] = str(e)

    try:
        rules = yara.compile(filepath="config/yara_rules.yar")
        matches = rules.match(path)
        results["yara_matches"] = [str(m) for m in matches]
    except Exception as e:
        results["yara_error"] = str(e)

    try:
        with open(path, "rb") as f:
            code = f.read(64)
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        disasm = [f"0x{i.address:x}: {i.mnemonic} {i.op_str}" for i in md.disasm(code, 0x0)]
        results["disassembly_preview"] = disasm
    except Exception as e:
        results["capstone_error"] = str(e)

    return results


def analyze_python_bytecode(path):
    print("[*] Decompiling Python bytecode")
    try:
        output = subprocess.check_output(["uncompyle6", path]).decode(errors='ignore')
        return {"type": "python_bytecode", "source_code": output}
    except Exception as e:
        return {"error": f"Uncompyle6 failed: {str(e)}"}


def analyze_shellcode(path):
    print("[*] Analyzing shellcode")
    try:
        with open(path, 'rb') as f:
            raw = f.read()
        hex_rep = binascii.hexlify(raw).decode()
        return {
            "type": "shellcode",
            "length": len(raw),
            "hex": hex_rep[:100] + ("..." if len(hex_rep) > 100 else "")
        }
    except Exception as e:
        return {"error": f"Shellcode read failed: {str(e)}"}


def save_results(results):
    os.makedirs("output", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"output/memory-{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)
    print(f"[+] Results saved to {filename}")
