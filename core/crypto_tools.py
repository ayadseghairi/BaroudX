import base64
import binascii
import codecs
import hashlib
import os
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import json

HASH_TYPES = {
    32: "MD5",
    40: "SHA1",
    56: "SHA224",
    64: "SHA256",
    96: "SHA384",
    128: "SHA512"
}

def decode_base64(data):
    try:
        return base64.b64decode(data).decode('utf-8')
    except Exception as e:
        return f"[!] Base64 decode error: {e}"

def decode_hex(data):
    try:
        return bytes.fromhex(data).decode('utf-8')
    except Exception as e:
        return f"[!] Hex decode error: {e}"

def decode_rot13(data):
    try:
        return codecs.decode(data, 'rot_13')
    except Exception as e:
        return f"[!] ROT13 decode error: {e}"

def detect_hash_type(hash_str):
    length = len(hash_str)
    return HASH_TYPES.get(length, "Unknown")

def brute_force_hash(hash_str, wordlist_path="/usr/share/wordlists/rockyou.txt"):
    algo = detect_hash_type(hash_str)
    if algo == "Unknown":
        return {"error": "Unknown hash type"}

    hash_func = getattr(hashlib, algo.lower(), None)
    if not hash_func:
        return {"error": f"Hash function for {algo} not found"}

    if not os.path.isfile(wordlist_path):
        return {"error": f"Wordlist not found at {wordlist_path}"}

    try:
        with open(wordlist_path, "r", encoding="latin-1") as f:
            for word in f:
                word = word.strip()
                if hash_func(word.encode()).hexdigest() == hash_str:
                    return {"cracked": word, "method": algo}
    except Exception as e:
        return {"error": str(e)}

    return {"cracked": None, "status": "Not found"}

def aes_encrypt(plaintext, key):
    try:
        cipher = AES.new(key.encode(), AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        return base64.b64encode(cipher.iv + ct_bytes).decode()
    except Exception as e:
        return f"[!] AES encryption error: {e}"

def aes_decrypt(ciphertext, key):
    try:
        raw = base64.b64decode(ciphertext)
        iv = raw[:AES.block_size]
        ct = raw[AES.block_size:]
        cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode()
    except Exception as e:
        return f"[!] AES decryption error: {e}"

def rsa_encrypt(plaintext, pubkey_path):
    try:
        key = RSA.import_key(open(pubkey_path).read())
        cipher = PKCS1_OAEP.new(key)
        return base64.b64encode(cipher.encrypt(plaintext.encode())).decode()
    except Exception as e:
        return f"[!] RSA encryption error: {e}"

def rsa_decrypt(ciphertext, privkey_path):
    try:
        key = RSA.import_key(open(privkey_path).read())
        cipher = PKCS1_OAEP.new(key)
        return cipher.decrypt(base64.b64decode(ciphertext)).decode()
    except Exception as e:
        return f"[!] RSA decryption error: {e}"

def save_results(data):
    os.makedirs("output", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"output/crypto-{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"[+] Results saved to {filename}")
    return filename

def run(target, wordlist=None):
    print(f"[CryptoTools] Running on target: {target}")

    results = {
        "base64_decoded": decode_base64(target),
        "hex_decoded": decode_hex(target),
        "rot13_decoded": decode_rot13(target),
        "hash_type": detect_hash_type(target),
    }

    if results["hash_type"] != "Unknown":
        results["hash_crack"] = brute_force_hash(target, wordlist_path=wordlist or "/usr/share/wordlists/rockyou.txt")

    save_results(results)
