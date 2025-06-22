# 🔥 BaroudX

BaroudX is a powerful, modular cybersecurity toolkit designed for advanced penetration testing, CTF challenges, and ethical hacking. It includes support for cryptography, binary/memory analysis, network scanning, DDoS simulation, and more.

> ⚠️ **Disclaimer:** This tool is for **authorized testing** and educational purposes **only**. Unauthorized use is **illegal**.

---

## 📦 Features

- 🔐 Crypto tools (hash cracking, AES, RSA, ROT13, Base64, Hex)
- 🧠 Memory & binary analysis (Volatility3, Capstone, LIEF, YARA)
- 🌐 Network scanner (ARP/Nmap, OS detection, ARP spoof detection)
- 📸 Webcam scanner (USB + IP detection)
- 💥 Advanced DDoS module (HTTP/TCP/UDP)
- 🧠 Automated hash detection
- 📁 Output stored in structured JSON
- 📊 Network visualization with `networkx`

---

## 🛠️ Installation

### 1. Clone the repo

```bash
git clone https://github.com/ayadseghairi/BaroudX.git
cd BaroudX
```

### 2. Run the installer

```bash
chmod +x install.sh
sudo ./install.sh
```

This will:

- Install all Python packages
- Setup `useragents.txt` with real User-Agents
- Generate sample YARA rules and RSA keys

---


### 🔐 Environment Configuration (`.env` file)

The tool uses a `.env` file to load sensitive environment variables. The following variable must be set before using certain modules (like Shodan enumeration):

```env
SHODAN_API_KEY=your_shodan_api_key_here
```

#### Steps:

1. Create a `.env` file in the root directory of the project.
2. Paste your Shodan API key as shown above.
3. You can get a free Shodan API key by registering at:
   🔗 [https://account.shodan.io/register](https://account.shodan.io/register)

**⚠️ Do not share your `.env` file or expose your API key publicly.**



## ⚙️ Usage

```bash
sudo -E PYTHONPATH="$PYTHONPATH" python3 main.py --module <module> --target <target> [options]
```

### 🧩 Available Modules

| Module    | Description                                  |
| --------- | -------------------------------------------- |
| `crypto`  | Crypto tools (hash cracking, AES, RSA, etc)  |
| `memory`  | Binary / memory analysis                     |
| `network` | Scan network, sniff packets, detect spoofing |
| `webcam`  | Detect and access webcams (USB/IP)           |
| `ddos`    | Simulate a DDoS attack (for lab use only)    |

---

## 🔐 Crypto Example

```bash
sudo python3 main.py --module crypto --target "5f4dcc3b5aa765d61d8327deb882cf99"
```

Optional: You can place `rockyou.txt` in `/usr/share/wordlists/` or change path in `crypto_tools.py`.

---

## 🧠 Memory Analysis Example

```bash
sudo python3 main.py --module memory --target ./dump.mem
```

Supports ELF/PE/memory images, `.pyc`, shellcode.

---

## 🌐 Network Scanning Example

```bash
sudo python3 main.py --module network --nmap-scan --detect-os --packets 200
```

This will:

- Detect ARP spoofing
- Scan LAN devices
- Detect OS (Nmap)
- Sniff 200 packets
- Save results and visualization

---

## 📸 Webcam Scanner

```bash
sudo python3 main.py --module webcam
```

Detects USB and IP cameras, captures one frame from each.

---

## 💥 DDoS Simulation

> ⚠️ Use in CTF labs or test environments **only**.

```bash
sudo python3 main.py --module ddos --target https://example.com --ddos-type http --threads 100 --duration 30
```

Supported attack types:

- `http` (uses `requests` with fake headers)
- `tcp`
- `udp`

---

## 📁 Output

All results are saved automatically in the `output/` directory with timestamps:

- `crypto-*.json`
- `memory-*.json`
- `network-*.json`
- `ddos-*.json` + `.pcap` + `.png` if applicable

---

## 🔧 File Structure

```
BaroudX/
├── core/
│   ├── crypto_tools.py
│   ├── memory_tools.py
│   ├── network_tools.py
│   ├── webcam_tools.py
│   ├── ddos.py
│   └── ...
├── config/
│   ├── useragents.txt
│   ├── yara_rules.yar
│   ├── rsa_public.pem
│   └── rsa_private.pem
├── output/
├── install.sh
├── main.py
└── README.md
```

---

## ✍️ Author

**Ayad Seghairi**
🇩🇿 Cybersecurity Developer • Offensive Security Enthusiast
🔗 [GitHub](https://github.com/ayadseghairi) • [LinkedIn](https://www.linkedin.com/in/ayad-seghiri)

---

## 🛡️ Disclaimer

This tool is provided **as-is** and is intended only for **legal use** in testing environments or with explicit permission.
By using BaroudX, you agree to **comply with all applicable laws** and regulations.
