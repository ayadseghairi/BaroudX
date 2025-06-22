#!/bin/bash

echo "[*] Starting installation of Cyber Security Toolkit requirements..."
echo

# Detect distribution
if [ -f /etc/debian_version ]; then
    DISTRO="debian"
elif [ -f /etc/arch-release ]; then
    DISTRO="arch"
elif [ -f /etc/fedora-release ]; then
    DISTRO="fedora"
else
    echo "[!] Unsupported Linux distribution."
    exit 1
fi

echo "[+] Detected distribution: $DISTRO"
sleep 1

echo "[*] Installing system dependencies..."

if [ "$DISTRO" = "debian" ]; then
    sudo apt update
    sudo apt install -y tshark nmap yara python3 python3-pip python3-venv volatility3 \
        radare2 python3-capstone python3-lief python3-pycryptodome uncompyle6 git \
        build-essential libpcap-dev

elif [ "$DISTRO" = "arch" ]; then
    sudo pacman -Syu --noconfirm
    sudo pacman -S --noconfirm wireshark-qt nmap yara python python-pip python-virtualenv \
        radare2 python-capstone python-lief python-pycryptodome uncompyle6 git \
        base-devel libpcap

elif [ "$DISTRO" = "fedora" ]; then
    sudo dnf install -y wireshark nmap yara python3 python3-pip python3-virtualenv \
        radare2 python3-capstone python3-lief python3-pycryptodome python3-uncompyle6 \
        git gcc make libpcap-devel
fi

echo "[✓] System tools installed."

echo "[*] Installing Python libraries from requirements.txt..."
pip3 install --upgrade pip
pip3 install -r requirements.txt

# Download rockyou.txt wordlist if not present
if [ ! -f /usr/share/wordlists/rockyou.txt ]; then
    echo "[!] rockyou.txt not found. Downloading..."
    sudo mkdir -p /usr/share/wordlists
    curl -L -o /usr/share/wordlists/rockyou.txt.gz https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
    gunzip /usr/share/wordlists/rockyou.txt.gz
    echo "[+] rockyou.txt downloaded and extracted."
fi
YARA_RULES="config/yara_rules.yar"
if [[ ! -f "$YARA_RULES" ]]; then
  echo -e "\n\e[1;33m[*] Creating default YARA rules...\e[0m"
  cat <<EOF > "$YARA_RULES"
rule Suspicious_HTTP
{
    strings:
        $s1 = "cmd.exe"
        $s2 = "powershell"
        $s3 = "curl "
        $s4 = "wget "
        $s5 = "/bin/sh"

    condition:
        1 of ($s*)
}
EOF
  echo -e "\e[1;32m[✓] YARA rules created.\e[0m"
fi

# 7. Generate RSA keys if not exists
RSA_PRIV="config/private.pem"
RSA_PUB="config/public.pem"
if [[ ! -f "$RSA_PRIV" || ! -f "$RSA_PUB" ]]; then
  echo -e "\n\e[1;33m[*] Generating RSA key pair...\e[0m"
  openssl genrsa -out "$RSA_PRIV" 2048
  openssl rsa -in "$RSA_PRIV" -pubout -out "$RSA_PUB"
  echo -e "\e[1;32m[✓] RSA key pair created.\e[0m"
fi

echo "[✓] All requirements installed successfully."
