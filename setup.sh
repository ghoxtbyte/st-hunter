#!/bin/bash
echo "[+] Starting setup for ultimate_hunt.sh..."
apt update && sudo apt upgrade -y || { echo "[-] Apt failed"; exit 1; }
apt install -y python3-pip python3-venv git curl wget build-essential dnsutils || { echo "[-] Install failed"; exit 1; }
dpkg -l | grep golang && sudo apt remove golang -y
rm -rf /usr/lib/go-* /usr/local/go
wget -q https://go.dev/dl/go1.22.1.linux-amd64.tar.gz && [ -s go1.22.1.linux-amd64.tar.gz ] || { echo "[-] Go download failed"; exit 1; }
tar -C /usr/local -xzf go1.22.1.linux-amd64.tar.gz || { echo "[-] Go extract failed"; exit 1; }
rm go1.22.1.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
echo "export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin" >> ~/.bashrc && source ~/.bashrc
[ -n "$ZSH_VERSION" ] && echo "export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin" >> ~/.zshrc && source ~/.zshrc
/usr/local/go/bin/go version || { echo "[-] Go not installed"; exit 1; }
apt install -y jq || { echo "[-] JQ install failed"; exit 1; }
pip install pipx
pipx ensurepath && source ~/.*rc
pip install git+https://github.com/AN0N9M0US/ShodanX.git --break-system-packages
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomnomnom/anew@latest
echo "[+] Setup complete!"
exec $SHELL
