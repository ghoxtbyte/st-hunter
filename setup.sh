#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}[+] Starting full setup for ST-Hunter (with Recon capabilities)...${NC}"

# 1. Update & Base Dependencies
echo -e "${GREEN}[*] Updating system and installing base dependencies...${NC}"
sudo apt update
sudo apt install -y python3-pip python3-venv git curl wget build-essential dnsutils jq parallel unzip libpcap-dev || { echo -e "${RED}[-] Base install failed${NC}"; exit 1; }

# 2. Install/Update Golang 
echo -e "${GREEN}[*] Installing Go...${NC}"
sudo apt remove golang -y 2>/dev/null
sudo rm -rf /usr/local/go
wget -q https://go.dev/dl/go1.22.1.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.1.linux-amd64.tar.gz
rm go1.22.1.linux-amd64.tar.gz

# Setup Paths
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
grep -qxF 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' ~/.bashrc || echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
[ -f ~/.zshrc ] && (grep -qxF 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' ~/.zshrc || echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.zshrc)

# 3. Install Python Requirements
echo -e "${GREEN}[*] Installing Python libraries...${NC}"
pip install --upgrade pip
pip install aiohttp aiodns alive-progress

# 4. Install Go-based Tools 
echo -e "${GREEN}[*] Installing Go tools (Subfinder, Assetfinder, Amass, Anew)...${NC}"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/OWASP/Amass/v3/...@master
go install -v github.com/tomnomnom/anew@latest

# 5. Install Findomain (Binary)
echo -e "${GREEN}[*] Installing Findomain...${NC}"
curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip
unzip -o findomain-linux.zip
chmod +x findomain
sudo mv findomain /usr/local/bin/
rm findomain-linux.zip

# 6. Install ShodanX 
echo -e "${GREEN}[*] Installing ShodanX...${NC}"
go install -v github.com/ChiggerX/shodanx@latest

# 7. Final Verification
echo -e "${BLUE}--------------------------------------${NC}"
echo -e "${BLUE}[+] Setup Complete! Verifying tools:${NC}"
TOOLS="subfinder assetfinder amass findomain anew shodanx dig jq"

for tool in $TOOLS; do
    if command -v $tool &> /dev/null; then
        echo -e "$tool: ${GREEN}Installed${NC}"
    else
        echo -e "$tool: ${RED}Not found in PATH${NC}"
    fi
done

echo -e "${GREEN}[!] Please run 'source ~/.bashrc' or restart your terminal.${NC}"
