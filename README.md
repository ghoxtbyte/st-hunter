# ST-Hunter
ST-Hunter is a powerful and efficient tool for detecting subdomain takeover vulnerabilities. It supports both online service enumeration and brute-force scanning, with AXFR testing for comprehensive domain reconnaissance.

## Features
- Subdomain enumeration using services like Subfinder, Shodan, crt.sh, AlienVault, and urlscan.io
- Brute-force subdomain scanning with custom wordlists
- AXFR testing for DNS zone transfers
- Concurrent DNS lookups with customizable DNS servers
- Silent mode for minimal output
- Output results to a file for further analysis

## Installation
```bash
git clone https://github.com/ghoxtbyte/ST-Hunter.git
cd ST-Hunter
chmod +x setup.sh
./setup.sh
```

## Usage 
```bash
python3 main.py -h
python3 main.py -d example.com
python3 main.py -l domains.txt --wordlist subs.txt
python3 main.py --subdomains-file fqdns.txt --output results.txt
```

## Options
* `-d, --domain`: Scan a single domain
* `-l, --domain-list`: File containing list of domains
* `--subdomains-file`: File with full subdomains (FQDNs) to scan directly
* `-w, --wordlist`: Subdomain wordlist for brute-force
* `-o, --output-file:` Save vulnerable results to file
* `-s, --silent`: Silent mode, only show results
* `--dns-server`: Custom DNS server to use
* `--dns-list`: File containing list of DNS servers
* `--brute-force-only`: Only run brute-force scan
* `--online-only`: Only run online services

## Requirements
- Python 3.6+
- Tools: dig, subfinder, shodanx, jq, curl, anew

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
