import argparse

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="ST-Hunter: Advanced Subdomain Takeover Scanner with AXFR Support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py -d example.com
  python3 main.py -l domains.txt --wordlist subs.txt
  python3 main.py --subdomains-file fqdns.txt --output results.txt
"""
    )
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("-d", "--domain", help="Single domain to scan")
    group.add_argument("-l", "--domain-list", help="File containing list of domains")
    parser.add_argument("--subdomains-file", help="File with full subdomains (FQDNs) to scan directly")
    parser.add_argument("-w", "--wordlist", help="Subdomain wordlist for brute-force")
    parser.add_argument("-o", "--output-file", help="Save vulnerable results to file")
    parser.add_argument("-s", "--silent", action="store_true", help="Silent mode, only show results")
    parser.add_argument("--dns-server", help="Custom DNS server to use")
    parser.add_argument("--dns-list", help="File containing list of DNS servers")
    parser.add_argument("--brute-force-only", action="store_true", help="Only run brute-force scan (skip online services)")
    parser.add_argument("--online-only", action="store_true", help="Only run online services (skip brute-force)")
    return parser.parse_args()
