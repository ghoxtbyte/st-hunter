import asyncio
import random
import sys
import time
from pathlib import Path
import tldextract
from .subdomain_gather import run_subdomain_gathering
from .dns_utils import dig_full, get_ns_records, perform_axfr
from .output import print_status_line, format_time, output_lines, save_output

CHUNK_SIZE = 1000
CONCURRENCY = 100

progress = {
    "checked": 0,
    "total": 0,
    "found": 0,
    "start_time": 0,
    "status": "" 
}

async def check_subdomain_fqdn(fqdn, found_list, dns_servers, current_domain_ns, silent_mode, sema):
    async with sema:
        try:
            if dns_servers:
                cname_dns = random.choice(dns_servers)
            else:
                cname_dns = random.choice(current_domain_ns) if current_domain_ns else None
            cname_output = await dig_full(fqdn, "CNAME", cname_dns)
            status = extract_status(cname_output)
            if status == "NXDOMAIN":
                return
            if status == "NOERROR":
                target = extract_cname_target(cname_output)
                if target:
                    if dns_servers:
                        a_dns = random.choice(dns_servers)
                    else:
                        a_dns = random.choice(["8.8.8.8", "1.1.1.1"])
                    a_output = await dig_full(target, "A", a_dns)
                    a_status = extract_status(a_output)
                    if a_status == "NXDOMAIN":
                        progress["found"] += 1
                        found_list.append((fqdn, target))

                        line = f"{fqdn} {target}"
                        output_lines.append(line)
                        if silent_mode:
                            print(line)
                        else:
                            sys.stdout.write("\r" + " " * 120 + "\r")
                            print(f"[+] Vulnerable: {fqdn:<40} → {target:<50}")
        finally:
            progress["checked"] += 1
            print_status_line(silent_mode)

async def scan_fqdn_list(fqdns, dns_servers, current_domain_ns, silent_mode, output_file):
    progress["checked"] = 0
    progress["found"] = 0
    progress["total"] = len(fqdns)
    progress["start_time"] = time.time()
    progress["status"] = "Scanning FQDN list"
    
    sema = asyncio.Semaphore(CONCURRENCY)
    
    found = []
    chunks = [fqdns[i:i + CHUNK_SIZE] for i in range(0, len(fqdns), CHUNK_SIZE)]
    for chunk in chunks:
        tasks = [check_subdomain_fqdn(fqdn, found, dns_servers, current_domain_ns, silent_mode, sema) for fqdn in chunk]
        await asyncio.gather(*tasks)
        await asyncio.sleep(0.2)
        
    if output_file and output_lines:
        save_output(output_file)

async def scan_domain(domain, subdomains, dns_servers, silent_mode, output_file, save_subs=True):
    global current_domain_ns
    if dns_servers:
        current_domain_ns = dns_servers
    else:
        if not silent_mode:
            sys.stdout.write(f"\r[*] Fetching NS records for {domain}...".ljust(120))
            sys.stdout.flush()
        current_domain_ns = await get_ns_records(domain)
    
    axfr_fqdns = await perform_axfr(domain, current_domain_ns, silent_mode, save_subs)
    axfr_subs = [f.replace(f".{domain}", "") for f in axfr_fqdns if f.endswith(f".{domain}")]
    
    subdomains = list(set(subdomains) | set(axfr_subs))
    
    progress["checked"] = 0
    progress["found"] = 0
    progress["total"] = len(subdomains)
    progress["start_time"] = time.time()
    progress["status"] = f"Scanning: {domain}"
    
    if progress["total"] == 0:
        return
        
    random.shuffle(subdomains)
    sema = asyncio.Semaphore(CONCURRENCY)
    
    chunks = [subdomains[i:i + CHUNK_SIZE] for i in range(0, len(subdomains), CHUNK_SIZE)]
    found = []
    for chunk in chunks:
        
        tasks = [check_subdomain_fqdn(f"{sub}.{domain}" if sub else domain, found, dns_servers, current_domain_ns, silent_mode, sema) for sub in chunk]
        await asyncio.gather(*tasks)
        await asyncio.sleep(0.2)
        
    if output_file and output_lines:
        save_output(output_file)
        
def run_scan(args):
    global output_lines
    silent_mode = args.silent
    output_file = args.output_file
    save_subs = not args.no_save_subdomains
    dns_servers = [args.dns_server] if args.dns_server else load_lines(args.dns_list) if args.dns_list else []
    
    if args.subdomains_file:
        fqdns = load_lines(args.subdomains_file)
        domains_map = {}
        for fqdn in fqdns:
            if '.' not in fqdn:
                continue
            
            
            ext = tldextract.extract(fqdn)
            domain_part = f"{ext.domain}.{ext.suffix}"
            sub_part = ext.subdomain
            
            domains_map.setdefault(domain_part, []).append(sub_part)
            
        for domain_part, subs in domains_map.items():
            asyncio.run(scan_domain(domain_part, subs, dns_servers, silent_mode, output_file, save_subs))
        if not silent_mode:
            print()
        return

    domains = [args.domain] if args.domain else load_lines(args.domain_list) if args.domain_list else []
    for domain in domains:
        if args.online_only:
            if not silent_mode:
                print("\n[*] Starting online subdomain reconnaissance... (This process may take some time)")
            gathered = run_subdomain_gathering(domain, silent=silent_mode, save=save_subs)
            if not silent_mode:
                print("[+] Subdomain reconnaissance finished.\n")
            subs = [s.replace(f".{domain}", "") for s in gathered if s.endswith(f".{domain}")]
            asyncio.run(scan_domain(domain, subs, dns_servers, silent_mode, output_file, save_subs))
            
        elif args.brute_force_only:
            if args.wordlist:
                bruteforce_list = load_lines(args.wordlist)
            elif Path("default-subs.txt").exists():
                bruteforce_list = load_lines("default-subs.txt")
            else:
                print("[!] default-subs.txt not found and no --wordlist provided.")
                continue
            asyncio.run(scan_domain(domain, bruteforce_list, dns_servers, silent_mode, output_file, save_subs))
            
        else:
            if not silent_mode:
                print("\n[*] Starting online subdomain reconnaissance... (This process may take some time)")
            gathered = run_subdomain_gathering(domain, silent=silent_mode, save=save_subs)
            if not silent_mode:
                print("[+] Subdomain reconnaissance finished.\n")
            subs = [s.replace(f".{domain}", "") for s in gathered if s.endswith(f".{domain}")]
            
            if args.wordlist:
                bruteforce_list = load_lines(args.wordlist)
            elif Path("default-subs.txt").exists():
                bruteforce_list = load_lines("default-subs.txt")
            else:
                bruteforce_list = []
                print("[!] default-subs.txt not found and no --wordlist provided. Continuing with online results only.")
                
            combined_subs = list(set(subs) | set(bruteforce_list))
            asyncio.run(scan_domain(domain, combined_subs, dns_servers, silent_mode, output_file, save_subs))
            
    if not silent_mode:
        print()

def extract_status(output):
    for line in output.splitlines():
        if "status:" in line:
            return line.split("status:")[1].split(",")[0].strip()
    return None

def extract_cname_target(output):
    for line in output.splitlines():
        if "\tCNAME\t" in line:
            return line.split()[-1].strip(".")
    return None

def load_lines(path):
    try:
        with open(path) as f:
            return [line.strip() for line in f if line.strip()]
    except:
        sys.exit(f"[ERROR] Cannot read file: {path}")
