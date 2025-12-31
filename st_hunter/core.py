import asyncio
import random
import sys
import time
from pathlib import Path
from .subdomain_gather import run_subdomain_gathering
from .dns_utils import dig_full, get_ns_records, perform_axfr
from .output import print_status_line, format_time, output_lines, save_output

CHUNK_SIZE = 1000
CONCURRENCY = 200

progress = {
    "checked": 0,
    "total": 0,
    "found": 0,
    "start_time": 0
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
                    if a_status == "NXDOMAIN" or (a_status == "SERVFAIL" and "cloudfront" not in target):
                        if not silent_mode:
                            print(f"\r[!] Potential Takeover: {fqdn} -> {target}")
                        output_lines.append(f"VULNERABLE: {fqdn} points to {target}")
                        progress["found"] += 1
            progress["checked"] += 1
            print_status_line(silent_mode)
        except Exception:
            pass

async def scan_domain(domain, subs, dns_servers, silent_mode, output_file):
    print_status_line(silent_mode)
    ns_records = await get_ns_records(domain)
    
    await perform_axfr(domain, ns_records, silent_mode)

    sema = asyncio.Semaphore(CONCURRENCY)
    tasks = []
    
    progress["total"] = len(subs)
    progress["checked"] = 0
    progress["found"] = 0
    progress["start_time"] = time.time()
    
    for sub in subs:
        if sub:
            fqdn = f"{sub}.{domain}"
            tasks.append(check_subdomain_fqdn(fqdn, output_lines, dns_servers, ns_records, silent_mode, sema))
            
    await asyncio.gather(*tasks)
    
    if output_file:
        save_output(output_file)

def run_scan(args):
    targets = []
    if args.domain:
        targets.append(args.domain)
    elif args.domain_list:
        targets = load_lines(args.domain_list)

    output_file = args.output_file
    silent_mode = args.silent
    dns_servers = []
    
    if args.dns_server:
        dns_servers.append(args.dns_server)
    if args.dns_list:
        dns_servers.extend(load_lines(args.dns_list))

    for domain in targets:
        if args.subdomains_file:
            fqdns = load_lines(args.subdomains_file)
            subs = []
            target_domain = domain if domain else "unknown"
            for f in fqdns:
                if target_domain in f:
                    subs.append(f.replace(f".{target_domain}", ""))
                else:
                    subs.append(f) 
            asyncio.run(scan_domain(target_domain, subs, dns_servers, silent_mode, output_file))
        else:
            if args.brute_force_only:
                 if args.wordlist:
                    bruteforce_list = load_lines(args.wordlist)
                    asyncio.run(scan_domain(domain, bruteforce_list, dns_servers, silent_mode, output_file))
                 else:
                     print("[!] Wordlist required for brute-force only mode.")
            elif args.online_only:
                if not silent_mode:
                    print(f"\n[*] Starting online subdomain reconnaissance for {domain}...")
                run_subdomain_gathering(domain, silent_mode)
                if not silent_mode:
                    print("[+] Subdomain reconnaissance finished.\n")
                gathered = load_lines("all_subdomains.txt")
                subs = [s.replace(f".{domain}", "") for s in gathered if s.endswith(f".{domain}")]
                asyncio.run(scan_domain(domain, subs, dns_servers, silent_mode, output_file))
            else:
                if not silent_mode:
                    print(f"\n[*] Starting online subdomain reconnaissance for {domain}...")
                run_subdomain_gathering(domain, silent_mode)
                if not silent_mode:
                    print("[+] Subdomain reconnaissance finished.\n")
                gathered = load_lines("all_subdomains.txt")
                subs = [s.replace(f".{domain}", "") for s in gathered if s.endswith(f".{domain}")]
                asyncio.run(scan_domain(domain, subs, dns_servers, silent_mode, output_file))
                
                if args.wordlist:
                    bruteforce_list = load_lines(args.wordlist)
                elif Path("default-subs.txt").exists():
                    bruteforce_list = load_lines("default-subs.txt")
                else:
                    print("[!] default-subs.txt not found and no --wordlist provided.")
                    continue
                asyncio.run(scan_domain(domain, bruteforce_list, dns_servers, silent_mode, output_file))

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
        return []
