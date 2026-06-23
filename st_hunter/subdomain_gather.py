import subprocess
import shutil
import os
import re
import time
from datetime import datetime


SESSION_ID = str(int(time.time()))

TEMP_FILES = [
    f"sublist_{SESSION_ID}.txt", f"shodax_{SESSION_ID}.txt", f"subs_domain_{SESSION_ID}.txt", 
    f"alienvault_subs_{SESSION_ID}.txt", f"urlscan_subs_{SESSION_ID}.txt", f"assetfinder_{SESSION_ID}.txt", 
    f"findomain_{SESSION_ID}.txt", f"amass_{SESSION_ID}.txt", f"wayback_{SESSION_ID}.txt", 
    f"abuseipdb_{SESSION_ID}.txt", f"chaos_{SESSION_ID}.txt"
]

TEMP_ALL_SUBS = f"temp_all_subdomains_{SESSION_ID}.txt"
WILDCARD_DOMAINS = f"wildcard_domains_{SESSION_ID}.txt"

def clean_temp_files():
    files_to_remove = TEMP_FILES + [TEMP_ALL_SUBS, WILDCARD_DOMAINS]
    cmd = "rm -f " + " ".join(files_to_remove)
    subprocess.run(cmd, shell=True)

def execute_tools(target, silent=False):
    if not silent:
        print(f"[*] Running Subfinder on {target}...")
    subprocess.run(f"subfinder -d {target} -silent -o sublist_{SESSION_ID}.txt > /dev/null 2>&1", shell=True)
    
    if not silent:
        print(f"[*] Running Shodanx on {target}...")
    subprocess.run(f"shodanx subdomain -d {target} -ra -o shodax_{SESSION_ID}.txt > /dev/null 2>&1", shell=True)
    
    if not silent:
        print(f"[*] Querying crt.sh for {target}...")
    crt_cmd = (
        f"curl -s 'https://crt.sh/json?q=%25.{target}' | "
        r"jq -r '.[].name_value' 2>/dev/null | "
        r"sed 's/\*\.]//g' | "
        f"sort -u >> subs_domain_{SESSION_ID}.txt"
    )
    subprocess.run(crt_cmd, shell=True)
    
    if not silent:
        print(f"[*] Querying AlienVault for {target}...")
    alienvault_cmd = (
        f"curl -s 'https://otx.alienvault.com/api/v1/indicators/hostname/{target}/passive_dns' | "
        r"jq -r '.passive_dns[]?.hostname' 2>/dev/null | "
        fr"grep -E '^[a-zA-Z0-9.-]+\.{target}$' | "
        f"anew > alienvault_subs_{SESSION_ID}.txt"
    )
    subprocess.run(alienvault_cmd, shell=True)
    
    if not silent:
        print(f"[*] Querying URLScan for {target}...")
    urlscan_cmd = (
        f"curl -s 'https://urlscan.io/api/v1/search/?q=domain:{target}&size=10000' | "
        r"jq -r '.results[]?.page?.domain' 2>/dev/null | "
        fr"grep -E '^[a-zA-Z0-9.-]+\.{target}$' | "
        f"anew > urlscan_subs_{SESSION_ID}.txt"
    )
    subprocess.run(urlscan_cmd, shell=True)

    if shutil.which("assetfinder"):
        if not silent:
            print(f"[*] Running Assetfinder on {target}...")
        subprocess.run(f"assetfinder --subs-only {target} > assetfinder_{SESSION_ID}.txt 2>/dev/null", shell=True)

    if shutil.which("findomain"):
        if not silent:
            print(f"[*] Running Findomain on {target}...")
        subprocess.run(f"findomain -t {target} -q > findomain_{SESSION_ID}.txt 2>/dev/null", shell=True)

    if shutil.which("amass"):
        if not silent:
            print(f"[*] Running Amass on {target}...")
        subprocess.run(f"amass enum -passive -norecursive -noalts -d {target} > amass_{SESSION_ID}.txt 2>/dev/null", shell=True)

    if os.environ.get("PDCP_API_KEY") and shutil.which("chaos"):
        if not silent:
            print(f"[*] Running Chaos on {target}...")
        subprocess.run(f"chaos -d {target} -silent > chaos_{SESSION_ID}.txt 2>/dev/null", shell=True)

    if not silent:
        print(f"[*] Querying Wayback Machine for {target}...")
    wayback_cmd = (
        f"curl -sk 'http://web.archive.org/cdx/search/cdx?url=*.{target}&output=txt&fl=original&collapse=urlkey&page=' | "
        "awk -F/ '{gsub(/:.*/, \"\", $3); print $3}' | "
        f"sort -u > wayback_{SESSION_ID}.txt"
    )
    subprocess.run(wayback_cmd, shell=True)

    if not silent:
        print(f"[*] Querying AbuseIPDB for {target}...")
    abuseipdb_cmd = (
        f"curl -s 'https://www.abuseipdb.com/whois/{target}' -H 'user-agent: firefox' -b 'abuseipdb_session=' | "
        r"grep -E '<li>\w.*</li>' | "
        r"sed -E 's/<\/?li>//g' | "
        fr"sed -e 's/$/.{target}/' | "
        r"sed 's/^[[:space:]]*//' | "
        f"sort -u > abuseipdb_{SESSION_ID}.txt"
    )
    subprocess.run(abuseipdb_cmd, shell=True)

def run_subdomain_gathering(initial_domain, silent=False, save=True):
    clean_temp_files()

    scan_queue = [initial_domain]
    scanned_domains = set()

    while scan_queue:
        current_target = scan_queue.pop(0)
        
        if current_target in scanned_domains:
            continue
            
        execute_tools(current_target, silent)
        scanned_domains.add(current_target)

        all_files_str = " ".join(TEMP_FILES)
        merge_cmd = f"cat {all_files_str} 2>/dev/null | awk 'NF' | grep -F '.' | anew {TEMP_ALL_SUBS} > /dev/null 2>&1"
        subprocess.run(merge_cmd, shell=True)
        
        
        cmd = "rm -f " + " ".join(TEMP_FILES)
        subprocess.run(cmd, shell=True)

        if not os.path.exists(TEMP_ALL_SUBS): continue
        
        with open(TEMP_ALL_SUBS, "r") as f:
            all_subs = set(f.read().splitlines())
        
        wildcards = {s for s in all_subs if '*' in s}
        clean_subs = all_subs - wildcards
        
        if wildcards:
            with open(WILDCARD_DOMAINS, "a") as f:
                for w in wildcards:
                    f.write(w + "\n")
                    
        next_wildcards = set()
        
        for pattern in wildcards:
            b = pattern.split('*')[-1]
            clean_part = b.lstrip('.')
            
            if re.match(r'^\*\.[a-zA-Z0-9.-]+$', pattern):
                target = pattern.lstrip('*.')
            elif '.' not in clean_part:
                target = pattern.replace('*', '').replace('..', '.').strip('.')
            else:
                target = clean_part
                
            if target and target not in scanned_domains and target not in scan_queue:
                scan_queue.append(target)

            parts = pattern.rsplit('*', 1)
            A = parts[0]
            B = parts[1]
            L = A.split('*')[-1] if '*' in A else A
            
            for d in clean_subs:
                if B and not d.endswith(B): continue
                if not B and L and not d.startswith(L.lstrip('.')): continue
                
                R = d[:-len(B)] if B else d
                if not R: continue
                
                if not L:
                    X = R
                else:
                    if L in R:
                        X = R.split(L)[-1]
                    else:
                        l_clean = L.lstrip('.')
                        if l_clean in R:
                            X = R.split(l_clean)[-1]
                        else:
                            X = R
                X = X.lstrip('.')
                new_pattern = f"{A}{X}{B}"
                
                if '*' in new_pattern:
                    next_wildcards.add(new_pattern)
                else:
                    clean_subs.add(new_pattern)

        with open(TEMP_ALL_SUBS, "w") as f:
            for d in clean_subs:
                f.write(d + "\n")
            for w in next_wildcards:
                f.write(w + "\n")

    gathered_list = []
    if os.path.exists(TEMP_ALL_SUBS):
        with open(TEMP_ALL_SUBS, "r") as f:
            gathered_list = f.read().splitlines()
        
        if save:
            now = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
            final_file = f"all_subdomains-{now}.txt"
            shutil.move(TEMP_ALL_SUBS, final_file)
            if not silent:
                print(f"[+] Subdomains saved to: {final_file}")
        else:
            os.remove(TEMP_ALL_SUBS)
            if not silent:
                print("[!] Subdomains were not saved to a file (--no-save-subdomains).")

    if os.path.exists(WILDCARD_DOMAINS):
        os.remove(WILDCARD_DOMAINS)

    return gathered_list
