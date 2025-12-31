import subprocess
import shutil
import os

TEMP_FILES = [
    "sublist.txt", "shodax.txt", "subs_domain.txt", "alienvault_subs.txt", 
    "urlscan_subs.txt", "assetfinder.txt", "findomain.txt", "amass.txt",
    "wayback.txt", "abuseipdb.txt", "temp_wildcards.txt"
]

def clean_temp_files():
    cmd = "rm -f " + " ".join(TEMP_FILES)
    subprocess.run(cmd, shell=True)

def execute_tools(target, silent=False):
    if not silent:
        print(f"[*] Running Subfinder on {target}...")
    subprocess.run(f"subfinder -d {target} -silent -o sublist.txt > /dev/null 2>&1", shell=True)
    
    if not silent:
        print(f"[*] Running Shodanx on {target}...")
    subprocess.run(f"shodanx subdomain -d {target} -ra -o shodax.txt > /dev/null 2>&1", shell=True)
    
    if not silent:
        print(f"[*] Querying crt.sh for {target}...")
    crt_cmd = (
        f"curl -s 'https://crt.sh/json?q=%25.{target}' | "
        r"jq -r '.[].name_value' 2>/dev/null | "
        r"sed 's/\*\.]//g' | "
        r"sort -u >> subs_domain.txt"
    )
    subprocess.run(crt_cmd, shell=True)
    
    if not silent:
        print(f"[*] Querying AlienVault for {target}...")
    alienvault_cmd = (
        f"curl -s 'https://otx.alienvault.com/api/v1/indicators/hostname/{target}/passive_dns' | "
        r"jq -r '.passive_dns[]?.hostname' 2>/dev/null | "
        fr"grep -E '^[a-zA-Z0-9.-]+\.{target}$' | "
        r"anew > alienvault_subs.txt"
    )
    subprocess.run(alienvault_cmd, shell=True)
    
    if not silent:
        print(f"[*] Querying URLScan for {target}...")
    urlscan_cmd = (
        f"curl -s 'https://urlscan.io/api/v1/search/?q=domain:{target}&size=10000' | "
        r"jq -r '.results[]?.page?.domain' 2>/dev/null | "
        fr"grep -E '^[a-zA-Z0-9.-]+\.{target}$' | "
        r"anew > urlscan_subs.txt"
    )
    subprocess.run(urlscan_cmd, shell=True)

    if shutil.which("assetfinder"):
        if not silent:
            print(f"[*] Running Assetfinder on {target}...")
        subprocess.run(f"assetfinder --subs-only {target} > assetfinder.txt 2>/dev/null", shell=True)

    if shutil.which("findomain"):
        if not silent:
            print(f"[*] Running Findomain on {target}...")
        subprocess.run(f"findomain -t {target} -q > findomain.txt 2>/dev/null", shell=True)

    if shutil.which("amass"):
        if not silent:
            print(f"[*] Running Amass on {target}...")
        subprocess.run(f"amass enum -passive -norecursive -noalts -d {target} > amass.txt 2>/dev/null", shell=True)

    if not silent:
        print(f"[*] Querying Wayback Machine for {target}...")
    wayback_cmd = (
        f"curl -sk 'http://web.archive.org/cdx/search/cdx?url=*.{target}&output=txt&fl=original&collapse=urlkey&page=' | "
        "awk -F/ '{gsub(/:.*/, \"\", $3); print $3}' | "
        r"sort -u > wayback.txt"
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
        r"sort -u > abuseipdb.txt"
    )
    subprocess.run(abuseipdb_cmd, shell=True)

def run_subdomain_gathering(initial_domain, silent=False):
    clean_temp_files()
    subprocess.run("rm -f all_subdomains.txt wildcard_domains.txt", shell=True)

    scan_queue = [initial_domain]
    scanned_domains = set()

    while scan_queue:
        current_target = scan_queue.pop(0)
        
        if current_target in scanned_domains:
            continue
            
        execute_tools(current_target, silent)
        scanned_domains.add(current_target)

        all_files_str = " ".join(TEMP_FILES[:-1])

        merge_cmd = f"cat {all_files_str} 2>/dev/null | anew all_subdomains.txt > /dev/null 2>&1"
        subprocess.run(merge_cmd, shell=True)

        subprocess.run("grep '^\\*\\.' all_subdomains.txt > temp_wildcards.txt", shell=True)
        
        if os.path.exists("temp_wildcards.txt") and os.path.getsize("temp_wildcards.txt") > 0:

            subprocess.run("cat temp_wildcards.txt | anew wildcard_domains.txt > /dev/null 2>&1", shell=True)
            subprocess.run("grep -v '^\\*\\.' all_subdomains.txt > all_subdomains.clean && mv all_subdomains.clean all_subdomains.txt", shell=True)

            with open("temp_wildcards.txt", "r") as f:
                wildcards = f.readlines()
            
            for w in wildcards:
                w = w.strip()
                if not w: continue
                
                clean_domain = w.lstrip("*.")
                
                if clean_domain not in scanned_domains and clean_domain not in scan_queue:
                    scan_queue.append(clean_domain)

        clean_temp_files()
