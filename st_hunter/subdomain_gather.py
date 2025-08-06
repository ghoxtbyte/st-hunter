import subprocess

def run_subdomain_gathering(domain):
    for f in ["sublist.txt", "shodax.txt", "subs_domain.txt", "alienvault_subs.txt", "urlscan_subs.txt"]:
        subprocess.run(f"rm -f {f}", shell=True)
    subprocess.run(f"subfinder -d {domain} -silent -o sublist.txt > /dev/null 2>&1", shell=True)
    subprocess.run(f"shodanx subdomain -d {domain} -ra -o shodax.txt > /dev/null 2>&1", shell=True)
    crt_cmd = (
        f"curl -s 'https://crt.sh/json?q=%25.{domain}' | "
        r"jq -r '.[].name_value' 2>/dev/null | "
        r"sed 's/\*\.]//g' | "
        r"sort -u >> subs_domain.txt"
    )
    subprocess.run(crt_cmd, shell=True)
    alienvault_cmd = (
        f"curl -s 'https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/passive_dns' | "
        r"jq -r '.passive_dns[]?.hostname' 2>/dev/null | "
        fr"grep -E '^[a-zA-Z0-9.-]+\.{domain}$' | "
        r"anew > alienvault_subs.txt"
    )
    subprocess.run(alienvault_cmd, shell=True)
    urlscan_cmd = (
        f"curl -s 'https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000' | "
        r"jq -r '.results[]?.page?.domain' 2>/dev/null | "
        fr"grep -E '^[a-zA-Z0-9.-]+\.{domain}$' | "
        r"anew > urlscan_subs.txt"
    )
    subprocess.run(urlscan_cmd, shell=True)
    subprocess.run(
        "cat sublist.txt shodax.txt subs_domain.txt alienvault_subs.txt urlscan_subs.txt 2>/dev/null | anew > all_subdomains.txt",
        shell=True)
    subprocess.run("rm -f sublist.txt shodax.txt subs_domain.txt alienvault_subs.txt urlscan_subs.txt", shell=True)
