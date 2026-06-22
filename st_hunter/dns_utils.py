import asyncio
import sys
import aiodns
from .output import output_lines, print_status_line

async def get_ns_records(domain):
    
    try:
        resolver = aiodns.DNSResolver()
        res = await resolver.query(domain, 'NS')
        return [ns.host.rstrip('.') for ns in res]
    except Exception:
        return []

async def _dig_axfr_raw(domain, dns_server):
    
    try:
        cmd = ["dig", f"@{dns_server}", domain, "AXFR", "+noshort", "+noquestion", "+noauthority", "+noadditional", "+comments"]
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        stdout, _ = await proc.communicate()
        return stdout.decode()
    except Exception:
        return ""

async def perform_axfr(domain, ns_records, silent_mode):
    discovered_subs = set()
    if not silent_mode:
        sys.stdout.write(f"\r[*] AXFR testing for {domain}...".ljust(120))
        sys.stdout.flush()
    if not ns_records:
        return discovered_subs
        
    for ns in ns_records:
        axfr_output = await _dig_axfr_raw(domain, ns)
        
        records = [ln for ln in axfr_output.splitlines() if "\tIN\t" in ln or " IN " in ln]
        if records:
            if not silent_mode:
                sys.stdout.write("\r" + " " * 120 + "\r")
                print(f"[+] AXFR succeeded for {domain} via {ns}")
            
            for ln in records:
                if not silent_mode:
                    print(f"    {ln}")
                
                parts = ln.split()
                if parts:
                    fqdn = parts[0].rstrip(".")
                    if fqdn.endswith(domain) and fqdn != domain:
                        discovered_subs.add(fqdn)
                        
    return discovered_subs
