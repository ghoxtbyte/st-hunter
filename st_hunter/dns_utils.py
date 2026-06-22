import asyncio
import sys
from .output import output_lines, print_status_line

async def dig_full(domain, rtype, dns_server=None):
    try:
        cmd = ["dig"]
        if dns_server:
            cmd.append(f"@{dns_server}")
        cmd += [domain, rtype, "+noshort", "+noquestion", "+noauthority", "+noadditional", "+comments"]
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        stdout, _ = await proc.communicate()
        return stdout.decode()
    except Exception:
        return ""

async def get_ns_records(domain):
    ns_output = await dig_full(domain, "NS")
    return [line.split()[-1].rstrip('.') for line in ns_output.splitlines() if "\tNS\t" in line]

async def perform_axfr(domain, ns_records, silent_mode):
    discovered_subs = set()
    if not silent_mode:
        sys.stdout.write(f"\r[*] AXFR testing for {domain}...".ljust(120))
        sys.stdout.flush()
    if not ns_records:
        return discovered_subs
        
    for ns in ns_records:
        axfr_output = await dig_full(domain, "AXFR", ns)
        
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
