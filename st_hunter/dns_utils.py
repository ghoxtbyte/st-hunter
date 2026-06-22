import asyncio
import sys
from datetime import datetime
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

async def perform_axfr(domain, ns_records, silent_mode, save_subs=True):
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
            
            msg = f"[+] AXFR VULNERABLE: {domain} via {ns}"
            if not silent_mode:
                sys.stdout.write("\r" + " " * 120 + "\r")
                print(msg)
            else:
                
                print(msg)
            
            axfr_full_text = []
            for ln in records:
                axfr_full_text.append(ln)
                
                parts = ln.split()
                if parts:
                    fqdn = parts[0].rstrip(".")
                    if fqdn.endswith(domain) and fqdn != domain:
                        discovered_subs.add(fqdn)
                        
            
            output_lines.append(f"[AXFR VULNERABILITY] Domain: {domain} | NS: {ns}")
            
            
            if save_subs:
                timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
                axfr_filename = f"AXFR-{domain}-{timestamp}.txt"
                try:
                    with open(axfr_filename, "a") as f:
                        f.write(f"[*] AXFR Results for {domain} via {ns}\n")
                        f.write("\n".join(axfr_full_text) + "\n")
                        f.write("-" * 50 + "\n")
                except Exception as e:
                    if not silent_mode:
                        print(f"[!] Error saving AXFR file: {e}")
                    
    return discovered_subs
