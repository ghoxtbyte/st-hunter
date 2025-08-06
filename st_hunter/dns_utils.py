import asyncio
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
    if not silent_mode:
        print(f"[*] AXFR testing for {domain}")
    if not ns_records:
        print(f"[-] Not Found for {domain}")
        return
    for ns in ns_records:
        axfr_output = await dig_full(domain, "AXFR", ns)
        records = [ln for ln in axfr_output.splitlines() if "\tIN\t" in ln]
        if records:
            print(f"[+] AXFR succeeded for {domain} via {ns}")
            if not silent_mode:
                for ln in records[:10]:
                    print(ln)
                if len(records) > 10:
                    print(f"... ({len(records)} records)")
            
            line = f"{domain} AXFR SUCCESS via {ns}"
            output_lines.append(line)
            if not silent_mode:
                print(f"\n[+] AXFR SUCCESS: {line}")
            return
    print(f"[-] Not Found for {domain}")
