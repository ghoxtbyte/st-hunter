#!/usr/bin/env python3

import sys
import shutil
import os
sys.stdout.reconfigure(line_buffering=True)

from st_hunter.cli import parse_arguments
from st_hunter.core import run_scan
from st_hunter.subdomain_gather import clean_temp_files

BANNER = """

  sSSs  sdSS_SSSSSSbs         .S    S.    .S       S.    .S_sSSs    sdSS_SSSSSSbs    sSSs   .S_sSSs    
 d%%SP  YSSS~S%SSSSSP        .SS    SS.  .SS       SS.  .SS~YS%%b   YSSS~S%SSSSSP   d%%SP  .SS~YS%%b   
d%S'         S%S             S%S    S%S  S%S       S%S  S%S   `S%b       S%S       d%S'    S%S   `S%b  
S%|          S%S             S%S    S%S  S%S       S%S  S%S    S%S       S%S       S%S     S%S    S%S  
S&S          S&S             S%S SSSS%S  S&S       S&S  S%S    S&S       S&S       S&S     S%S    d*S  
Y&Ss         S&S             S&S  SSS&S  S&S       S&S  S&S    S&S       S&S       S&S_Ss  S&S   .S*S  
`S&&S        S&S             S&S    S&S  S&S       S&S  S&S    S&S       S&S       S&S~SP  S&S_sdSSS   
  `S*S       S&S             S&S    S&S  S&S       S&S  S&S    S&S       S&S       S&S     S&S~YSY%b   
   l*S       S*S             S*S    S*S  S*b       d*S  S*S    S*S       S*S       S*b     S*S   `S%b  
  .S*P       S*S             S*S    S*S  S*S.     .S*S  S*S    S*S       S*S       S*S.    S*S    S%S  
sSS*S        S*S             S*S    S*S   SSSbs_sdSSS   S*S    S*S       S*S        SSSbs  S*S    S&S  
YSS'         S*S             SSS    S*S    YSSP~YSSY    S*S    SSS       S*S         YSSP  S*S    SSS  
             SP                     SP                  SP               SP                SP          
             Y                      Y                   Y                Y                 Y           
                                                                                                       
ST-Hunter: Subdomain Takeover Scanner
Version: 1.0.0
Developed by: ghoxtbyte
GitHub: https://github.com/ghoxtbyte
"""

def check_dependencies(silent_mode):
    required_tools = ["dig", "curl", "jq", "subfinder", "anew"]
    optional_tools = {
        "shodanx": "Shodan enumeration"
    }
    
    missing_required = [tool for tool in required_tools if shutil.which(tool) is None]
    
    if missing_required:
        print(f"\n[!] Error: Missing required dependencies: {', '.join(missing_required)}")
        print("[!] Please install them and make sure they are in your system's PATH before running.")
        sys.exit(1)
        
    if not silent_mode:
        for tool, desc in optional_tools.items():
            if shutil.which(tool) is None:
                print(f"[*] Warning: '{tool}' is not installed. {desc} will be skipped.")

def main():
    args = parse_arguments()
    
    if not args.silent:
        print(BANNER)
        
    check_dependencies(args.silent)
        
    run_scan(args)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Cleaning up temporary files...")
        try:
            
            clean_temp_files()
            
            
            if os.path.exists("temp_all_subdomains.txt"):
                os.remove("temp_all_subdomains.txt")
            if os.path.exists("wildcard_domains.txt"):
                os.remove("wildcard_domains.txt")
                
        except Exception as e:
            print(f"[!] Error during cleanup: {e}")
            
        sys.exit(1)
