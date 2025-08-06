#!/usr/bin/env python3

from st_hunter.cli import parse_arguments
from st_hunter.core import run_scan

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

def main():
    print(BANNER)
    args = parse_arguments()
    run_scan(args)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
