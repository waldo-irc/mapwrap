# mapwrap  - Current Version 1.0.0

[*] Nmap wrapper (outputs as -oN wrapper_nmap by default)

[*] Usage: ./wrap.sh <target> [options]

options:

--help                          Show Brief Help

-p [args], --port [args]        Select port range - EX: ./wrap.sh 127.0.0.1 -p 0-65535

-f [args], --full [args]        All port scan (cannot be used with -f)

--sweep                         Runs a ping sweep on a target, will ignore all other arguments.

-mon [args], --monitor [args]   TCPDump your nmap scan.  Must choose an interface - EX:./wrap.sh 127.0.0.1 -mon eth0

-c=[args], --custom=[args]      Additional custom commands - EX: ./wrap.sh 127.0.0.1 -f --custom='-oA filename -T5'

--nverb [args]                  Sets Nmap verbosity level - EX: ./wrap.sh 127.0.0.1 -vv

-v                              Set verbosity for debugging.

--version                       Check current version level.

--update                        Update mapwrap.

##TODO
###*Add searchsploit capabilities to any NSE scripts that returns vuln
###*Proper bug checking and validation
