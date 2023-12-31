```
┌──(kali㉿kali)-[~/HTB/Blue]
└─$ sudo masscan -p1-65535 10.10.10.40 --rate=1000 -e tun0 > ports
[sudo] password for kali: 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2023-11-11 19:38:46 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
                                                                                                                                                                       
┌──(kali㉿kali)-[~/HTB/Blue]
└─$ cat ports    
Discovered open port 135/tcp on 10.10.10.40                                    
Discovered open port 445/tcp on 10.10.10.40                                    
Discovered open port 139/tcp on 10.10.10.40                                    
Discovered open port 49154/tcp on 10.10.10.40                                  
Discovered open port 49155/tcp on 10.10.10.40                                  
Discovered open port 49157/tcp on 10.10.10.40                                  
Discovered open port 49156/tcp on 10.10.10.40                                  
Discovered open port 49152/tcp on 10.10.10.40                                  
Discovered open port 49153/tcp on 10.10.10.40                                  
                                                                                                                                                                       
┌──(kali㉿kali)-[~/HTB/Blue]
└─$ ports=$(cat ports | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')

```

```
┌──(kali㉿kali)-[~/HTB/Blue]
└─$ nmap -sV -sC -p$ports -oA nmap/blue_ports 10.10.10.40 -v 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-11 14:49 EST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 14:49
Completed NSE at 14:49, 0.00s elapsed
Initiating NSE at 14:49
Completed NSE at 14:49, 0.00s elapsed
Initiating NSE at 14:49
Completed NSE at 14:49, 0.00s elapsed
Initiating Ping Scan at 14:49
Scanning 10.10.10.40 [2 ports]
Completed Ping Scan at 14:49, 0.15s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 14:49
Completed Parallel DNS resolution of 1 host. at 14:49, 0.03s elapsed
Initiating Connect Scan at 14:49
Scanning 10.10.10.40 [9 ports]
Discovered open port 135/tcp on 10.10.10.40
Discovered open port 445/tcp on 10.10.10.40
Discovered open port 139/tcp on 10.10.10.40
Discovered open port 49155/tcp on 10.10.10.40
Discovered open port 49154/tcp on 10.10.10.40
Discovered open port 49153/tcp on 10.10.10.40
Discovered open port 49156/tcp on 10.10.10.40
Discovered open port 49157/tcp on 10.10.10.40
Discovered open port 49152/tcp on 10.10.10.40
Completed Connect Scan at 14:49, 0.19s elapsed (9 total ports)
Initiating Service scan at 14:49
Scanning 9 services on 10.10.10.40
Service scan Timing: About 44.44% done; ETC: 14:51 (0:01:10 remaining)
Completed Service scan at 14:50, 70.41s elapsed (9 services on 1 host)
NSE: Script scanning 10.10.10.40.
Initiating NSE at 14:50
Completed NSE at 14:50, 12.49s elapsed
Initiating NSE at 14:50
Completed NSE at 14:50, 0.02s elapsed
Initiating NSE at 14:50
Completed NSE at 14:50, 0.01s elapsed
Nmap scan report for 10.10.10.40
Host is up (0.17s latency).

PORT      STATE SERVICE     VERSION
135/tcp   open  msrpc       Microsoft Windows RPC
139/tcp   open  netbios-ssn Microsoft Windows netbios-ssn
445/tcp   open              Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc       Microsoft Windows RPC
49153/tcp open  msrpc       Microsoft Windows RPC
49154/tcp open  msrpc       Microsoft Windows RPC
49155/tcp open  msrpc       Microsoft Windows RPC
49156/tcp open  msrpc       Microsoft Windows RPC
49157/tcp open  msrpc       Microsoft Windows RPC
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 3s, deviation: 2s, median: 1s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-11-11T19:50:45+00:00
| smb2-time: 
|   date: 2023-11-11T19:50:43
|_  start_date: 2023-11-11T19:37:49
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required

```

```
┌──(kali㉿kali)-[~/HTB/Blue]
└─$ nmap --script "safe or smb-enum-*" -p 445 10.10.10.40                                                                                                      
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-11 15:05 EST
Pre-scan script results:
|_hostmap-robtex: *TEMPORARILY DISABLED* due to changes in Robtex's API. See https://www.robtex.com/api/
| targets-asn: 
|_  targets-asn.asn is a mandatory parameter
|_http-robtex-shared-ns: *TEMPORARILY DISABLED* due to changes in Robtex's API. See https://www.robtex.com/api/
| broadcast-dropbox-listener: 
| displayname  ip            port   version  host_int             namespaces
|_             192.168.14.1  17500  2.0      1.6981742811802e+38  2589442961
Nmap scan report for 10.10.10.40
Host is up (0.15s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-protocols: 
|   dialects: 
|     NT LM 0.12 (SMBv1) [dangerous, but default]
|     2:0:2
|_    2:1:0
| smb2-capabilities: 
|   2:0:2: 
|     Distributed File System
|   2:1:0: 
|     Distributed File System
|     Leasing
|_    Multi-credit operations
| dns-blacklist: 
|   SPAM
|_    l2.apews.org - FAIL
| smb-ls: Volume \\10.10.10.40\Share
| SIZE   TIME                 FILENAME
| <DIR>  2017-07-14T13:48:44  .
| <DIR>  2017-07-14T13:48:44  ..
| 
| 
| Volume \\10.10.10.40\Users
| SIZE   TIME                 FILENAME
| <DIR>  2009-07-14T03:20:08  .
| <DIR>  2009-07-14T03:20:08  ..
| <DIR>  2009-07-14T03:20:08  Public
| <DIR>  2009-07-14T03:20:08  Public\Documents
| <DIR>  2009-07-14T03:20:08  Public\Downloads
| <DIR>  2009-07-14T03:20:08  Public\Music
| <DIR>  2009-07-14T03:20:08  Public\Pictures
| <DIR>  2011-04-12T07:51:29  Public\Recorded TV
| <DIR>  2009-07-14T03:20:08  Public\Videos
|_
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx

...
```
![](assets/Blue_assets/Pasted%20image%2020231111215947.png)

![](assets/Blue_assets/Pasted%20image%2020231111220003.png)

![](assets/Blue_assets/Pasted%20image%2020231111220020.png)
```
┌──(kali㉿kali)-[~/HTB/Blue]
└─$ smbclient \\\\10.10.10.40\\Users -N
Try "help" to get a list of possible commands.
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *

```

![](assets/Blue_assets/Pasted%20image%2020231111215159.png)
![](assets/Blue_assets/Pasted%20image%2020231111215230.png)
![](assets/Blue_assets/Pasted%20image%2020231111215244.png)

![](assets/Blue_assets/Pasted%20image%2020231111215347.png)
![](assets/Blue_assets/Pasted%20image%2020231111215428.png)
