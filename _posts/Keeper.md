---
tags:
  - keepass
  - dotnet
---
***Overview**: Keeper is an Easy rated HTB machine that uses default credentials to gain access into a dashboard that leaks user credentials that can be used to gain foothold on the machine. It then exploits  CVE-2023-32784 in KeePass 2.X that allows us to retrieve the master password in cleartext from a memory dump and then access the passcodes database, where we retrieved our password and SSH key to gain compromised access as root.*
# HTB: Keeper

## Scanning and Enumeration

- So we start by running a scan to identify open ports and services

```shell
──(kali㉿kali)-[~/HTB]
└─$ nmap -sV -sC -oA nmap/keeper_ports 10.10.11.227 -r -v
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-28 17:53 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 17:53
Completed NSE at 17:53, 0.00s elapsed
Initiating NSE at 17:53
Completed NSE at 17:53, 0.00s elapsed
Initiating NSE at 17:53
Completed NSE at 17:53, 0.00s elapsed
Initiating Ping Scan at 17:53
Scanning 10.10.11.227 [2 ports]
Completed Ping Scan at 17:53, 0.18s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 17:53
Completed Parallel DNS resolution of 1 host. at 17:53, 0.05s elapsed
Initiating Connect Scan at 17:53
Scanning 10.10.11.227 [1000 ports]
Discovered open port 22/tcp on 10.10.11.227
Discovered open port 80/tcp on 10.10.11.227
Discovered open port 8000/tcp on 10.10.11.227
Completed Connect Scan at 17:54, 27.27s elapsed (1000 total ports)
Initiating Service scan at 17:54
Scanning 3 services on 10.10.11.227
Completed Service scan at 17:54, 6.81s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.11.227.
Initiating NSE at 17:54
Completed NSE at 17:54, 5.49s elapsed
Initiating NSE at 17:54
Completed NSE at 17:54, 0.80s elapsed
Initiating NSE at 17:54
Completed NSE at 17:54, 0.01s elapsed
Nmap scan report for 10.10.11.227
Host is up (0.17s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT     STATE    SERVICE   VERSION
22/tcp   open     ssh       OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
|_  256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
80/tcp   open     http      nginx 1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.18.0 (Ubuntu)
7627/tcp filtered soap-http
7937/tcp filtered nsrexecd
8000/tcp open     http      SimpleHTTPServer 0.6 (Python 3.10.12)
|_http-title: Directory listing for /
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: SimpleHTTP/0.6 Python/3.10.12
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 17:54
Completed NSE at 17:54, 0.00s elapsed
Initiating NSE at 17:54
Completed NSE at 17:54, 0.00s elapsed
Initiating NSE at 17:54
Completed NSE at 17:54, 0.01s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 44.03 seconds

```

### port 80

- so by accessing the webserver on port 80, we are told to visit a path in a subdomain `tickets.keeper.htb`

![](assets/Keeper_assets/Pasted%20image%2020230828225754.png)

- so we add the VHOSTs to the `/etc/hosts` files

![](assets/Keeper_assets/Pasted%20image%2020230828233149.png)

- so navigating to the page, we are presented with a login panel

![](assets/Keeper_assets/Pasted%20image%2020230828233129.png)

- we could see that a software rt 4.4.4 was running on the web server, so checking for default passwords, I tested root and password and I got access

![](assets/Keeper_assets/Pasted%20image%2020230829233503.png)

![](assets/Keeper_assets/Pasted%20image%2020230829233524.png)
- we oculd also retrieve the default credentials by reading the documentation at [https://docs.bestpractical.com/rt/4.4.4/README.html](https://docs.bestpractical.com/rt/4.4.4/README.html) 

![](assets/Keeper_assets/Pasted%20image%2020230829233731.png)

```ad-important
READ DOCUMENATION!!
```

- so looking through the dashboard now we can see we have an additional user, which is the lnorgaard user

![](assets/Keeper_assets/Pasted%20image%2020230829234758.png)

- so looking at the user, we can see information about the user

![](assets/Keeper_assets/Pasted%20image%2020230830073959.png)

- we can also see the comments about the user, and we found a possible password `Welcome2023!`

![](assets/Keeper_assets/Pasted%20image%2020230830074018.png)
### Port 8000: OOOpps
- visiting the web server on port 8000, from our nmap scan we could see that it was a python http server

![](assets/Keeper_assets/Pasted%20image%2020230828230135.png)

- But this seems like it was a mistake from someone that compromised the machine (WE ARE NOT MEANT TO HAVE ACCESS TO THIS!!)

### Foothold

- so using the username and password, we got foothold on the machine lnorgaard and we can read the user flag

![](assets/Keeper_assets/Pasted%20image%2020230830150111.png)

- we also notice a zip file, so we can retrieve the zip file and unzip it and we get a dmp file and a .kbdx file

![](assets/Keeper_assets/Pasted%20image%2020230830163056.png)

- so we can see that the .kbdx file is a keepass password database file for Keepass 2.X (note that)

![](assets/Keeper_assets/Pasted%20image%2020230830080057.png)

- and for the dmp file, it looks like it is a data dump file (memory dump) for the keepass program, we can look at it using visual studio

![](assets/Keeper_assets/Pasted%20image%2020230828232405.png)

```ad-info
Memory dump files are usually created when a program crashes or has an error
```

## Post Exploitation: KeePass master password dump

- Now researching on the Keepass 2.X, see that it is vulnerable to CVE-2023-32784, which allows us to recover the master password in clear text from a memory dump (which we have :) )

Resource: [https://www.malwarebytes.com/blog/news/2023/05/keepass-vulnerability-allows-attackers-to-access-the-master-password](https://www.malwarebytes.com/blog/news/2023/05/keepass-vulnerability-allows-attackers-to-access-the-master-password)

![](assets/Keeper_assets/Pasted%20image%2020230830080116.png)

- because we were not using the dotnet version that is compatible with the SDK version that was used to create the keepass dumper tool (.NET 7.0)

![](assets/Keeper_assets/Pasted%20image%2020231230141500.png)

- we had to download the latest version using the [Install .NET on Linux without using a package manager - .NET | Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/core/install/linux-scripted-manual)

```shell
wget https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh
./dotnet-install.sh --channel 7.0

```

```shell
┌──(kali㉿kali)-[~/HTB/keepass-password-dumper]
└─$ export DOTNET_ROOT=$HOME/.dotnet    
                                                                                                                                                                       
┌──(kali㉿kali)-[~/HTB/keepass-password-dumper]
└─$ export PATH=$PATH:$DOTNET_ROOT:$DOTNET_ROOT/tools

```

But it still didn't work so we had to delete the dotnet directory in /usr/share and then we copy the `.dotnet` directory to the dotnet directory in /usr/share, for the latest version to work

```shell
sudo rm -rf /usr/share/dotnet
cd ~
sudo cp -r .dotnet/ /usr/share/dotnet
```

![](assets/Keeper_assets/Pasted%20image%2020231230172025.png)

- verify with

```shell
dotnet --list-sdks
```

- so following the guide at [(6) Steal KeePass 2.x < 2.54 Master Password | LinkedIn](https://www.linkedin.com/pulse/steal-keepass-2x-254-master-password-chance-johnson/)
- so after cloning the keepass password dumper tool repo at [GitHub - vdohney/keepass-password-dumper: Original PoC for CVE-2023-32784](https://github.com/vdohney/keepass-password-dumper) then we use dotnet to run the dump file in the directory of the tool (so we have to `cd keepass-password-dumper` first), then run the command

![](assets/Keeper_assets/Pasted%20image%2020230830130337.png)

![](assets/Keeper_assets/Pasted%20image%2020230830130307.png)

- so we got this `dgrød med fløde`, but we tried this to access the keepass database but it didn't work

```
dgrødmedfløde
dgrdmedflde
```

- so we decided to do a google search and we got a meal named `rødgrød med fløde`

![](assets/Keeper_assets/Pasted%20image%2020230830145702.png)

- in our keepass 2, we can then open the passcodes.kbdx file and we got access using the password `rødgrød med fløde`

![](assets/Keeper_assets/Pasted%20image%2020230830145827.png)

- now if we look at the root user, we can see a password as `F4><3K0nd!` and we can also see a Putty SSH key

![](assets/Keeper_assets/Pasted%20image%2020230830145900.png)

```
PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: rsa-key-20230519
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
Private-Lines: 14
AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0
```

### Convert putty keys to openssh format
- so we downloaded puttygen from [Download Putty (0.79) for Windows, Linux and Mac - Install SSH in PuTTY (puttygen.com)](https://www.puttygen.com/download-putty) and then we want to convert the putty key to open SSH format so we can use it, we can watch this video at  [(5) How to convert Putty Keys to Open SSH format for Control-M for AFT - YouTube](https://www.youtube.com/watch?v=iUeRs5t48-A)
- so we place the putty ssh key in a file as key.ppk, and then we load  it using  putty key generator and then convert it by going to Conversions >> Export OpenSSH key >> Yes to save key without passphrase, then name  file name id_rsa

![](assets/Keeper_assets/Pasted%20image%2020230830153643.png)

- then we get our ssh key in OpenSSH format, now we can use it

![](assets/Keeper_assets/Pasted%20image%2020230830155053.png)

- we tried access with the password but it didn't work, but when we tried with the public key, we got access as Root!!, and we got our root flag

![](assets/Keeper_assets/Pasted%20image%2020230830155137.png)






other things tried
```

                                                                            
┌──(kali㉿kali)-[~/HTB]
└─$ keepass2john passcodes.kdbx > keepasshash
                                                                                                                                                                       
┌──(kali㉿kali)-[~/HTB]
└─$ cat keepasshash 
passcodes:$keepass$*2*60000*0*5d7b4747e5a278d572fb0a66fe187ae5d74a0e2f56a2aaaf4c4f2b8ca342597d*5b7ec1cf6889266a388abe398d7990a294bf2a581156f7a7452b4074479bdea7*08500fa5a52622ab89b0addfedd5a05c*411593ef0846fc1bb3db4f9bab515b42e58ade0c25096d15f090b0fe10161125*a4842b416f14723513c5fb704a2f49024a70818e786f07e68e82a6d3d7cdbcdc
                                                                                                                                                                       
┌──(kali㉿kali)-[~/HTB]
└─$ cut -d ":" keepasshash -f 2 > hash_only
                                                                                                                                                                       
┌──(kali㉿kali)-[~/HTB]
└─$ cat hash_only                          
$keepass$*2*60000*0*5d7b4747e5a278d572fb0a66fe187ae5d74a0e2f56a2aaaf4c4f2b8ca342597d*5b7ec1cf6889266a388abe398d7990a294bf2a581156f7a7452b4074479bdea7*08500fa5a52622ab89b0addfedd5a05c*411593ef0846fc1bb3db4f9bab515b42e58ade0c25096d15f090b0fe10161125*a4842b416f14723513c5fb704a2f49024a70818e786f07e68e82a6d3d7cdbcdc
                                                                                                                                                        
```
![](assets/Keeper_assets/Pasted%20image%2020230830130613.png)

```
hashcat.exe -m 13400  "hashes_to _crack\hashes.txt" -a 3 -1 ?l?1?1?1?1 ?1dgr?1d?1med?1fl?1de
 -O
```

`hashcat.exe -m 1800 "hashes_to _crack\hashes.txt" rockyou-50.txt -O








![](assets/Keeper_assets/Pasted%20image%2020230829235805.png)

modify referrer header in request in trying to create user
also try the XSS in creating a ticket
`scp lnorgaard@keeper.htb:/home/lnorgaard/passcodes.kbx .`


```
┌──(kali㉿kali)-[~/HTB/keepass-password-dumper]
└─$ sudo apt install keepass2


```