---
tags:
  - nibbleblog
---
***Overview**: Nibbles is an easy rated HTB machine that exploit a shell upload vulnerability on the Nibbleblog server in order to gain compromised access.*
# HTB: Nibbles

- So we start by scanning for open ports as well as the services running on those open ports

```shell
┌──(kali㉿kali)-[~/HTB/Nibbles]
└─$ sudo masscan -p1-65535 10.10.10.75 --rate=1000 -e tun0 > ports
[sudo] password for kali: 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2023-11-12 11:35:07 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
                                                                                                                                                                       
┌──(kali㉿kali)-[~/HTB/Nibbles]
└─$ cat ports 
Discovered open port 80/tcp on 10.10.10.75                                     
Discovered open port 22/tcp on 10.10.10.75                                     
                                                                                                                                                                       
┌──(kali㉿kali)-[~/HTB/Nibbles]
└─$ ports=$(cat ports | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')
                                                                                                                                                                       
┌──(kali㉿kali)-[~/HTB/Nibbles]
└─$ nmap -sV -sC -p$ports -oA nmap/nibbles_ports 10.10.10.75 -v
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-12 06:38 EST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 06:38
Completed NSE at 06:38, 0.00s elapsed
Initiating NSE at 06:38
Completed NSE at 06:38, 0.00s elapsed
Initiating NSE at 06:38
Completed NSE at 06:38, 0.00s elapsed
Initiating Ping Scan at 06:38
Scanning 10.10.10.75 [2 ports]
Completed Ping Scan at 06:38, 0.17s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 06:38
Completed Parallel DNS resolution of 1 host. at 06:38, 0.03s elapsed
Initiating Connect Scan at 06:38
Scanning 10.10.10.75 [2 ports]
Discovered open port 80/tcp on 10.10.10.75
Discovered open port 22/tcp on 10.10.10.75
Completed Connect Scan at 06:38, 0.16s elapsed (2 total ports)
Initiating Service scan at 06:38
Scanning 2 services on 10.10.10.75
Completed Service scan at 06:39, 6.36s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.10.75.
Initiating NSE at 06:39
Completed NSE at 06:39, 4.94s elapsed
Initiating NSE at 06:39
Completed NSE at 06:39, 0.71s elapsed
Initiating NSE at 06:39
Completed NSE at 06:39, 0.00s elapsed
Nmap scan report for 10.10.10.75
Host is up (0.16s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 06:39
Completed NSE at 06:39, 0.00s elapsed
Initiating NSE at 06:39
Completed NSE at 06:39, 0.00s elapsed
Initiating NSE at 06:39
Completed NSE at 06:39, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.66 seconds

```

- So navigating to the web server, we're presented with the below

![](assets/Nibbles_assets/Pasted%20image%2020231112123726.png)

- Then inspecting the page, we can see a hint on where to go next

![](assets/Nibbles_assets/Pasted%20image%2020231112123623.png)

- Navigating to the /nibbleblog directory, we can also see that the web server is runnign Nibbleblog


![](assets/Nibbles_assets/Pasted%20image%2020231112123757.png)

![](assets/Nibbles_assets/Pasted%20image%2020231112123940.png)

- we also fuzz for sub directories for the nibbleblog direcotry using ffuf and we see a few

```shell
ffuf -w /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://10.10.10.75/nibbleblog/FUZZ -e .php,.txt
```

![](assets/Nibbles_assets/Pasted%20image%2020231112125835.png)

## Explotiation

- So searching for any Nibbleblog exploits, we are can see that there exists an Arbitrary File Upload vulnerability for version Nibblieblog 4.0.3

![](assets/Nibbles_assets/Pasted%20image%2020231112124839.png)

- So trying  nibbleblog credentials of admin and nibbles, after a number of guessing attempts we got access to the nibbleblog dashboard

```ad-note
Machine name always mean something
```

![](assets/Nibbles_assets/Pasted%20image%2020231112133849.png)

- Understanding the shell upload vulnerability, we can view information about the manual exploitation of this vulnerability at [https://packetstormsecurity.com/files/133425/NibbleBlog-4.0.3-Shell-Upload.html](https://packetstormsecurity.com/files/133425/NibbleBlog-4.0.3-Shell-Upload.html)

![](assets/Nibbles_assets/Pasted%20image%2020231112155724.png)

- so we can upload a reverse shell manually like below

![](assets/Nibbles_assets/Pasted%20image%2020231112143448.png)

- then execute the script at the `/nibbleblog/content` directory 

![](assets/Nibbles_assets/Pasted%20image%2020231112153028.png)

- and then we should have a shell in our nc listener

![](assets/Nibbles_assets/Pasted%20image%2020231112153055.png)

- or we can utilize the nibbleblog_file_upload exploit in metasploit instead to get a shell

![](assets/Nibbles_assets/Pasted%20image%2020231112154047.png)

- so we can view the user flag

![](assets/Nibbles_assets/Pasted%20image%2020231112154236.png)

- we can also see that we have a zip archive, so we can unzip to view the contents and we see we have a script monitor.sh

![](assets/Nibbles_assets/Pasted%20image%2020231112154620.png)

## Privilege Escalation
- we can see what commands we can run as sudo and that is the monitor.sh file which we unzipped

![](assets/Nibbles_assets/Pasted%20image%2020231112154430.png)

- since we have write access on the file, we can just do the following to append to the script

```
echo "su root" >> monitor.sh
```

- if we cat the file, we can see the command has been appended

![](assets/Nibbles_assets/Pasted%20image%2020231112155157.png)

- so we run the script using sudo and we can see we now have root access

![](assets/Nibbles_assets/Pasted%20image%2020231112155223.png)

- we can also view the root flag now

![](assets/Nibbles_assets/Pasted%20image%2020231112155412.png)





tried but did not work
`hydra -L users.txt -P pass.txt <service://server> <options>`
![](assets/Nibbles_assets/Pasted%20image%2020231112131017.png)
username=test&password=test&remember=1
`hydra -l admin  -P /usr/share/wordlists/rockyou.txt 10.10.10.75 http-post-form "/nibbleblog/admin.php:username=^USER^&password=^PASS^&remember=1:Incorrect username or password" -f -V`

![](assets/Nibbles_assets/Pasted%20image%2020231112131746.png)
![](assets/Nibbles_assets/Pasted%20image%2020231112131758.png)

it shows error because of too many login attempts