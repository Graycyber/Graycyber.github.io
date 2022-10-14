---
tags: wordpress, gtfobins, rbash, cewl. wpscan
---
## Offsec PG: DC-2

***Overview**: DC-2 is a Linux machine on Offensive Security Proving grounds rated as easy, this machine exploits a Wordpress site to gain foothold from generated wordlist and also exploits pivoting to another user with access to a binary that can be exploited to escalated privileges.*

#### Enumeration
- firstly add it to the /etc/hosts file `echo "192.168.243.194   dc-2" | sudo tee -a /etc/hosts`
- then go to the site 
![](DC-2_assets/Pasted%20image%2020221013144419.png)
-  i then scan for directories `ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://192.168.243.194/FUZZ`
![](DC-2_assets/Pasted%20image%2020221013145635.png)
- i also scan for open ports and services `nmap -sV -sC -T4 192.168.243.194`
![](DC-2_assets/Pasted%20image%2020221014190011.png)
- check for users with wpcan `wpscan --url http://dc-2/ -e u` and found admin, jerry & tom
![](DC-2_assets/Pasted%20image%2020221013145943.png)
 WordPress version 4.7.10
![](DC-2_assets/Pasted%20image%2020221013150158.png)
- looking at the flag section of the page, we get a clue on what we are to do
![](DC-2_assets/Pasted%20image%2020221013151833.png)
- so now i will use the Cewl tool to generate a wordlist. Cewl is a Ruby program that crawls a URL or site and produce a list of keywords that can be used by password crackers to crack passwords. so the syntax is `cewl http://dc-2/ -w passwords.txt` and our list is saved in password.txt
-  I bruteforce the list of users with the passwords using WPScan `wpscan --url http://dc-2/ -U users.txt -P passwords.txt`
![](DC-2_assets/Pasted%20image%2020221013152529.png)
- then i discovered the password for jerry as adipiscing and tom as parturient
- logging in a jerry and found the second file
![](DC-2_assets/Pasted%20image%2020221013153649.png)

#### FootHold
- by another entry point, it means ssh which is on port 7744 as seen in out nmap scan so i then `ssh tom@dc-2 -p 7744` and use tom's password
![](DC-2_assets/Pasted%20image%2020221013162135.png)
- trying to view the files, i discover that i am in a restricted shell and can use the cat binary and i can only access vi
![](DC-2_assets/Pasted%20image%2020221014184205.png)
- so i use vi to view the files and and got the flag in local.txt and also vied the 3rd hint
![](DC-2_assets/Pasted%20image%2020221013162409.png)
 - so since I can use the vi binary, I can break out of the restricted shell, firstly i open the flag3.txt file and then run the following
```text
:set shell=/bin/sh
:shell
```
- by running the following commands, i am setting the $PATH and $SHELL variables, setting the $PATH, variable so the binaries like `whoami` can be executed easily without specifying the full path and the set the shell as bash.
![](DC-2_assets/Pasted%20image%2020221013165926.png)
- looking at the 3rd flag, it tells us to switch the user to Jerry so I run `su jerry` and then enter jerry's password as adipiscing and i get access as jerry
![](DC-2_assets/Pasted%20image%2020221013172812.png)
#### Privilege Escalation
- then i view the 4th flag in jerry's home directory 
![](DC-2_assets/Pasted%20image%2020221014184906.png)
- now all I have to do is to escalate privileges, running `sudo -l` command, i can see the user jerry can run the git binary with sudo privileged and without a password
![](DC-2_assets/Pasted%20image%2020221013172828.png)
- looking a gtfobins i see that i can run the following commands
![](DC-2_assets/Pasted%20image%2020221014185256.png)
- running them, i finally get root access
![](DC-2_assets/Pasted%20image%2020221014185400.png)

That'll be then end of my writeup. Thank you for reading my blog :)