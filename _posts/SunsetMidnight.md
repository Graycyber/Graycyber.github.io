---
tags: wordpress
---
## Offsec PG: SunsetMidnight Writeup

***Overview**: SunsetMidnight is a Linux machine on Offensive Security Proving grounds rated as intermediate, this machine exploits upload of a vulnerable wordpress plugin to gain foothold and then exploits a system binary to elevate privileges.*

#### Enumeration
- so i begin by adding the ip to the /etc/hosts file `echo "192.168.169.88   sunset-midnight" | sudo tee -a /etc/hosts`
- then to get the version of the wordpress being used i run`curl http://sunset-midnight/ | grep 'content="WordPress'` and got WordPress 5.4.2'
![](SunsetMidnight_assets/Pasted%20image%2020221003032234.png)
- viewing the robots.txt file
![](SunsetMidnight_assets/Pasted%20image%2020221003032811.png)
- i run a port scan `nmap -sV -sC -p- -T4 192.168.169.88`
![](SunsetMidnight_assets/Pasted%20image%2020221003032858.png)
-  i also ran a directory scan `ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://sunset-midnight/FUZZ`
![](SunsetMidnight_assets/Pasted%20image%2020221012110100.png)
- then i further enumerate the wordpress site using wpscan`wpscan --url http://sunset-midnight/`
![](SunsetMidnight_assets/Pasted%20image%2020221003041346.png)
- i also enumerated for possible users using `wpscan --url http://sunset-midnight/ -e u` and got admin
![](SunsetMidnight_assets/Pasted%20image%2020221003041745.png)
- i tried bruteforcing the login but didn't get anything
`wpscan --url http://sunset-midnight/ -U admin -P /usr/share/wordlists/rockyou.txt`
- so i also tried bruteforcing the mysql root user using `hydra -l root -P /usr/share/wordlists/rockyou.txt 192.168.237.88 mysql -t 6 -V` and got a password robert
![](SunsetMidnight_assets/Pasted%20image%2020221012110420.png)
- now that i he the password of the mysql root user as robert, then i connect to the database using
`mysql -u root -h 192.168.237.88 -probert`
![](SunsetMidnight_assets/Pasted%20image%2020221011010441.png)
- then i can view the databases available and also the tables in the wordpress_db database
![](SunsetMidnight_assets/Pasted%20image%2020221011010717.png)
- then i view the content of the wp_users table
![](SunsetMidnight_assets/Pasted%20image%2020221011011804.png)
- i replaced the hash in the table with the md5 hash of 123456 which is e10adc3949ba59abbe56e057f20f883e, so i can log in with it, so i run `UPDATE wp_users SET user_pass = 'e10adc3949ba59abbe56e057f20f883e' WHERE id = 1;`
![](SunsetMidnight_assets/Pasted%20image%2020221011014041.png)
- and i am able to log in with admin and 123456 as the password at http://sunset-midnight/admin
![](SunsetMidnight_assets/Pasted%20image%2020221011014418.png)

#### Foothold
- now i tried editing the theme, so i can get a reverse shell but it didn't update for some reason
![](SunsetMidnight_assets/Pasted%20image%2020221011015135.png)
- since this didn't work i uploaded a malicious plugin using the script [https://github.com/wetw0rk/malicious-wordpress-plugin](https://github.com/wetw0rk/malicious-wordpress-plugin) and i got a meterpreter shell
![](SunsetMidnight_assets/Pasted%20image%2020221012092545.png)
- then looking through, i viewed the wordpress config file
![](SunsetMidnight_assets/Pasted%20image%2020221012093109.png)
![](SunsetMidnight_assets/Pasted%20image%2020221012093126.png)
- then i discovered a user jose with what i thought was the password hash, i tried cracking the hash, but didn't get a match, so tried using it to login and discovered it was the actual password
![](SunsetMidnight_assets/Pasted%20image%2020221012093805.png)
- i found the first flag in the home directory
![](SunsetMidnight_assets/Pasted%20image%2020221012101309.png)
#### Privilege Escalation
- so searching for SUID files i discovered the status binary
![](SunsetMidnight_assets/Pasted%20image%2020221012104325.png)
- then running strings on this binary, i saw that it was using the service binary as well
![](SunsetMidnight_assets/Pasted%20image%2020221012104731.png)
- so i then created a file service with the content `/bin/bash` to get a shell and then we add the location of the file which is /home/jose to path so that the serve script will get executed before the actual service binary
- running the `/usr/bin/status`, i then get root
![](SunsetMidnight_assets/Pasted%20image%2020221012105351.png)

 That's the end of the challenge, thanks for reading my blog :)