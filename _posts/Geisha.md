## PG: Geisha Writeup

***Overview***: *Geisha is a Linux machine on Offensive Security Proving Grounds which is rated Easy, and the goal is to obtain root access*.

#### Scanning and Enumeration
- So I firstly inspect the webpage for relevant information or clues but i get none
![](Geisha_assets/Pasted%20image%2020220927164613.png)
- then i run a port scan using nmap `nmap -sV -sC -p- -T4 192.168.155.82`
![](Geisha_assets/Pasted%20image%2020220927185427.png)
- viewing the port 8088, i didn't find any relevant information and its just like the default page
![](Geisha_assets/Pasted%20image%2020220927164632.png)
- I scanned for directories using ffuf `ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://192.168.155.82/FUZZ `
- then i scanned port 8088 and got the following directories
![](Geisha_assets/Pasted%20image%2020220927171405.png)
- Viewing the /docs directory i found the documentation for OpenLiteSpeed Server, so we know the the version of the litespeed server
![](Geisha_assets/Pasted%20image%2020220927164746.png)
- viewing the other directories i get
![](Geisha_assets/Pasted%20image%2020220927175715.png)
- since i saw the ssh port open,  and guessing the username as geisha, i decided to bruteforce using hydra `hydra -l geisha -P /usr/share/wordlists/rockyou.txt ssh://192.168.155.82/ -t 6 -V` and got the password letmein
![](Geisha_assets/Pasted%20image%2020220927180237.png)
#### Exploitation and Foothold
- then i logged in using the password found and got foothold 
![](Geisha_assets/Pasted%20image%2020220927180338.png)
- then i got the user flag in the home directory
![](Geisha_assets/Pasted%20image%2020220927183639.png)
#### Privileged Escalation
- then i run the `id` command to see the groups the user is associated with
![](Geisha_assets/Pasted%20image%2020220927180548.png)
- so i search for SUID files using the command `find / -perm /2000 2>/dev/null` and discover the base32 binary
![](Geisha_assets/Pasted%20image%2020220927180648.png)
- i also verified it in my linpeas output
![](Geisha_assets/Pasted%20image%2020220927181110.png)
- then looking at gtfobins on how to exploit the base32 binary when it has the SUID bit set, and i saw that we can use this command to read unauthorised files
![](Geisha_assets/Pasted%20image%2020220927182705.png)
- we can guess the file name for the root flag as proof.txt and  the command `base32 "/root/proof.txt" | base32 --decode` to get the flag
![](Geisha_assets/Pasted%20image%2020220927183546.png)
- we can also obtain the identity file of the root user and login using it, so i run `base32 "/root/.ssh/id_rsa" | base32 --decode` and get the contents of the identity file
![](Geisha_assets/Pasted%20image%2020220927193620.png)
- then i save it in a file named id and run `ssh root@192.168.70.82 -i id` and finally get root access
![](Geisha_assets/Pasted%20image%2020220927193832.png)