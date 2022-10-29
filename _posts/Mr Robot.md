---
tags: wordpress, nmap
---
# Tryhackme: MrRobot

***Overview**: MrRobot is a LInux machine on Tryhackme rated as Easy, this machine exploits a wordpress theme to gain foothold using a reverse shell and after pivoting to another user using found credentials, it escalated privileges to root by exploit the nmap binary running with SUID permissions.*
- going to the site, I'm displayed with the page below
![](Mr%20Robot_assets/Pasted%20image%2020221022192447.png)
- prepare command gave a video and the rest of the commands din't give anything useful as well
- so going to the robots.txt directory and can see 2 files
![](Mr%20Robot_assets/Pasted%20image%2020221022194302.png)
- the key-1-of-3.txt file, I got the first key
![](Mr%20Robot_assets/Pasted%20image%2020221022194725.png)
- then viewing the other directory, I saw a list of words, so I save it in a file
![](Mr%20Robot_assets/Pasted%20image%2020221022195024.png)
- I did an nmap scan to discover the open ports and services `nmap -sV -sC -T4 -p- 10.10.245.237`
![](Mr%20Robot_assets/Pasted%20image%2020221022195143.png)
- I also ran a ffuf scan to find the list of directories `ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://10.10.55.237/FUZZ`. and looking at the directories I can tell that it is a wordpress site
![](Mr%20Robot_assets/Pasted%20image%2020221022204353.png)
- viewing the sitemap and sitemap.xml directories and it shows the error
![](Mr%20Robot_assets/Pasted%20image%2020221022200712.png)
- since it is a wordpress site, I enumerated for users, vulnerable plugins and themes with wpscan `wpscan --url http://10.10.55.237/ -e u,vp,vt`
![](Mr%20Robot_assets/Pasted%20image%2020221022203907.png)
- looking at directories found, I viewed the readme but got nothing reasonable
![](Mr%20Robot_assets/Pasted%20image%2020221022204248.png)
- Since I found I login page for the wordpress site, i decided to bruteforce with burp using the fsocity.dic file found, so I intercept with burp and send to intruder
![](Mr%20Robot_assets/Pasted%20image%2020221022220831.png)
- then set the payload options as the list in the fsocity.dic file
![](Mr%20Robot_assets/Pasted%20image%2020221025093827.png)
- Also set the grep match feature, to filter based on the error specified, so we will add the Invalid username error cause it's given to us when we try to login with invalid credentials, we want to know if one of the entries gives a different error
![](Mr%20Robot_assets/Pasted%20image%2020221022220344.png)
```ad-note
If it error is formatted like in bold or sth, it won't filter for some reason.
```
- and starting the attack, I saw a change in length for the word Elliot for then the invalid username is also blank
![](Mr%20Robot_assets/Pasted%20image%2020221025094101.png)
- so i then try logging in with the Elliot but with an invalid password and got another error
![](Mr%20Robot_assets/Pasted%20image%2020221025094252.png)
- so we will add the error "The password you entered for the username **Elliot** is incorrect" that to our Grep match feature and then change the username from the intruder the Elliot and bruteforce for the password 

**Note**: We can also bruteforce with hydra using the syntax `hydra -l Elliot -P fsocity.dic 10.10.46.174 http-post-form "/wp-login:log=Elliot&pwd=^PASS^:F=The password you entered for the username" -vV`
- While running the attack, i kept enumerating the directories found, viewing the license directory and inspecting the page, i found an encoded base64 text
![](Mr%20Robot_assets/Pasted%20image%2020221022204601.png)
- decoding the text i get the login credentials of the user elliot
![](Mr%20Robot_assets/Pasted%20image%2020221022205047.png)
- so now, since I found the credentials, there isn't a need to keep bruteforcing with burp
- going to the login page, I then login with the credentials found
![](Mr%20Robot_assets/Pasted%20image%2020221022211142.png)
- logging in, I see the dashboard
![](Mr%20Robot_assets/Pasted%20image%2020221022215942.png)
- so I decided to upload a reverse shell script in a wordpress theme editor
![](Mr%20Robot_assets/Pasted%20image%2020221022213603.png)
- then putting up an nmap listener and then going to the link http://10.10.132.141/wp-content/themes/twentyfifteen/404.php and I got a shell
![](Mr%20Robot_assets/Pasted%20image%2020221022213531.png)
- then i got a more interactive `python3 -c 'import pty;pty.spawn("/bin/bash")'`
![](Mr%20Robot_assets/Pasted%20image%2020221022213745.png)
- I couldn't view the second key as the current user, but i found the credentials of the robot user with it hash
![](Mr%20Robot_assets/Pasted%20image%2020221022213837.png)
- so cracking the md5 hash, i got the robot user's password
![](Mr%20Robot_assets/Pasted%20image%2020221022214102.png)
- I was then able to switch to the robot user and view the passwor
![](Mr%20Robot_assets/Pasted%20image%2020221022225649.png)
- then I got linpeas to the tmp directory and ran it
![](Mr%20Robot_assets/Pasted%20image%2020221022214453.png)
- analysing the results of linpeas script and I saw nmap binary was running SUID permissions
![](Mr%20Robot_assets/Pasted%20image%2020221022215419.png)
- so from gtfobins i was able to get how to elevate privileges and then running it I got it
![](Mr%20Robot_assets/Pasted%20image%2020221022215519.png)
- I then found the third key in the root directory
![](Mr%20Robot_assets/Pasted%20image%2020221022215706.png)

Resource:
- [Brute-focing Sites with Hydra](https://infinitelogins.com/2020/02/22/how-to-brute-force-websites-using-hydra/)