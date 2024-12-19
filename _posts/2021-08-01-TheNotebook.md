---
title: "TheNotebook - HackTheBox"
layout: single
excerpt: "This is a medium difficulty machine, for the cookie intrusion I was able to find out that I was dealing with a JWT attack, to break it I created a new cookie pulling my private key through a Python server and changed the panel, it had an option to upload files, I created a reverse shell and uploaded it, for the privilege escalation I took advantage of a vulnerable version of Docker."
header:
show_date: true
classes: wide
header:
  teaser: "https://user-images.githubusercontent.com/69093629/127784478-22759c0e-2a0d-4735-b467-ccb39e2e8b18.png"
  teaser_home_page: true
  icon: "https://user-images.githubusercontent.com/69093629/125662338-fd8b3b19-3a48-4fb0-b07c-86c047265082.png"
categories:
  - HackTheBox
tags:
  - PHP
  - Docker
  - JWT
  - SSH
---

![image (35)](https://user-images.githubusercontent.com/69093629/129931228-f352f4a7-ecdb-49ef-9786-099fcce0e627.png)

I started by doing a scan with `Nmap` to detect open ports.

```bash 
┌──(root💀kali)-[/home/wackyh4cker/HTB/TheNotebook]
└─# nmap -sS --min-rate=5000 --open -v -n 10.10.10.230 -oN targeted
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-31 19:12 CEST
Initiating Ping Scan at 19:12
Scanning 10.10.10.230 [4 ports]
Completed Ping Scan at 19:12, 0.08s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 19:12
Scanning 10.10.10.230 [1000 ports]
Discovered open port 80/tcp on 10.10.10.230
Discovered open port 22/tcp on 10.10.10.230
Completed SYN Stealth Scan at 19:12, 0.47s elapsed (1000 total ports)
Nmap scan report for 10.10.10.230
Host is up (0.15s latency).
Not shown: 997 closed ports, 1 filtered port
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.73 seconds
       	Raw packets sent: 1014 (44.592KB) | Rcvd: 1009 (40.356KB)
```

I made another one to detect the version of each open port found.

```bash
┌──(root💀kali)-[/home/wackyh4cker/HTB/TheNotebook]
└─# nmap -sC -sV -p22,80 10.10.10.230 -oN webscan             	 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-31 19:12 CEST
Nmap scan report for 10.10.10.230
Host is up (0.069s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh 	OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 2048 86:df:10:fd:27:a3:fb:d8:36:a7:ed:90:95:33:f5:bf (RSA)
|   256 e7:81:d6:6c:df:ce:b7:30:03:91:5c:b5:13:42:06:44 (ECDSA)
|_ 256 c6:06:34:c7:fc:00:c4:62:06:c2:36:0e:ee:5e:bf:6b (ED25519)
80/tcp open  http	nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: The Notebook - Your Note Keeper
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.04 seconds
```

I had two ports open, I started by looking at the web server, this is what I had.

![PaginaPrincipal](https://user-images.githubusercontent.com/69093629/127784555-be9394f6-a112-45ac-b968-e899bfe8c4af.png)

I signed up and was redirected to this dashboard.

![accesoalpanel](https://user-images.githubusercontent.com/69093629/127784565-718e0d46-ffd0-434e-9970-739318080035.png)

I created a note and tried different `html` and `js` code injections but it was not vulnerable to `XSS` or `HTMLi`, I tried to intercept the request to see how everything goes behind the scenes and I found a cookie that caught my attention.

![jwtcookie](https://user-images.githubusercontent.com/69093629/127784626-d6684b12-cd00-4841-a60d-cda619895db7.png)

It appears to be a `JWT` or "JSON Web Token", I copied the cookie and pasted it into [jwt.io](https://jwt.io) to see the `json` format it was being treated in and found the following.

![jwtio](https://user-images.githubusercontent.com/69093629/127784670-55e9afce-d921-48ee-8db2-f2cde7935c9b.png)

It seemed to be communicating with a `priv key` on `localhost`, meaning it didn't have any kind of access to it, so I thought about creating my own with `OpenSSL` and then going for it by opening a server with `Python`, I started by creating the private key with the following command.

```bash
openssl genrsa -out privKey.key 2048
``` 

I opened a `python` server on the port the victim's `priv key` was running on, `7070`, and changed to my `IP` address and put `1` in `admin_cap` and pasted my `priv key` down on the left.

![code](https://user-images.githubusercontent.com/69093629/127784840-d48b22b0-a2a6-4aac-a821-1bf7a629f685.png)

I copied the string in `base64` and replaced it with the cookie that came to me on the page.

![paneladminconseguido](https://user-images.githubusercontent.com/69093629/127784916-d01dd378-0ac6-4cb2-9ee1-7d5a494add28.png)

And I changed the panel, now there was a section that allowed me to upload files.

![uploadfiles](https://user-images.githubusercontent.com/69093629/127784939-95aaa155-21b1-4328-98ee-66c58794d699.png)

I immediately tried to upload a `reverse shell` in PHP, I used one from `pentestmonkey`.

![subida](https://user-images.githubusercontent.com/69093629/127784972-88b14e18-19fb-45fc-9e7a-e2a5aea08dc0.png)

It let me upload it, I hit `save` with a `netcat` session running on port '443' and gained access to the machine.

![reverseshell (1)](https://user-images.githubusercontent.com/69093629/127785005-a0a7153c-f609-4079-8ba6-ab006cff7e60.png)

I did some work around with the `TTY`, doing some research on the machine and found a file called `home.tar.gz` that caught my eye, so I thought I'd transfer it to my machine with `netcat`.

![transferusingnmap](https://user-images.githubusercontent.com/69093629/127785044-0f98c96a-e111-4c53-bb96-4878f3e6057f.png)

Unzipping it I saw that it was the `home` directory, inside I found an `SSH` private key, an `id_rsa`, I also had to list the user I had to migrate under and in the path I followed I found a directory called `noah`.

![ypadentroconhome](https://user-images.githubusercontent.com/69093629/127785072-76c5a770-7284-47a9-ba7e-a8300a94fec1.png)

I gave `600` permissions to the `id_rsa` and tried connecting to it via `SSH` using the `noah` user and it worked.

![ssshacceso](https://user-images.githubusercontent.com/69093629/127785391-bec76498-0971-405a-9f70-2c52ce270879.png)

I was now able to view the user's "flag".

![flagdelusuario (3)](https://user-images.githubusercontent.com/69093629/127785441-cdc9b061-7d1b-4a08-b252-ae66a8e78296.jpg)

<hr>
<h1 align="center"><b>ESCALADA DE PRIVILEGIOS</b></h1>

Now all that was missing was the privilege escalation, doing `sudo -l` I saw that I could run Docker with `sudo` privileges.

![sudoguionele](https://user-images.githubusercontent.com/69093629/127785458-6b7c09ad-a0c9-49d2-924c-99da531f2a12.png)

I ran it by adding `bash` and got a session with Docker, but this was not escalation as it was just in a container, look at the Docker version.

![dockerversion](https://user-images.githubusercontent.com/69093629/127785504-8970f5a3-4746-4710-8e71-e1837766edc3.png)

I searched for an exploit for that version on Google and found the following `PoC`.

![pocdockerexploit](https://user-images.githubusercontent.com/69093629/127785520-25394cde-7733-416a-9ec6-f9bf94b0f215.png)

I brought it to my machine and modified the line that executed the code, I put it to give `777` permissions to `/etc/passwd`.

![modificandoetchosts](https://user-images.githubusercontent.com/69093629/127785669-327b2f5d-b0c4-4b7b-af24-403bf5e4ab4e.png)

I compiled the exploit and transferred it to the victim server, specifically in the Docker session, run the exploit by running another Docker session at the same time as the exploit is running.

![descargarexploit (1) (1)](https://user-images.githubusercontent.com/69093629/127785892-1faeee6d-f798-4dad-9b86-6d4eadca10e4.png)

I modified the `x` of `/etc/passwd` and put a password previously created with `OpenSSL`, I did `sudo su` and put the password that `OpenSSL` created for me and gained access with `root`, I could now see the "flag".

![bashmenosoe (1)](https://user-images.githubusercontent.com/69093629/127785688-60e6f17c-073c-4f7e-9139-9387f8cb17a4.png)











