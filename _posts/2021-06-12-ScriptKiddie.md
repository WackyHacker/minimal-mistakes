---
title: "ScriptKiddie - HackTheBox"
layout: single
excerpt: "This is an easy difficulty machine, I liked the intrusion better, for its intrusion I took advantage of a file upload field, I used a script that created the malicious template, I uploaded it, I listened with netcat and gained a Shell. For privilege escalation I used the sudo -ly command and like all users it allowed me to execute the Metasploit binary."
header:
show_date: true
classes: wide
header:
  teaser: "https://user-images.githubusercontent.com/69093629/124383644-d2531a00-dccd-11eb-9c08-fca9e5557500.png"
  teaser_home_page: true
  icon: "https://user-images.githubusercontent.com/69093629/125662338-fd8b3b19-3a48-4fb0-b07c-86c047265082.png"
categories:
  - HackTheBox
tags:
  - WriteUp
---

<p align="center">
<img src="https://user-images.githubusercontent.com/69093629/124676571-10fbf680-debf-11eb-975d-7e2aa7e95deb.png">
</p>

I started by doing a scan with Nmap to see what ports and services the server had running.

```bash
┌─[root@parrot]─[/home/wackyhacker/Desktop]
└──╼ nmap -sS --min-rate=5000 -p- -v -Pn -n 10.10.10.226 -oG allports

Starting Nmap 7.80 ( https://nmap.org ) at 2021-06-12 11:26 CEST
Initiating SYN Stealth Scan at 11:26
Scanning 10.10.10.226 [65535 ports]
Discovered open port 22/tcp on 10.10.10.226
Discovered open port 5000/tcp on 10.10.10.226
Completed SYN Stealth Scan at 11:27, 13.04s elapsed (65535 total ports)
Nmap scan report for 10.10.10.226
Host is up (0.13s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.12 seconds
           Raw packets sent: 65641 (2.888MB) | Rcvd: 65543 (2.622MB)
``` 

Once the scan was complete, I ran another scan to determine what version of ports 22 and 5000 were running.

```bash
┌─[root@parrot]─[/home/wackyhacker/Desktop]
└──╼ nmap -sC -sV -p22,5000 10.10.10.226 -oN targeted      
 
Starting Nmap 7.80 ( https://nmap.org ) at 2021-06-12 11:28 CEST
Nmap scan report for 10.10.10.226
Host is up (0.042s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
5000/tcp open http tool httpd 0.16.1 (Python 3.8.5)
|_http-title: k1d'5 h4ck3r t00l5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.86 seconds
```

Port 22 was SSH version 8.2p1 and was running on an Ubuntu system, and port 5000 is a web server, I started enumerating the web server to see what it brought up, this was the result.

![image](https://user-images.githubusercontent.com/69093629/121775004-59a4e600-cb85-11eb-9afe-09c9d5ac8f02.png)

I started trying command injections into the buffers that were there, but nothing interesting.

![Captura de pantalla (504)](https://user-images.githubusercontent.com/69093629/121785032-b9b48000-cbb7-11eb-8f0e-93e43ebdad7f.png)

Until I decided on the middle buffer that allowed me to upload a file, I put *template file (optional)*, searched for *template apk* in searchsploit and found the following "exploit" made in Metasploit.

![Captura de pantalla (505)](https://user-images.githubusercontent.com/69093629/121785124-40695d00-cbb8-11eb-85b2-e1cafd29153c.png)

Examine el "exploit".

![Screenshot (506)](https://user-images.githubusercontent.com/69093629/121785156-74dd1900-cbb8-11eb-82f1-04c1de91f090.png)

Once I found the *CVE*, I went to Google and searched for an exploit on GitHub that I could use to exploit it.

![Screenshot (507)](https://user-images.githubusercontent.com/69093629/121785296-4e6bad80-cbb9-11eb-9238-b74e9516e303.png)

I came across the following repository.

![Screenshot (508)](https://user-images.githubusercontent.com/69093629/121785321-73f8b700-cbb9-11eb-94d3-71db240ad95e.png)

I downloaded it.

```bash
┌─[root@parrot]─[/home/wackyhacker/Desktop]
└──╼ wget https://raw.githubusercontent.com/nikhil1232/CVE-2020-7384/main/CVE-2020-7384.sh

--2021-06-12 11:33:41--  https://raw.githubusercontent.com/nikhil1232/CVE-2020-7384/main/CVE-2020-7384.sh
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 185.199.110.133, 185.199.111.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)[185.199.109.133]:443... connected.
HTTP request sent, waiting for response... 200 OK
Longitud: 2183 (2,1K) [text/plain]
Recording to: “CVE-2020-7384.sh”

CVE-2020-7384.sh 100%[================================================================ ===================================================== ==========>] 2.13K --.-KB/s at 0s      

2021-06-12 11:33:41 (14.3 MB/s) - “CVE-2020-7384.sh” saved [2183/2183]
```

I ran it and it created a malicious template for "netcat", I used port 443 plus the IP of tun0 [10.10.16.5], I named it exploit.apk.

![Captura de pantalla (509)](https://user-images.githubusercontent.com/69093629/121785375-cb972280-cbb9-11eb-9c09-18928d027278.png)

I uploaded it to the server, put my IP in the buffer and selected Android as the operating system.

![Screenshot (510)](https://user-images.githubusercontent.com/69093629/121785521-7c052680-cbba-11eb-9432-d6ef1b19c50f.png)

And I gave myself a shell via Netcat.

![Screenshot (511)](https://user-images.githubusercontent.com/69093629/121785549-b7075a00-cbba-11eb-80f7-cc9eef28fa74.png)

The user's "flag" was located in */home/kid/user.txt*, I did a *cat* to view it.

![voam](https://user-images.githubusercontent.com/69093629/121785702-9e4b7400-cbbb-11eb-994e-8d7dd9b58e3c.jpg)

I did a *TTY* treatment to be more comfortable.

![Screenshot (512)](https://user-images.githubusercontent.com/69093629/121785592-f46be780-cbba-11eb-9a75-303212eb5eb1.png)

<hr>
<h1 align="center"><b>ESCALADA DE PRIVILEGIOS</b></h1>

In */home/pwn* I found a script called scanlosers.sh, I saw what it did.

![Screenshot (514)](https://user-images.githubusercontent.com/69093629/121785788-203b9d00-cbbc-11eb-8c35-9088ee75e64f.png)

I was declaring the log variable with an absolute system path */home/kid/logs/hackers*, then accessing */home/pwn*, doing a *log* filter, after that running an Nmap session concatenating the *ip* variable and finally doing a "if greater than 0" comparison on the lines contained in the *log* variable.
I went to */home/kid/logs/hackers* and started trying command injections based on the script's programming, until I managed to find one that executed the command I wanted, forced the execution of the next command using ";" and the command I wanted, I redirected the output to the hackers file which was where the script pointed to, I also commented the following so that there would be no problem, I ran the *whoami* command as a test and the response was pwn (**the hackers file was not readable**).

![Screenshot (515)](https://user-images.githubusercontent.com/69093629/121786129-419d8880-cbbe-11eb-8da4-584cfb15c165.png)

I started a reverse shell via Netcat.

![Captura de pantalla (516)](https://user-images.githubusercontent.com/69093629/121786245-e7e98e00-cbbe-11eb-977d-a96dc36a99a3.png)

And I became the pwn user, I just needed to escalate privileges, I checked if I could run something as ROOT and to my surprise I had the ability to run the Metasploit binary as the ROOT user, I just ran ```sudo``` plus the Metasploit binary in */root/root.txt* was the *flag*.

![Screenshot (517)](https://user-images.githubusercontent.com/69093629/121786348-9e4d7300-cbbf-11eb-9bd3-f036886b4e55.jpg)


