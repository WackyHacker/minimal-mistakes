---
title: "Armageddon - HackTheBox"
layout: single
excerpt: "This is an easy machine, for the intrusion I took advantage of a vulnerable version of Drupal that was running on the system and gained RCE, I had to migrate to another user, for this I found MySQL credentials that helped me find a hash, after breaking it the credential was of the user I had to migrate to, for the privilege escalation I took advantage of snap, since it could be executed with sudo privileges."
header:
show_date: true
classes: wide
header:
  teaser: "https://user-images.githubusercontent.com/69093629/127804995-eba40d50-e9ad-43a8-bb7b-b88434fdad40.png"
  teaser_home_page: true
  icon: "https://user-images.githubusercontent.com/69093629/125662338-fd8b3b19-3a48-4fb0-b07c-86c047265082.png"
categories:
  - HackTheBox
tags:
  - mysql
  - Drupal
  - snap
  - SSH
---

<p align="center">
<img src="https://user-images.githubusercontent.com/69093629/129924671-d8937044-7ee4-4b35-8791-7c8261d5d903.png">
</p>

I started by running an `Nmap` scan to detect open ports and services on the system.

```bash 
┌──(root💀kali)-[/home/wackyh4cker/HTB/Armageddon]
└─$ nmap -sS --min-rate=5000 --open -v -n 10.10.10.233 -oN targeted            	 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-29 18:59 CEST
Initiating Ping Scan at 18:59
Scanning 10.10.10.233 [4 ports]
Completed Ping Scan at 18:59, 0.07s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 18:59
Scanning 10.10.10.233 [1000 ports]
Discovered open port 22/tcp on 10.10.10.233
Discovered open port 80/tcp on 10.10.10.233
Completed SYN Stealth Scan at 18:59, 0.68s elapsed (1000 total ports)
Nmap scan report for 10.10.10.233
Host is up (0.094s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.97 seconds
       	Raw packets sent: 1825 (80.276KB) | Rcvd: 1811 (72.436KB)
 ```
 
 I did another scan to detect the version of each service found.
 
 ```bash 
┌──(root💀kali)-[/home/wackyh4cker/HTB/Armageddon]
└─$ nmap -sC -sV -p22,80 10.10.10.233 -oN webscan             	 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-29 19:00 CEST
Nmap scan report for 10.10.10.233
Host is up (0.037s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh 	OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey:
| 2048 82:c6:bb:c7:02:6a:93:bb:7c:cb:dd:9c:30:93:79:34 (RSA)
| 256 3a:ca:95:30:f3:12:d7:ca:45:05:bc:c7:f1:16:bb:fc (ECDSA)
|_ 256 7a:d4:b3:68:79:cf:62:8a:7d:5a:61:e7:06:0f:5f:33 (ED25519)
80/tcp open  http	Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-generator: Drupal 7 (http://drupal.org)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Welcome to  Armageddon |  Armageddon

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.31 seconds
```

I saw that he had a web server, I took a look at it.

![armageddon](https://user-images.githubusercontent.com/69093629/127578672-548a6401-10d7-430d-a01c-835523da332f.png)

I found a Drupal CMS, thought I'd check if there was any exploit and found the following.

![exploit](https://user-images.githubusercontent.com/69093629/127578743-4233e86c-f010-478e-96ec-558de362dbdf.png)

I executed it by giving it the website URL and it granted me arbitrary code execution.

![drupalgeddon2](https://user-images.githubusercontent.com/69093629/127578821-64748b45-715f-49ea-b03f-1a8a789a767a.png)

Now all that was left was to open a reverse shell to gain access to the machine. I tried a `bash` `reverse shell` but it detected a "bad character", so I had to use a `python` one.

![entrada](https://user-images.githubusercontent.com/69093629/127578935-84be425c-c97e-4f50-9415-c7ce2b71ce73.png)

And I got a connection via `netcat`

![reverseshell](https://user-images.githubusercontent.com/69093629/127578974-241fd99f-8b3f-4783-80d6-ac0d648f7737.png)

After a little research on `Google` I found that credentials are stored in a file called `settings.php`.

![credencialesdrupal](https://user-images.githubusercontent.com/69093629/127579080-1bfebdce-534d-4b71-81e1-1f2f3992d6e4.png)

I filtered that file with `find` and found credentials

![drupalcreds](https://user-images.githubusercontent.com/69093629/127579123-79d4bb64-5c8c-4d18-8ad7-fb7e86012ce8.png)

It was a user and a password, I tried in `SSH` but it didn't work, but when I tried in `mysql` it did work, but it hung, so I had to execute the statement in the same command, I tried to list the tables.

![tables](https://user-images.githubusercontent.com/69093629/127579240-4228535d-4557-45ec-bcbf-81f197f88ba5.png)

The `users` table caught my attention so I selected `name` and `pass` from the `users` column and it reported a `hash`.

![hashdecontra (1)](https://user-images.githubusercontent.com/69093629/127579502-c8690364-ef70-4c36-a0bd-6f458cf0f5f3.png)

I was able to brute force crack it with `john`.

```bash
┌──(root💀kali)-[/home/wackyh4cker/HTB/Armageddon/Drupalgeddon2
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash                                                                                                	 
Using default input encoding: UTF-8
Loaded 1 password hash (Drupal7, $S$ [SHA512 128/128 SSE2 2x])
Cost 1 (iteration count) is 32768 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
booboo       	(?)
1g 0:00:00:01 DONE (2021-07-29 20:00) 0.7407g/s 171.8p/s 171.8c/s 171.8C/s courtney..harley
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

This credential authenticates me via `SSH` using the system user `brucetherealadmin`.

![sshypadentro](https://user-images.githubusercontent.com/69093629/127580332-0e65c9f8-28cd-451f-8e50-314742db01f9.png)

I was now able to view the user's "flag".

![flagdelusuario (2)](https://user-images.githubusercontent.com/69093629/127579644-4ec95b78-ef93-4fa2-b47b-f5694ec3cac3.jpg)

<hr>
<h1 align="center"><b>ESCALADA DE PRIVILEGIOS</b></h1>

For privilege escalation it allowed me to run `snap` with `sudo` permissions, I searched in [gtfobins](https://gtfobins.github.io) and found that I could take advantage of it by using `sudo`.

![Screenshot (661)](https://user-images.githubusercontent.com/69093629/127579819-ada222e3-d01a-4b9f-bbe1-aeb66e3aedae.png)

When running a command I got a problem that I was able to solve by installing the corresponding gem.

```ruby
┌──(root💀kali)-[/home/wackyh4cker/HTB/Armageddon/Drupalgeddon2
└─$ gem install fpm
```

Now if I let the malicious `.snap` file be created on my machine, I had it run `cat /root/root.txt` to see the `root` flag.
        
![verlaflag](https://user-images.githubusercontent.com/69093629/127580026-55b17835-313b-4377-807b-9492dca7ca03.png)

Once exported to the victim machine I used the command that allowed me to execute `snap` with `sudo` privileges and selecting my `.snap` followed by the parameters `--dangerous` and `--devmode` and it reported the "flag" in clear text.

![laflag](https://user-images.githubusercontent.com/69093629/127580209-10840b2e-8a23-477f-a3aa-1a582f79aab1.jpg)



