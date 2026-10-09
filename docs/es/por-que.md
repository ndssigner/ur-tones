# Por qué ur-tones

*[English](../why.md)*

## Un firmador sin cámara ni pantalla grande

[SeedSigner](https://seedsigner.com) demostró que un firmador de Bitcoin
aislado (air-gapped) puede ser barato y sin estado: una Raspberry Pi Zero,
una pantallita a color y una cámara, con los datos entrando y saliendo como
códigos QR. Pero los QR piden dos cosas: **una cámara** para leerlos y
**una pantalla capaz de mostrarlos** (un QR animado necesita unos cientos
de píxeles de lado, refrescados varias veces por segundo).

ur-tones cambia las dos cosas por **sonido**. Al firmador le basta con:

- un **micrófono** para escuchar (o la entrada de micrófono de un jack de
  auriculares, para ir por cable);
- un **altavoz** para contestar (o la salida de auriculares del mismo jack);
- una **pantalla pequeña**, solo para los menús y para revisar la
  transacción (importes, direcciones), y unos pocos botones.

Eso abre la puerta a firmadores hechos con **microcontroladores modestos**:
una Raspberry Pi Pico (RP2040/RP2350) o una placa ESP32, una pantalla OLED
de 1", cuatro botones y un jack de 3,5 mm. La librería en C de ur-tones está
escrita para ese hardware: C99, sin `malloc`, **sin coma flotante**
(Goertzel con enteros, una tabla de senos), unos 12 KB de código ARM Thumb.
Ya funciona en una consola portátil de 2008, la Nintendo DSi
([NDS-Signer](https://github.com/ndssigner/nds-signer)), escuchando por su
micrófono.

Es una idea antigua: los ordenadores domésticos de los 80 guardaban sus
programas en casete como tonos. Aquí los "programas" son PSBT, xpubs y
semillas.

> **Qué existe hoy y qué no.** Existen el formato, la implementación de
> referencia, la librería en C y la herramienta web, y NDS-Signer escucha
> tonos en una DSi de verdad (semillas con y sin PIN, una PSBT de Sparrow
> al aire). Un firmware de firmador para microcontrolador **no** existe
> todavía: habría que escribir o portar el análisis de PSBT, BIP-32 y la
> firma (por ejemplo libsecp256k1), como han hecho otras carteras para
> microcontroladores. Y las carteras aún no hablan en tonos: en el
> ordenador, la [herramienta web](https://ndssigner.github.io/ur-tones/)
> hace de puente (copias la PSBT de Sparrow y la reproduces; escuchas la
> firmada y la copias de vuelta).

### SeedSigner frente a un firmador con ur-tones

| | SeedSigner (oficial) | Un firmador con ur-tones (hipotético) |
| :--- | :--- | :--- |
| **Placa** | Raspberry Pi Zero v1.3 (1 GHz, 512 MB de RAM, Linux) | Raspberry Pi Pico / Pico 2 (RP2040 / RP2350, 133–150 MHz, 264–520 KB de RAM), o un ESP32 |
| **Pantalla** | LCD a color de 1,3" y 240×240 (tiene que mostrar QR animados) | Cualquier pantalla pequeña: una OLED de 0,96–1,3" y 128×64 basta para los menús y para revisar direcciones por páginas |
| **Entrada de datos** | Cámara (lee QR) | Micrófono, o la entrada de micrófono de un jack de 3,5 mm (cable) |
| **Salida de datos** | QR animados en pantalla | Tonos por un altavoz pequeño, o por la salida de auriculares del jack |
| **Radios** | Ninguna en la v1.3 (la Zero W tiene Wi-Fi/Bluetooth) | Ninguna en la Pico / Pico 2 (las versiones "W" y todos los ESP32 tienen Wi-Fi/Bluetooth: mejor placas sin radio) |
| **Coste aproximado de las piezas** | ≈ 50–80 USD (placa, pantalla HAT, cámara, microSD, caja) | ≈ 10–20 USD (placa, OLED, botones, jack o micrófono MEMS + amplificador pequeño) |
| **Consumo** | 5 V, alrededor de 1 W; arranca Linux (decenas de segundos) | Alrededor de 0,1 W, podría ir con pilas AA; lista en un segundo |
| **Velocidad** | Un QR animado: segundos | Por cable, ≈ 16 tonos/s (una PSBT de 450 bytes en menos de 2 minutos); al aire, 80 + 80 ms por tono (unas 2,7 veces más lento) |
| **Quién puede capturar los datos** | Cualquiera con una cámara que vea la pantalla | Por cable, nadie; al aire, cualquier micrófono de la habitación (de ahí el PIN para semillas) |
| **Meter una semilla** | SeedQR (cámara), o palabra a palabra | Tonos (con PIN opcional), el modo teclado a mano en cualquier teléfono, o palabra a palabra |
| **Firmware** | Maduro, muy usado, revisado (Python) | Aún no existe (solo la capa de sonido, en C) |

Los costes son aproximados, de 2026, comprando las piezas sueltas; varían
mucho según el país y el stock. Un firmador con tonos renuncia a velocidad;
a cambio se puede montar con piezas que se venden en todas partes, pequeño,
barato y fácil de verificar (sin controlador de cámara, sin Linux).

## Dispositivos sin internet con los que funciona

Los tonos son audio normal, así que un firmador con ur-tones puede
intercambiar datos con aparatos de audio antiguos y desconectados: para
**llevar** una PSBT (o la PSBT firmada) entre el firmador y el ordenador,
para **guardar** una copia de seguridad, o para **teclear** una semilla a
mano.

| Aparato | Reproduce | Graba | Uso | Notas |
| :--- | :---: | :---: | :--- | :--- |
| Walkman / grabadora de casete | ✓ | ✓ (grabadoras) | Copia de la semilla; llevar PSBT | Las variaciones de velocidad de la cinta (wow y flutter, unos %) pueden afectar; sin probar |
| MiniDisc | ✓ | ✓ | Copia de la semilla; llevar PSBT | Con pérdidas (ATRAC) pero bueno para tonos; sin probar |
| CD de audio (grabado) | ✓ | — | Copia de la semilla (solo reproducir) | Graba el WAV como pista de audio; los CD-R envejecen: ten dos; sin probar |
| iPod (classic, nano, shuffle) y otros reproductores MP3 | ✓ | — (casi todos) | Llevar una PSBT al firmador; copia de la semilla | Un MP3 a 128 kbps o más debería conservar los tonos; sin probar |
| Reproductores MP3 con grabadora de voz, grabadoras digitales (dictáfonos) | ✓ | ✓ | Llevar PSBT en los dos sentidos; copia de la semilla | Lo que mejor encaja: reproducen y graban, sin red; sin probar |
| Móvil clásico (sin SIM, o en modo avión) | ✓ | ✓ (notas de voz) | Grabar y reproducir; teclear una semilla a mano en modo teclado | Sus tonos de tecla tienen que ser DTMF de verdad; nunca con SIM y en llamada (la red los oye) |
| Un portátil, móvil o tableta sin conexión con la herramienta web | ✓ | ✓ | Todo: la herramienta web reproduce y escucha | **Probado** (navegadores, por cable y al aire) |
| Nintendo DSi con NDS-Signer | — (próximamente) | ✓ (escucha) | Recibir PSBT y semillas | **Probado** en una DSi de verdad; enviar tonos viene después |

"Sin probar" significa eso: pruébalo con una semilla **de prueba** o una
PSBT de testnet antes de fiarte, y si falla, graba lo que se oye
(*Escuchar → Grabar lo que se oye*) y abre una incidencia. Reed-Solomon
repara unos cuantos tonos mal oídos por trama, y una PSBT en varias partes
sobrevive a tramas perdidas, pero un formato tan joven aún no se ha
encontrado con todas las pletinas del mundo.

## Otra forma de hacer copias de la semilla

Los mismos tonos sirven de copia de seguridad: la semilla como **secuencia
de tonos cifrada con un PIN** (SPEC §4), guardada en un casete, un
MiniDisc, un CD o un MP3, y el **PIN guardado en otro sitio**, sin relación
y fuera de alcance. Quien encuentre la grabación sin el PIN obtiene una
cartera distinta, válida y vacía; quien tenga el PIN sin la grabación no
tiene nada.

Para recuperarla, se la reproduces al firmador (o a la herramienta web, sin
conexión) y escribes el PIN; comprueba la **huella** que muestran los dos
lados.

Conviene ser honesto con sus límites:

- **El PIN se puede adivinar sin conexión** si alguien tiene la grabación y
  sabe lo que es. Cada intento cuesta 10 000 HMAC-SHA256 (el PIN) más las
  derivaciones BIP-39 y BIP-32 y buscar las direcciones resultantes. Como
  orden de magnitud, a un millón de intentos por segundo (unas pocas GPU
  potentes): **un PIN inventado de 8 caracteres (40 bits) cae en menos de
  dos semanas**; **12 caracteres (60 bits) llevan decenas de miles de
  años**; 16 caracteres quedan fuera de alcance. Para una copia que puede
  pasar años guardada, usa **12 caracteres o más**, o añade una passphrase
  BIP-39 guardada con el PIN.
- **Fuera de internet.** Una grabación en la nube o en un correo es una
  grabación que cualquiera puede copiar y atacar con calma.
- **Los soportes envejecen.** Las cintas se estiran, los CD-R se degradan,
  los archivos se corrompen. Ten dos copias en soportes distintos, y
  reprodúcesela al firmador de vez en cuando (con la huella) para
  comprobar que se sigue leyendo.
- **Es un formato en borrador.** No la uses aún como única copia de fondos
  reales; junto a una copia en papel o metal, añade una copia que no parece
  una semilla.

Mira también [Seedcraft](https://github.com/ndssigner/seedcraft), que
guarda una semilla como una secuencia de objetos físicos.
