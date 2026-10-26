# Portar la librería C

*[English](../porting.md)*

`c/ur_tones.c` y `c/ur_tones.h` son C99 sin más: sin `malloc`, sin estado
global mutable y sin coma flotante. Compilan en cualquier cosa con un
compilador de C y unos pocos KB de RAM. Esta guía explica dónde se conecta el
hardware de cada dispositivo, cuánto cuesta cada opción y cada parte, qué
configuraciones se han probado y cómo añadir una.

## Las capas: dónde se conecta el hardware

| Capa | Llamadas | Se conecta aquí |
| --- | --- | --- |
| 1. muestras ⇄ detecciones | `ut_detector_*`, `ut_synth_*` | Un ADC, I2S o un códec de entrada; un DAC, PWM o I2S de salida, a cualquier frecuencia de 8 kHz o más. |
| | `ut_classify` | Tu propio DSP (una FFT de CMSIS-DSP, un núcleo DSP): le das las 8 potencias DTMF de una ventana y decide como la librería. |
| 2. detecciones ⇄ grupos | `ut_keys_*` | Tonos, ecos, pausas y modo teclado. `ut_keys_tone` + `ut_keys_time` reciben los eventos de un **chip decodificador DTMF** (MT8870, HT9170: una tecla, su inicio y su final). |
| | `ut_player_*` | Un **chip generador DTMF** (HT9200): qué tecla, cuánto tiempo, y luego cuánto silencio. |
| 3. grupos ⇄ tramas | `ut_frame_decode`, `ut_frame_encode` | Tramas como bytes (`ut_frame`): sincronía, base 15, Reed-Solomon, un tono perdido o sobrante reparado. |
| 4. tramas ⇄ mensajes | `ut_frame_to_ur`, `ut_ur_to_frame`, semillas, `ut_fountain_*`, claves | Texto UR, semillas y el PIN, UR de varias partes, PSBT, claves públicas. |

`ut_listener` son las capas 1 y 2 juntas: entran muestras y salen grupos. Es
lo que necesitan casi todos los dispositivos con micrófono o entrada de línea.

**Los aceleradores** se encargan del hash mediante dos ganchos
(`c/ur_tones_config.example.h` muestra los dos):

- `UT_SHA256_BLOCK`: la compresión de SHA-256, para hardware que puede cargar un estado (ESP32-S3/C3/C6, STM32 con periférico HASH, nRF CC3xx).
- `UT_PBKDF2_SHA256`: el PBKDF2 entero, para hardware que solo calcula el hash de mensajes completos (el SHA-256 del RP2350), o para un firmware que ya lleva mbedTLS o wolfSSL.

El PIN de la semilla son 10.000 iteraciones de PBKDF2, o 20.000 bloques de
SHA-256: ahí es donde compensa un acelerador. Un gancho ve el PIN y su clave,
así que debe borrar sus propios búferes y los registros del acelerador, como
hace el código portable.

## Lo que cuesta cada parte

Código para un Cortex-M0+ (Thumb-1, `arm-none-eabi-gcc -Os`), según
`tools/portability.sh m0plus`:

| Compilación | Código |
| --- | ---: |
| Todo (por defecto) | 19,2 KB |
| `UT_NO_AUDIO`: sin detector, síntesis ni `ut_listener` (lo hace un chip DTMF) | 16,7 KB |
| `UT_NO_KEYPAD`: sin modo teclado | 18,4 KB |
| `UT_NO_SEED`: sin semillas, PIN ni modo teclado | 17,4 KB |
| `UT_NO_FOUNTAIN`: sin UR de varias partes ni PSBT como CBOR | 15,3 KB |
| `UT_NO_KEYS`: sin xpub, descriptores ni sus UR | 16,7 KB |
| `UT_NO_SEED`, `UT_NO_FOUNTAIN`, `UT_NO_KEYS`: tramas y audio | 9,7 KB |
| Lo mismo con `UT_NO_AUDIO`: solo tramas | 7,2 KB |

La librería no reserva memoria. La RAM son las estructuras que coloca la
aplicación (estáticas, en la pila o en su propia memoria), con los tamaños por
defecto:

| Estructura | Bytes | Crece con |
| --- | ---: | --- |
| `ut_listener` (= `ut_detector` + `ut_keys`) | 5.300 | |
| `ut_detector` | 2.120 | `UT_RING`: 2 bytes por muestra guardada (≥ 560) |
| `ut_keys` | 3.176 | `UT_GROUP` (≥ 560) × (`UT_READY` + 1), `UT_LIVE` |
| `ut_fountain_encoder` | 3.104 | `UT_MAX_PARTS`: 12 bytes por fragmento |
| `ut_fountain_decoder` | 3.200 | `UT_MAX_PARTS`: 12 bytes por fragmento |
| `ut_frame` | 476 | |
| `ut_synth` | 56 | |

El otro coste es la **pila**. En un Cortex-M0+, la llamada más profunda
(`ut_ur_to_frame`, que analiza un UR) usa unos 2,6 KB, reparar una trama unos
2,3 KB, y el PIN de una semilla unos 2,1 KB. Algunos SDK dan a `main` menos
que eso por defecto (el de la Pico: 2 KB).

Las cifras se regeneran con:

```
tools/portability.sh m0plus
```

## Opciones, ganchos e interruptores

Todos van en una cabecera de configuración propia, que se indica con
`-DUT_CONFIG_FILE="mi_config.h"` (o `UR_TONES_CONFIG_FILE` con CMake).
`c/ur_tones_config.example.h` explica cada uno; los valores imposibles paran
la compilación con un `#error`.

- **Tamaños:** `UT_MAX_PARTS`, `UT_GROUP`, `UT_READY`, `UT_LIVE`, `UT_RING` (arriba).
- **Aritmética:** `UT_USE_DOUBLE 1` usa los double de la CPU para los códigos fuente en lugar de los enteros de la librería: mismos resultados, más rápido con una FPU de doble precisión.
- **Ubicación:**
  - `UT_ROM` y `UT_ROM_U8/U16/U32` ponen las tablas constantes (unos 1,4 KB) en la memoria de programa en las CPU Harvard (AVR: `PROGMEM`).
  - `UT_HOT` marca los bucles calientes (Goertzel, síntesis, la compresión de SHA-256) para ejecutarlos desde RAM en las CPU que ejecutan el código desde la flash a través de una caché. Incluye `noinline`: una función estática integrada en la que la llama se ejecuta desde donde se ejecute esa.
- **Ganchos:** `UT_SHA256_BLOCK`, `UT_PBKDF2_SHA256` (arriba).
- **Interruptores:** `UT_NO_AUDIO`, `UT_NO_SEED`, `UT_NO_KEYPAD`, `UT_NO_FOUNTAIN`, `UT_NO_KEYS` (arriba).

## Secretos

Las llamadas de semillas borran todas las copias que hacen de la entropía, el
PIN y su clave antes de volver, también cuando fallan. `tests/c/wipe.c` lo
comprueba buscando en la pila. Los búferes de la aplicación le toca borrarlos
a ella: la entropía y el PIN que pasa, lo que recibe, un `ut_frame`, y los
tonos que oyó un `ut_listener` (`ut_listener_init` los borra).

## Configuraciones

### Raspberry Pi Pico (RP2040): medida

[`c/configs/ut_config_rp2040.h`](../../c/configs/ut_config_rp2040.h): los
tamaños por defecto, y `UT_HOT` en la sección `.time_critical` del SDK. La CI
la compila con los avisos como errores y compila
[`examples/pico`](../../examples/pico), un ejemplo que escucha por cable (ADC
con DMA a 16 kHz), envía (PWM) y mide. En una Pico a 125 MHz:

| | |
| --- | --- |
| PIN de la semilla (PBKDF2, 10.000 iteraciones) | 1,46 s |
| Receptor (`ut_listener_push`) | 127 ms de CPU por segundo de audio a 16 kHz (13 %) |
| Una trama con 16 bytes que reparar (`ut_frame_to_ur`) | 2,6 ms |
| Recibido por cable desde un ordenador | tramas y una semilla en modo teclado, 0 bytes reparados |

La salida PWM del ejemplo está hecha, pero aún no se ha probado en una placa.

### Nintendo DSi (ARM946E-S, sin FPU): medida

[`c/configs/ut_config_nds.h`](../../c/configs/ut_config_nds.h): los valores
por defecto. La CI la compila con los avisos como errores
(`tools/portability.sh arm946`). [NDS-Signer](https://github.com/ndssigner/nds-signer)
la usa para escuchar por el micrófono y reproducir por el altavoz; el
diagnóstico de su versión de desarrollo (Diagnostics -> Benchmark) ejecuta
el `bench` de `examples/pico`. En una DSi XL (134 MHz, devkitARM, `-O2`):

| | |
| --- | --- |
| Código (ARM, la librería entera) | 26,5 KB con `-Os`, 33,8 KB con `-O2` |
| PIN de la semilla (PBKDF2, 10.000 iteraciones) | 1,06 s |
| Receptor (`ut_listener_push`) | 44 ms de CPU por segundo de audio a 16.364 Hz (4,4 %) |
| Una trama con 5 tonos mal oídos (`ut_frame_to_ur`) | 2 ms |
| Por el aire, en una DSi XL | semillas, con y sin PIN; una PSBT en los dos sentidos con Sparrow |

También se midió `UT_HOT` en la ITCM y se dejó fuera: el PIN pasó de 1,06 s
a 1,01 s, porque la caché de instrucciones de 8 KB ya contiene los bucles.

### Previstas

Raspberry Pi Pico 2 (RP2350, con `UT_PBKDF2_SHA256` en su acelerador de
SHA-256), placas ESP32, STM32 y otros Cortex-M, AVR, MSP430 y RISC-V. Ninguna
se ha compilado ni medido todavía.

## Un port nuevo, paso a paso

1. Compila `c/ur_tones.c` con el compilador del destino y los avisos como errores (`-Wall -Wextra -Werror`). Ojo con un `int` de 16 bits: los resultados son `int32_t`, pero cuenta lo que diga tu compilador.
2. Escribe `c/configs/ut_config_<destino>.h`: tamaños para su RAM, `UT_ROM` y `UT_HOT` si los necesita, ganchos para sus aceleradores.
3. Comprueba la pila que necesitan tus llamadas frente a la que el SDK da a `main`.
4. Dale audio real: las tramas de los vectores y una semilla en modo teclado (`vectors/ur-tones-v0.json`; `reference/python/ur_tones.py` las convierte en un WAV). Apunta cuántos bytes reparó Reed-Solomon. El modo teclado necesita al menos 80 ms de tono y 80 ms de silencio (SPEC §1.1).
5. Mide lo que mide el `bench` de `examples/pico`: el PIN, la CPU del receptor por segundo de audio, una reparación.
6. Si la cadena de herramientas está en el apt de Debian o Ubuntu, añádela a `tools/portability.sh` y al trabajo `portability` de la CI.

## Se buscan ports

Si tienes alguna de estas placas o cadenas de herramientas, un port será muy
bienvenido:

- Raspberry Pi Pico 2 (RP2350): una compilación para Cortex-M33, y `UT_PBKDF2_SHA256` en su acelerador de SHA-256.
- AVR (`UT_ROM` como `PROGMEM`) y MSP430, revisando el `int` de 16 bits (`-Wconversion`); RISC-V; un Cortex-M4F con `UT_USE_DOUBLE 1`.
- Los tests de la librería en QEMU (32 bits, big-endian) o simavr.
- Paquetes: un componente de ESP-IDF, un módulo de Zephyr, PlatformIO, una librería de Arduino; ejemplos para ESP-IDF, Arduino y un chip decodificador MT8870.
- Grabaciones de dispositivos reales enviando y recibiendo, para los vectores de prueba.

Una contribución debería traer la línea de compilación del destino, su
`c/configs/ut_config_<destino>.h`, las cifras medidas (y cómo), y un trabajo
de CI si su cadena de herramientas está en apt. Abre una pull request
([CONTRIBUTING.md](../../CONTRIBUTING.md)). Un port no cambia nada del
formato, así que no necesita una issue antes.
