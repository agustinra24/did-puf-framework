# did-puf-framework

Framework de identidad descentralizada para dispositivos IoT, combinando identidad por hardware (SRAM-PUF), criptografia post-cuantica y un ledger auditable anclado a blockchain.

Proyecto de tesis de maestria en Ciencias y Tecnologias de Seguridad (INAOE, 2026).

> **Nota:** Este proyecto esta en desarrollo activo. La arquitectura y varios componentes pueden cambiar conforme avanza la investigacion. Lo que se describe aqui refleja el estado actual y la direccion general del framework.

## El problema

La autenticacion de dispositivos IoT depende tipicamente de hardware especializado y/o credenciales almacenadas en software: claves privadas, certificados, tokens. Estas credenciales tienen dos vulnerabilidades fundamentales:

- **Son extraibles.** Un atacante con acceso fisico (o remoto, en algunos casos) puede leer la memoria del dispositivo y clonar sus credenciales. Una vez clonadas, el dispositivo falso es indistinguible del original.
- **Son vulnerables a ataques cuanticos.** Los algoritmos de criptografia asimetrica actuales (RSA, ECDSA) seran rompibles por computadoras cuanticas suficientemente potentes. Los estandares post-cuanticos del NIST (FIPS 203, 204) ya estan publicados, pero su adopcion en IoT embebido es minima.

Este framework propone una alternativa que aborda ambos problemas, organizada en tres modulos complementarios.

## Los tres modulos

### Modulo 1: Identidad por hardware (SRAM-PUF)

Una PUF (Physical Unclonable Function) es una "huella digital" del silicio. Cuando un chip se enciende, las celdas de SRAM se inicializan con valores aleatorios que dependen de variaciones microscopicas del proceso de fabricacion. Estos valores son unicos por chip e imposibles de replicar, ni siquiera por el fabricante.

El framework utiliza la SRAM del ESP32 como PUF: al encender el dispositivo, se captura el patron de inicializacion, se aplican codigos de correccion de errores para hacerlo estable entre reinicios, y se obtiene una respuesta de 64 bytes que actua como identidad intrinseca del dispositivo. A partir de esta respuesta se deriva un device ID via SHA-512.

La ventaja frente a credenciales en software es que la identidad PUF no se puede extraer como un archivo, no se puede copiar a otro chip, y no existe en ninguna parte excepto en la fisica del dispositivo mismo.

### Modulo 2: Criptografia post-cuantica

Una vez que el dispositivo tiene su identidad PUF, necesita comunicarla al servidor de forma segura y autenticada. Para esto se usa un protocolo de autenticacion mutua (AKE, Authenticated Key Exchange) basado en criptografia post-cuantica:

- **ML-KEM / Kyber-768** (FIPS 203) para intercambio de claves: permite al dispositivo y al servidor derivar un secreto compartido sin transmitirlo, resistente a ataques cuanticos.
- **ML-DSA / Dilithium-5** (FIPS 204) para firmas digitales: permite firmar registros de identidad de forma no repudiable (implementado en Step 0, auditado).

El protocolo AKE tiene 5 fases. En el Step 0 (enrollment), el dispositivo envia su MAC address y el hash de su PUF al servidor, y recibe la clave publica Kyber del servidor que almacena cifrada localmente. Los pasos 1-4 (mutual authentication con encapsulacion Kyber, derivacion HKDF y verificacion HMAC) estan diseñados pero no implementados.

El almacenamiento local de claves usa un esquema de secure storage con AES-256-CBC, HMAC-SHA512 y IV aleatorio por escritura, sobre una particion NVS (Non-Volatile Storage, el sistema key-value sobre flash del ESP32) dedicada de 1MB.

### Modulo 3: Ledger auditable + anclaje a blockchain

Las identidades PUF autenticadas con criptografia post-cuantica se registran en un Centralized Ledger Database (CLD) diseñado especificamente para este framework. El CLD no es un blockchain: es una base de datos centralizada con propiedades criptograficas que la hacen verificable y a prueba de manipulacion. Inspirado en LedgerDB (Yang et al., PVLDB 2020).

Componentes del CLD (en desarrollo):

- **Journal append-only** con cadena de hashes: cada operacion (enrollment, rotacion de claves, revocacion) se encadena criptograficamente con la anterior.
- **Arbol de Merkle por lotes**: permite generar pruebas de inclusion (demostrar que una identidad fue registrada) y pruebas de consistencia (demostrar que el estado actual incluye todos los registros anteriores).
- **Protocolo de no-repudio con doble firma**: el dispositivo firma con ML-DSA, el servidor firma el recibo; ambas firmas se almacenan en el journal.

La razon de usar un CLD en lugar de un blockchain puro es pragmatica: los blockchains permisionados (Hyperledger, etc.) frecuentemente se despliegan en infraestructura centralizada de todos modos, y su throughput es ordenes de magnitud menor. Lo que realmente importa para auditabilidad no es la descentralizacion del consenso, sino la verificabilidad criptografica del registro. El CLD provee esto a mucho mayor rendimiento.

Para añadir una capa de descentralizacion, las raices de Merkle del CLD se anclan periodicamente a Bitcoin via **OpenTimestamps**. Esto permite que cualquier tercero verifique que el estado del ledger en un momento dado no fue alterado retroactivamente, sin depender del servidor.

## Como se conecta todo

```
ESP32                           Servidor
┌─────────────┐                ┌──────────────────────┐
│ SRAM-PUF    │                │ IoT API (FastAPI)    │
│   ↓         │                │   ↓                  │
│ SHA-512     │  HTTP POST     │ Verificar identidad  │
│ Device ID   │ ──────────────>│   ↓                  │
│   ↓         │  Step 0        │ CLD Service          │
│ AKE Protocol│ <──────────────│   ↓                  │
│   ↓         │  Kyber pk      │ Journal + Merkle     │
│ Sec_Store   │                │   ↓                  │
│ (cifrado)   │                │ OpenTimestamps → BTC  │
└─────────────┘                └──────────────────────┘
```

El flujo completo (objetivo final del framework):

1. El dispositivo genera su identidad PUF unica al encenderse por primera vez.
2. Se autentica con el servidor usando criptografia post-cuantica (AKE).
3. El servidor registra la identidad en el CLD con doble firma.
4. Periodicamente, las raices de Merkle del CLD se anclan a Bitcoin.
5. Cualquier auditor puede verificar la integridad del registro sin confiar en el servidor.

## Estructura del repositorio

```
did-puf-framework/
├── firmware/
│   ├── puf_provisioning/          # Firmware de enrollment PUF (fase 1)
│   ├── root_of_trust_fw/          # Firmware funcional con enrollment Step 0 (fase 2)
│   └── components/
│       ├── esp32_puflib/          # Libreria SRAM-PUF (submodulo, fork propio)
│       ├── ml_dsa/                # ML-DSA-87 FIPS 204 (submodulo, port propio)
│       ├── crypto_storage/        # Secure storage (AES-256-CBC + HMAC-SHA512)
│       ├── crypto_utils/          # Utilidades de codificacion (base64)
│       └── http_helpers/          # Helpers para transacciones HTTP
├── web/
│   └── puf-web-flasher/          # Herramienta web de provisioning (Chrome, Web Serial)
├── server/
│   ├── auto-iotserver/            # API IoT + autoinstalador Debian (submodulo)
│   ├── cld-service/               # Servicio CLD (en desarrollo)
│   └── test-enrollment/           # Servidor de prueba para Step 0 (FastAPI)
└── reference/
    └── esp32_dignal_course/       # Protocolo AKE de referencia (submodulo, A. Salinas)
```

### Sobre los directorios

**`web/puf-web-flasher/`** es una aplicacion HTML que corre en Chrome y permite hacer todo el proceso de provisioning desde el navegador: diagnostico del chip, flasheo de ambos firmwares, y configuracion del dispositivo via Web Serial API. No requiere instalar ESP-IDF; util para demos y para provisionar dispositivos sin entorno de desarrollo.

**`server/auto-iotserver/`** es el backend IoT actual (v1.1): una API FastAPI con autenticacion, telemetria y un autoinstalador de 14 fases para Debian. Esta programado para ser reescrito desde cero incorporando autenticacion post-cuantica.

**`firmware/components/ml_dsa/`** es el [port de mldsa-native a ESP32](https://github.com/agustinra24/mldsa-native-esp32) (submodulo). Primer port documentado de mldsa-native al ESP32. Provee firmas digitales ML-DSA-87 (FIPS 204, NIST Level 5) como componente ESP-IDF standalone.

**`reference/esp32_dignal_course/`** es el repositorio de Alejandro Salinas (colaborador), incluido como submodulo de referencia. Contiene el diseño del protocolo AKE, la implementacion de Kyber-768 para ESP32, y los componentes de secure storage que fueron extraidos y adaptados como componentes compartidos en `firmware/components/`.

## Configuracion del dispositivo

Al arrancar por primera vez despues del flasheo, `root_of_trust_fw` entra en modo de configuracion y espera recibir parametros via UART (115200 baud). El protocolo es simple: se envia `CFG_START`, luego pares `CLAVE=valor` (uno por linea), y se cierra con `CFG_END`.

```
CFG_START
SERVER_URL=http://192.168.1.100
SERVER_PORT=8000
ENDPOINT=/api/v1/device/heartbeat
INTERVAL=30
WIFI_SSID=MiRed
WIFI_PASS=clave123
PUF_RESPONSE=4D EA 99 3F A3 E2 F9 16 ...
CFG_END
```

El firmware responde `CFG_OK` si todo se almaceno correctamente, o `CFG_ERR` en caso de error. Estos parametros se guardan en NVS y persisten entre reinicios. El web flasher automatiza este proceso a traves de su interfaz grafica.

## Hardware

- **Target:** ESP32-WROOM-32D (y variantes 32X), 4MB flash
- **Particiones:** NVS (480K) + App (1M) + Sec_Store (1M)
- La particion Sec_Store se usa para almacenar claves criptograficas cifradas con AES-256-CBC, autenticadas con HMAC-SHA512 y derivadas de la PUF.

## Requisitos

- [ESP-IDF v5.5.3](https://docs.espressif.com/projects/esp-idf/en/v5.5.3/esp32/get-started/)
- Python 3.11+ con [uv](https://docs.astral.sh/uv/) (para el test server)
- Chrome (para el web flasher, usa Web Serial API)

## Clonar y compilar

```bash
git clone --recursive https://github.com/agustinra24/did-puf-framework.git
cd did-puf-framework

# Activar ESP-IDF
. ~/esp/esp-idf/export.sh

# Compilar firmware de provisioning PUF
cd firmware/puf_provisioning
idf.py build
idf.py flash monitor

# Compilar firmware funcional (root of trust + Step 0)
cd ../root_of_trust_fw
idf.py build
idf.py flash monitor
```

### Perfiles de medicion PUF

El firmware de provisioning soporta dos perfiles. El numero de mediciones determina la estabilidad de la respuesta PUF: mas mediciones, mas confiable la seleccion de bits estables, pero mas tiempo de enrollment.

```bash
idf.py build                          # basico: 200 mediciones (~5 min)
idf.py -DPUF_PROFILE=strong build     # fuerte: 1000 mediciones (~25 min)
```

### Servidor de prueba

```bash
cd server/test-enrollment
uv run server.py
```

Levanta un servidor FastAPI en `http://localhost:8000` que acepta el enrollment Step 0 y responde con una Kyber pk de prueba (bytes aleatorios). Util para desarrollo y demos sin necesidad del servidor real.

### Firmas post-cuanticas (ML-DSA-87)

El componente `firmware/components/ml_dsa/` ([repo independiente](https://github.com/agustinra24/mldsa-native-esp32), incluido como submodulo) integra [mldsa-native](https://github.com/pq-code-package/mldsa-native) (PQCA, Apache/ISC/MIT) como componente ESP-IDF. Implementa ML-DSA-87 (FIPS 204, NIST Level 5) con las siguientes adaptaciones para ESP32:

- Configuracion estandar (sin `MLD_CONFIG_REDUCE_RAM`) para mantener cobertura de pruebas formales CBMC de upstream.
- `MLD_CONFIG_CUSTOM_ALLOC_FREE`: redirige los buffers internos (~100 KB) al heap en lugar del stack (el main task tiene solo 12 KB).
- `MLD_CONFIG_CUSTOM_RANDOMBYTES`: usa `esp_fill_random()` como fuente de entropia por hardware (requiere WiFi activo para TRNG real).

**Benchmark (N=10,000, ESP32-WROOM-32D v3.1 @ 240 MHz):**

| Operacion | Media | Desv. est. | Min | Max |
|-----------|-------|------------|-----|-----|
| Keygen | 41.09 ms | 0.15 ms | 40 ms | 42 ms |
| Sign | 185.17 ms | 146.63 ms | 57 ms | 1,516 ms |
| Verify | 42.00 ms | 0.01 ms | 41 ms | 42 ms |

La alta varianza en signing es comportamiento esperado: FIPS 204 Algorithm 2 usa rejection sampling, donde cada intento de firma puede requerir multiples iteraciones internas. Keygen y verify son deterministicos.

| Parametro | Valor |
|-----------|-------|
| Clave publica | 2,592 bytes |
| Clave secreta | 4,896 bytes |
| Firma | 4,627 bytes |
| Flash (componente) | +19 KB |

Para replicar el benchmark:

```bash
cd firmware/root_of_trust_fw
idf.py -DBENCH_MLDSA=ON build
idf.py -p /dev/cu.usbserial-XXXX flash monitor
```

El benchmark ejecuta 10,000 iteraciones de keygen, sign y verify con estadisticas online (algoritmo de Welford). Tarda aproximadamente 45 minutos. Los resultados se imprimen por UART a 115200 baud.

## Flujo de provisioning

1. **Fase 1 (Enrollment PUF):** Se flashea `puf_provisioning`. El ESP32 reinicia multiples veces con deep sleep, capturando el patron SRAM en cada arranque. Despues de las N mediciones, genera los helper data (codigos de correccion) y almacena la informacion de reconstruccion en NVS. Al terminar, imprime la respuesta PUF como hex por UART y la limpia de memoria. Este proceso es destructivo: no se debe interrumpir.

2. **Transferencia PUF:** La respuesta PUF se transfiere entre firmwares via UART, no por persistencia automatica de flash. El usuario (o el web flasher) captura el output hex de la fase 1 y lo reinyecta como `PUF_RESPONSE=4D EA 99 ...` durante el modo de configuracion de la fase 2. La tabla de particiones identica asegura que Sec_Store este alineada, pero los bytes PUF no se comparten por NVS entre los dos firmwares.

3. **Fase 2 (Firmware funcional):** Se flashea `root_of_trust_fw` sin borrar la flash. Al primer arranque, el firmware entra en modo de configuracion UART donde recibe la PUF, credenciales WiFi y URL del servidor. Con la PUF almacenada, deriva el device ID (SHA-512), se conecta a WiFi, genera un par de claves ML-DSA-87, firma el enrollment request (SHA-512 + ML-DSA con context "enroll"), y lo envia al servidor junto con la clave publica. El servidor responde con su Kyber pk, que el dispositivo almacena cifrada en Sec_Store. La clave secreta ML-DSA tambien se almacena cifrada.

4. **Operacion:** Despues del enrollment, el firmware envia heartbeats periodicos al servidor con su device ID. El boton BOOT (GPIO0) dispara reportes inmediatos. En reinicios posteriores, el dispositivo detecta que ya esta enrolled y salta directamente al modo operacional.

## Arquitectura del servidor

La arquitectura objetivo del servidor son dos microservicios FastAPI independientes, desplegados en Docker Compose detras de Nginx como reverse proxy:

- **IoT API**: autenticacion de dispositivos, telemetria, gestion de usuarios y RBAC. Interfaz principal con los ESP32. Actualmente existe como auto-iotserver v1.1 (sera reescrito).
- **CLD Service**: ledger de identidades, verificacion por Merkle tree, protocolo de no-repudio y anclaje a OpenTimestamps. En desarrollo (actualmente solo placeholder).

El autoinstalador (`server/auto-iotserver/`) despliega todo el stack (MySQL, MongoDB, Redis, FastAPI, Nginx) en un servidor Debian 13 o Raspbian 64-bit limpio. Actualmente en v1.1, sera reescrito para integrar la autenticacion post-cuantica y el CLD como segundo servicio.

## Estado del proyecto

> Este framework es un trabajo de investigacion en desarrollo. Los componentes marcados como "en desarrollo" o "pendiente" representan la direccion actual del diseño, pero la implementacion y la arquitectura pueden evolucionar.

| Componente | Estado |
|---|---|
| SRAM-PUF enrollment | Funcional |
| Firmware root of trust + Step 0 | Funcional |
| Web flasher (provisioning via Chrome) | Funcional |
| Componentes crypto compartidos (ESP-IDF) | Funcional |
| Servidor de prueba Step 0 | Funcional |
| Protocolo AKE Steps 1-4 (autenticacion mutua) | En desarrollo (A. Salinas) |
| ML-DSA-87 / Dilithium-5 (firmas post-cuanticas) | Funcional (integrado en Step 0 enrollment, auditado) |
| CLD: journal, Merkle, no-repudio | En desarrollo |
| OpenTimestamps (anclaje a Bitcoin) | Pendiente |
| Rewrite de IoT API con auth PQC | Pendiente |
| Integracion end-to-end completa | Pendiente |

## Limitaciones conocidas

- **Clonacion PUF con acceso fisico.** Si un atacante obtiene acceso fisico al dispositivo, puede extraer los helper data y la respuesta PUF de la NVS, flashear un firmware minimo con la funcion de reconstruccion PUF, y generar el mismo identificador en el mismo chip. Esto requiere posesion fisica prolongada del dispositivo. Es una limitacion inherente a las PUFs basadas en helper data y se documenta como trabajo futuro.
- **Solo Step 0 del AKE implementado.** Los pasos 1-4 del protocolo de autenticacion mutua estan diseñados (diagramas de arquitectura) pero no codificados aun. El enrollment funciona, pero la sesion autenticada completa aun no.
- **Asimetria de nivel de seguridad PQC.** ML-DSA-87 opera a NIST Level 5, pero Kyber-768 (recepcion de clave publica del servidor) es Level 3. La migracion a Kyber-1024 (Level 5) depende de la integracion del componente de Alejandro Salinas.
- **Web flasher PUF extraction fragil.** El regex de extraccion de la PUF response en el web flasher matchea el output del firmware pero los datos capturados pueden contener prefijos del monitor serial (ESP_LOGI). Se agrego un regex de limpieza, pero la extraccion puede fallar dependiendo del formato exacto del output. La transferencia manual por UART es mas confiable.
- **CLD y anclaje a blockchain pendientes.** El modulo 3 esta en fase de diseño e implementacion inicial.

## Referencias

- Yang, X., et al. "LedgerDB: A Centralized Ledger Database for Universal Audit and Verification." *Proceedings of the VLDB Endowment*, vol. 13, no. 12, 2020. -- Inspiracion para la arquitectura del CLD.
- NIST FIPS 203. "Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)." 2024. -- Kyber-768 para intercambio de claves.
- NIST FIPS 204. "Module-Lattice-Based Digital Signature Standard (ML-DSA)." 2024. -- ML-DSA-87 para firmas digitales (implementado en ESP32 via mldsa-native).
- Stanicek, O. "SRAM PUF for ESP32." Czech Technical University, 2022. -- Libreria PUF base del framework.

## Creditos

- **Alejandro Salinas** -- Diseño del protocolo AKE (5 fases), componentes criptograficos (secure storage, Kyber-768 KEM en ESP32), implementacion de referencia.
- **Ondrej Stanicek** (Czech Technical University) -- Libreria SRAM-PUF original para ESP32.

## Licencia

[MIT](LICENSE)
