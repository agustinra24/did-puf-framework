# did-puf-framework

Framework de identidad descentralizada para IoT con SRAM-PUF, criptografia post-cuantica y blockchain.

Proyecto de tesis de maestria (MCyTS, 2026).

## Estructura

- `firmware/` - Proyectos ESP32 (provisioning PUF y firmware root of trust)
- `firmware/components/esp32_puflib/` - Libreria PUF (submodulo)
- `web/puf-web-flasher/` - Herramienta web para flasheo y provisioning via Chrome
- `server/auto-iotserver/` - API IoT + autoinstalador Debian (submodulo)
- `server/cld-service/` - Servicio CLD (en desarrollo)
- `reference/esp32_dignal_course/` - Protocolo AKE de referencia (submodulo, A. Salinas)
- `docs/` - Papers y documentacion

## Setup

Requiere [ESP-IDF v5.5.3](https://docs.espressif.com/projects/esp-idf/en/v5.5.3/esp32/get-started/).

```bash
git clone --recursive git@github.com:agustinra24/did-puf-framework.git
cd did-puf-framework

. ~/esp/esp-idf/export.sh

cd firmware/puf_provisioning
idf.py build
idf.py flash monitor
```

Target: ESP32-WROOM-32D, 4MB flash.

## Licencia

MIT
