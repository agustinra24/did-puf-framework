#!/usr/bin/env bash
# ============================================================
# generate_web_firmware.sh v3
# Extrae binarios + offsets del build ESP-IDF usando
# flasher_args.json (formato JSON fiable, no texto plano).
#
# Uso:
#   cd ~/esp/puf_provisioning
#   get_idf
#   idf.py build
#   bash generate_web_firmware.sh [destino]
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'
YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

PROJECT_DIR="${PWD}"
BUILD_DIR="${PROJECT_DIR}/build"
DEST_DIR="${1:-${PROJECT_DIR}/web_firmware}"

echo -e "${CYAN}======================================${NC}"
echo -e "${CYAN} DID-PUF Web Firmware Package v3     ${NC}"
echo -e "${CYAN}======================================${NC}"
echo ""

# Verificar build
if [ ! -d "${BUILD_DIR}" ]; then
    echo -e "${RED}[ERROR] No se encontro ${BUILD_DIR}. Ejecuta 'idf.py build' primero.${NC}"
    exit 1
fi

# Usar flasher_args.json (JSON estructurado, generado por ESP-IDF v4.4+)
FLASHER_JSON="${BUILD_DIR}/flasher_args.json"

if [ ! -f "${FLASHER_JSON}" ]; then
    echo -e "${RED}[ERROR] No se encontro ${FLASHER_JSON}${NC}"
    echo -e "${RED}        Este archivo lo genera 'idf.py build' automaticamente.${NC}"
    echo -e "${RED}        Verifica que tienes ESP-IDF v4.4 o superior.${NC}"
    exit 1
fi

echo -e "${YELLOW}[1/5] Parseando offsets de flasher_args.json...${NC}"

# Extraer offsets y paths del JSON con Python (disponible en ESP-IDF env)
# Nota: con set -e, si python3 falla, el || captura el error
# en lugar de abortar el script sin mensaje claro.
PARSE_RESULT=$(python3 << PYEOF
import json, sys

with open("${FLASHER_JSON}") as f:
    data = json.load(f)

flash_files = data.get("flash_files", {})

if not flash_files:
    print("ERROR: flash_files vacio en flasher_args.json", file=sys.stderr)
    sys.exit(1)

bootloader = None
partition = None
app = None

for offset_hex, filepath in flash_files.items():
    if "bootloader" in filepath:
        bootloader = (offset_hex, filepath)
    elif "partition" in filepath:
        partition = (offset_hex, filepath)
    else:
        app = (offset_hex, filepath)

if not all([bootloader, partition, app]):
    print("ERROR: No se encontraron los 3 binarios esperados", file=sys.stderr)
    print(f"  bootloader: {bootloader}", file=sys.stderr)
    print(f"  partition:  {partition}", file=sys.stderr)
    print(f"  app:        {app}", file=sys.stderr)
    sys.exit(1)

# Output: offset_hex|filepath for each, separated by newlines
print(f"BOOT_OFFSET={bootloader[0]}")
print(f"BOOT_FILE={bootloader[1]}")
print(f"PART_OFFSET={partition[0]}")
print(f"PART_FILE={partition[1]}")
print(f"APP_OFFSET={app[0]}")
print(f"APP_FILE={app[1]}")
PYEOF
) || {
    echo -e "${RED}[ERROR] Fallo al parsear flasher_args.json${NC}"
    echo -e "${RED}        Verifica que el archivo existe y tiene formato correcto.${NC}"
    exit 1
}

# Importar las variables parseadas
eval "$PARSE_RESULT"

echo -e "  bootloader:      ${BOOT_OFFSET} -> ${BOOT_FILE}"
echo -e "  partition-table:  ${PART_OFFSET} -> ${PART_FILE}"
echo -e "  app:             ${APP_OFFSET} -> ${APP_FILE}"

# Verificar que los archivos existen
for f in "${BUILD_DIR}/${BOOT_FILE}" "${BUILD_DIR}/${PART_FILE}" "${BUILD_DIR}/${APP_FILE}"; do
    if [ ! -f "${f}" ]; then
        echo -e "${RED}[ERROR] Archivo no encontrado: ${f}${NC}"
        exit 1
    fi
done

# Crear directorio destino
mkdir -p "${DEST_DIR}"

# Copiar binarios
echo -e "${YELLOW}[2/5] Copiando binarios...${NC}"
cp "${BUILD_DIR}/${BOOT_FILE}" "${DEST_DIR}/bootloader.bin"
cp "${BUILD_DIR}/${PART_FILE}" "${DEST_DIR}/partition-table.bin"
cp "${BUILD_DIR}/${APP_FILE}"  "${DEST_DIR}/puf_provisioning.bin"

echo -e "  bootloader.bin       $(wc -c < "${DEST_DIR}/bootloader.bin" | tr -d ' ') bytes"
echo -e "  partition-table.bin  $(wc -c < "${DEST_DIR}/partition-table.bin" | tr -d ' ') bytes"
echo -e "  puf_provisioning.bin $(wc -c < "${DEST_DIR}/puf_provisioning.bin" | tr -d ' ') bytes"

# Convertir offsets hex a decimal para JSON
BOOT_DEC=$((BOOT_OFFSET))
PART_DEC=$((PART_OFFSET))
APP_DEC=$((APP_OFFSET))

# Generar manifest.json con offsets CORRECTOS del build
echo -e "${YELLOW}[3/5] Generando manifest.json (offsets auto-detectados)...${NC}"
cat > "${DEST_DIR}/manifest.json" << MANIFEST
{
  "name": "DID-PUF Framework :: SRAM-PUF Enrollment",
  "version": "1.0.0",
  "new_install_prompt_erase": false,
  "builds": [
    {
      "chipFamily": "ESP32",
      "parts": [
        { "path": "bootloader.bin",      "offset": ${BOOT_DEC} },
        { "path": "partition-table.bin",  "offset": ${PART_DEC} },
        { "path": "puf_provisioning.bin", "offset": ${APP_DEC} }
      ]
    }
  ]
}
MANIFEST

echo -e "  Offsets en manifest.json:"
echo -e "    bootloader:      ${BOOT_OFFSET} (${BOOT_DEC})"
echo -e "    partition-table:  ${PART_OFFSET} (${PART_DEC})"
echo -e "    app:             ${APP_OFFSET} (${APP_DEC})"

# Generar merged binary (opcional, para flasheo manual con esptool.py)
echo -e "${YELLOW}[4/5] Generando firmware_merged.bin...${NC}"
if command -v esptool.py &> /dev/null || python3 -c "import esptool" 2>/dev/null; then
    ESPTOOL_CMD="esptool.py"
    command -v esptool.py &> /dev/null || ESPTOOL_CMD="python3 -m esptool"

    ${ESPTOOL_CMD} --chip esp32 merge_bin \
        -o "${DEST_DIR}/firmware_merged.bin" \
        --flash_mode dio \
        --flash_freq 40m \
        --flash_size 4MB \
        ${BOOT_OFFSET} "${DEST_DIR}/bootloader.bin" \
        ${PART_OFFSET} "${DEST_DIR}/partition-table.bin" \
        ${APP_OFFSET}  "${DEST_DIR}/puf_provisioning.bin" \
        2>&1 | tail -3

    echo -e "  firmware_merged.bin  $(wc -c < "${DEST_DIR}/firmware_merged.bin" | tr -d ' ') bytes"
else
    echo -e "${YELLOW}  [SKIP] esptool no encontrado. Ejecuta 'get_idf' primero.${NC}"
fi

# Checksums
echo -e "${YELLOW}[5/5] Generando checksums...${NC}"
cd "${DEST_DIR}"
shasum -a 256 *.bin > checksums.sha256 2>/dev/null || sha256sum *.bin > checksums.sha256 2>/dev/null || true
cd "${PROJECT_DIR}"

echo ""
echo -e "${GREEN}===========================================${NC}"
echo -e "${GREEN} Paquete listo en: ${DEST_DIR}/${NC}"
echo -e "${GREEN}===========================================${NC}"
echo ""
ls -lh "${DEST_DIR}/"
echo ""
echo -e "${CYAN}Siguiente paso:${NC}"
echo -e "  1. Copia index.html al mismo directorio que firmware/"
echo -e "  2. cd $(dirname ${DEST_DIR}) && python3 -m http.server 8080"
echo -e "  3. Abre Chrome en http://localhost:8080"
