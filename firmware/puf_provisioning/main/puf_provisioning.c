/*
 * PUF Provisioning para ESP32-WROOM-32D
 * Usa esp32_puflib (Daniel Stanion) para enrollment SRAM PUF.
 *
 * Flujo:
 *   Boot 1..N: puflib mide SRAM, deep sleep, repite (enrollment)
 *   Boot N+1:  enrollment completo, obtiene PUF response, la imprime
 *   Boot N+2+: solo reconstruye y muestra la PUF response
 */

#include <stdio.h>
#include <esp_sleep.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <puflib.h>
#include <esp_system.h>
#include <esp_log.h>
#include "nvs_flash.h"
#include "nvs.h"

#define TAG "PUF_PROV"

/* Solo diagnóstico: se incrementa en cada despertar desde deep sleep durante
 * el enrollment. El estado oficial del PUF vive en NVS/puflib, no aquí. */
RTC_DATA_ATTR volatile uint32_t puf_wake_stub_hits = 0;

/*
 * Verifica en NVS si el enrollment ya se completo.
 * Retorna true si ya existe un enrollment previo.
 */
static bool is_enrollment_done(void)
{
    /* Inicializar NVS default (no la particion Sec_Store) */
    esp_err_t err = nvs_flash_init();
    /* NVS llena o formato incompatible: borrar e init borran claves (p. ej.
     * enrolled); el próximo arranque volverá a hacer enrollment. */
    if (err == ESP_ERR_NVS_NO_FREE_PAGES ||
        err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

    nvs_handle_t h;
    err = nvs_open("puf_state", NVS_READONLY, &h);
    if (err != ESP_OK) return false;

    uint8_t done = 0;
    err = nvs_get_u8(h, "enrolled", &done);
    nvs_close(h);
    return (err == ESP_OK && done == 1);
}

/*
 * Marca en NVS que el enrollment se completo.
 */
static void mark_enrollment_done(void)
{
    nvs_handle_t h;
    if (nvs_open("puf_state", NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_u8(h, "enrolled", 1);
        nvs_commit(h);
        nvs_close(h);
    }
}

void app_main(void)
{
    puflib_init();

    ESP_LOGI(TAG, "Wake stub ejecutado %lu veces", (unsigned long)puf_wake_stub_hits);

    /*
     * Solo ejecutar enrollment si NO se ha completado antes.
     * enroll_puf() internamente dispara multiples ciclos de deep sleep
     * para medir la SRAM. En cada ciclo, app_main() se ejecuta de nuevo,
     * por eso es critico no re-enrollar despues de que termine.
     */
    if (!is_enrollment_done()) {
        ESP_LOGI(TAG, "====== ENROLLMENT (puede tardar varios minutos) ======");
        enroll_puf();
        mark_enrollment_done();
        ESP_LOGI(TAG, "====== ENROLLMENT COMPLETO, guardado en NVS ======");
    } else {
        ESP_LOGI(TAG, "Enrollment previo detectado, saltando enrollment.");
    }

    /* Con enrolled=1 no se vuelve a llamar enroll_puf(); aun así hay que
     * reconstruir la respuesta estable desde helper data en NVS. */
    /*
     * Si la respuesta aún no está en RAM (PUF_STATE != RESPONSE_READY),
     * get_puf_response() intenta obtenerla o indica que falta otro ciclo.
     * Si falla, get_puf_response_reset() reinicia el chip; no hay retorno aquí.
     */
    if (PUF_STATE != RESPONSE_READY) {
        bool puf_ok = get_puf_response();
        if (!puf_ok) {
            ESP_LOGW(TAG, "PUF no lista, reiniciando para captura SRAM...");
            get_puf_response_reset();
        }
    }

    ESP_LOGI(TAG, "=== PUF RESPONSE (%d bytes) ===", PUF_RESPONSE_LEN);
    /* Volcado hex por UART para captura manual o herramientas (p. ej. fase 2). */
    if (PUF_RESPONSE_LEN > 0) {
        for (size_t i = 0; i < PUF_RESPONSE_LEN; ++i) {
            printf("%02X ", PUF_RESPONSE[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        printf("\n");
    } else {
        ESP_LOGE(TAG, "ERROR: PUF_RESPONSE_LEN es 0. El enrollment pudo haber fallado.");
        ESP_LOGE(TAG, "Ejecuta: idf.py -p PUERTO erase-flash");
        ESP_LOGE(TAG, "Luego:   idf.py -p PUERTO flash monitor");
    }
    ESP_LOGI(TAG, "================================");

    /* Libera estado temporal de la respuesta en RAM (puflib); no borra NVS ni el enrollment. */
    clean_puf_response();
    ESP_LOGI(TAG, "Provisioning completo.");
}

/*
 * Wake stub en RTC IRAM: se ejecuta al salir de deep sleep, antes del arranque
 * normal de la app. Primero esp_default_wake_deep_sleep(); luego
 * puflib_wake_up_stub() para que puflib muestree la SRAM en cada ciclo del enrollment.
 */
void __attribute__((used)) RTC_IRAM_ATTR esp_wake_deep_sleep(void)
{
    puf_wake_stub_hits++;
    esp_default_wake_deep_sleep();
    puflib_wake_up_stub();
}
