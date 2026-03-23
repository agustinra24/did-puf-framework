/*
 * Root of Trust — Firmware funcional v4
 *
 * Flujo de ejecucion:
 *   1. NVS init
 *   2. Cargar PUF de NVS (o fallback a MAC como ID)
 *   3. Si no esta configurado -> modo UART (CFG_START/CFG_END) -> reboot
 *   4. Cargar config de NVS (server URL, WiFi, etc.)
 *   5. Conectar WiFi (10 reintentos, reboot si falla)
 *   6. Si no esta enrolled -> Step 0: POST enrollment -> almacenar Kyber pk -> marcar enrolled
 *   7. Modo operacional:
 *      - heartbeat_task: POST periodico cada N segundos
 *      - event_task: POST inmediato al presionar boton BOOT (GPIO0)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_http_client.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "driver/uart.h"
#include "driver/gpio.h"
#include "mbedtls/sha512.h"
#include "api_secure_storage.h"
#include "base64.h"
#include "http_transactions.h"
#include "cJSON.h"
#include "ml_dsa.h"
#include "esp_heap_caps.h"

static const char *TAG = "RoT";
#define NVS_NAMESPACE      "rot_config"
#define NVS_KEY_CONFIGURED "configured"
#define CFG_VALUE_MAX_LEN  256
#define CFG_LINE_MAX_LEN   2048
#define CFG_UART_PORT      UART_NUM_0
#define DEFAULT_INTERVAL_S 30
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1
#define WIFI_MAX_RETRIES   10
#define SHA512_LEN         64
#define DEVICE_ID_HEX_LEN 16
#define PUF_MAX_LEN        512
#define NVS_KEY_ENROLLED   "enrolled"
#define EVENT_BUTTON_GPIO  GPIO_NUM_0
#define EVENT_DEBOUNCE_MS  300

typedef struct {
    char server_url[CFG_VALUE_MAX_LEN];
    char server_port[16];
    char endpoint[CFG_VALUE_MAX_LEN];
    char wifi_ssid[64];
    char wifi_pass[64];
    int  interval_s;
} rot_config_t;

static rot_config_t g_config = {0};
static char g_device_id[DEVICE_ID_HEX_LEN + 1] = {0};
static uint8_t g_puf_hash[SHA512_LEN] = {0};
static bool g_puf_valid = false;
static uint8_t g_puf_raw[PUF_MAX_LEN] = {0};
static size_t  g_puf_raw_len = 0;
static EventGroupHandle_t s_wifi_event_group = NULL;
static int s_wifi_retry_count = 0;

/* Parse hex string "4D F2 DD ..." into bytes. Returns count. */
static int parse_hex_string(const char *hex, uint8_t *out, int max_len) {
    int count = 0;
    const char *p = hex;
    while (*p && count < max_len) {
        while (*p == ' ' || *p == '\n' || *p == '\r') p++;
        if (!*p) break;
        char hi = *p++;
        if (!*p) break;
        char lo = *p++;
        int h = (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 :
                (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10 :
                (hi >= '0' && hi <= '9') ? hi - '0' : -1;
        int l = (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 :
                (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10 :
                (lo >= '0' && lo <= '9') ? lo - '0' : -1;
        if (h < 0 || l < 0) break;
        out[count++] = (uint8_t)((h << 4) | l);
    }
    return count;
}

static void derive_identity(const uint8_t *puf_data, int puf_len) {
    mbedtls_sha512_context ctx;
    mbedtls_sha512_init(&ctx);
    mbedtls_sha512_starts(&ctx, 0);
    mbedtls_sha512_update(&ctx, puf_data, puf_len);
    mbedtls_sha512_finish(&ctx, g_puf_hash);
    mbedtls_sha512_free(&ctx);
    for (int i = 0; i < DEVICE_ID_HEX_LEN / 2; i++)
        snprintf(&g_device_id[i * 2], 3, "%02x", g_puf_hash[i]);
    g_puf_valid = true;
    ESP_LOGI(TAG, "Root of Trust established. Device ID: %s", g_device_id);
    printf("Root of Trust established. Device ID: %s\n", g_device_id);
}

static bool load_puf_from_nvs(void) {
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) return false;
    uint8_t puf[PUF_MAX_LEN];
    size_t len = PUF_MAX_LEN;
    esp_err_t err = nvs_get_blob(h, "puf_resp", puf, &len);
    nvs_close(h);
    if (err != ESP_OK || len == 0) return false;
    ESP_LOGI(TAG, "PUF Response loaded from NVS (%d bytes)", (int)len);
    memcpy(g_puf_raw, puf, len);
    g_puf_raw_len = len;
    derive_identity(puf, len);
    return true;
}

static bool nvs_is_configured(void) {
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) return false;
    uint8_t val = 0;
    esp_err_t err = nvs_get_u8(h, NVS_KEY_CONFIGURED, &val);
    nvs_close(h);
    return (err == ESP_OK && val == 1);
}

static esp_err_t nvs_store_str(const char *key, const char *value) {
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_set_str(h, key, value);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

static esp_err_t nvs_read_str(const char *key, char *buf, size_t buflen) {
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &h);
    if (err != ESP_OK) return err;
    err = nvs_get_str(h, key, buf, &buflen);
    nvs_close(h);
    return err;
}

static esp_err_t config_load_from_nvs(void) {
    esp_err_t err;
    err = nvs_read_str("srv_url", g_config.server_url, sizeof(g_config.server_url));
    if (err != ESP_OK) return err;
    err = nvs_read_str("srv_port", g_config.server_port, sizeof(g_config.server_port));
    if (err != ESP_OK) return err;
    err = nvs_read_str("endpoint", g_config.endpoint, sizeof(g_config.endpoint));
    if (err != ESP_OK) return err;
    char interval_str[16] = {0};
    if (nvs_read_str("interval", interval_str, sizeof(interval_str)) == ESP_OK)
        g_config.interval_s = atoi(interval_str);
    if (g_config.interval_s < 5) g_config.interval_s = DEFAULT_INTERVAL_S;
    err = nvs_read_str("wifi_ssid", g_config.wifi_ssid, sizeof(g_config.wifi_ssid));
    if (err != ESP_OK) return err;
    nvs_read_str("wifi_pass", g_config.wifi_pass, sizeof(g_config.wifi_pass));
    return ESP_OK;
}

static int uart_read_line(char *buf, size_t buflen, int timeout_ms) {
    int idx = 0;
    int64_t deadline = esp_timer_get_time() + (int64_t)timeout_ms * 1000;
    while (idx < (int)(buflen - 1)) {
        uint8_t ch;
        int len = uart_read_bytes(CFG_UART_PORT, &ch, 1, pdMS_TO_TICKS(100));
        if (len > 0) { if (ch == '\n') break; if (ch == '\r') continue; buf[idx++] = (char)ch; }
        if (esp_timer_get_time() > deadline) break;
    }
    buf[idx] = '\0';
    return idx;
}

static esp_err_t config_process_line(const char *line) {
    const char *eq = strchr(line, '=');
    if (!eq || eq == line) return ESP_ERR_INVALID_ARG;
    size_t key_len = eq - line;
    const char *value = eq + 1;

    /* PUF_RESPONSE: parse hex, store as blob */
    if (key_len == 12 && strncmp(line, "PUF_RESPONSE", 12) == 0) {
        uint8_t puf[PUF_MAX_LEN];
        int puf_len = parse_hex_string(value, puf, PUF_MAX_LEN);
        if (puf_len > 0) {
            nvs_handle_t h;
            if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
                nvs_set_blob(h, "puf_resp", puf, puf_len);
                nvs_commit(h);
                nvs_close(h);
            }
            memcpy(g_puf_raw, puf, puf_len);
            g_puf_raw_len = puf_len;
            derive_identity(puf, puf_len);
            ESP_LOGI(TAG, "PUF Response stored (%d bytes)", puf_len);
        }
        return ESP_OK;
    }

    const char *nvs_key = NULL;
    if      (key_len == 10 && strncmp(line, "SERVER_URL",  10) == 0) nvs_key = "srv_url";
    else if (key_len == 11 && strncmp(line, "SERVER_PORT", 11) == 0) nvs_key = "srv_port";
    else if (key_len ==  8 && strncmp(line, "ENDPOINT",     8) == 0) nvs_key = "endpoint";
    else if (key_len ==  8 && strncmp(line, "INTERVAL",     8) == 0) nvs_key = "interval";
    else if (key_len ==  9 && strncmp(line, "WIFI_SSID",    9) == 0) nvs_key = "wifi_ssid";
    else if (key_len ==  9 && strncmp(line, "WIFI_PASS",    9) == 0) nvs_key = "wifi_pass";
    else return ESP_OK;
    return nvs_store_str(nvs_key, value);
}

static void uart_init(void) {
    uart_config_t uart_config = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    uart_driver_install(CFG_UART_PORT, 2048, 0, 0, NULL, 0);
    uart_param_config(CFG_UART_PORT, &uart_config);
}

static void config_mode(void) {
    const char *id = g_puf_valid ? g_device_id : "unconfigured";
    ESP_LOGW(TAG, "========================================");
    ESP_LOGW(TAG, " ROOT OF TRUST — CONFIG MODE");
    ESP_LOGW(TAG, " Device: %s", id);
    ESP_LOGW(TAG, "========================================");
    printf("CFG_MODE: device_id=%s\n", id);
    char line[CFG_LINE_MAX_LEN];
    while (true) {
        int len = uart_read_line(line, sizeof(line), 1000);
        if (len == 0) continue;
        if (strcmp(line, "CFG_START") != 0) continue;
        int param_count = 0;
        bool success = true;
        int64_t deadline = esp_timer_get_time() + 30000000;
        while (true) {
            len = uart_read_line(line, sizeof(line), 5000);
            if (len == 0) { if (esp_timer_get_time() > deadline) { printf("CFG_ERR:timeout\n"); success = false; break; } continue; }
            if (strcmp(line, "CFG_END") == 0) break;
            if (config_process_line(line) == ESP_OK) param_count++;
        }
        if (!success) continue;
        if (param_count == 0) { printf("CFG_ERR:no_params\n"); continue; }
        nvs_handle_t h;
        if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
            nvs_set_u8(h, NVS_KEY_CONFIGURED, 1); nvs_commit(h); nvs_close(h);
        }
        printf("CFG_OK\n");
        vTaskDelay(pdMS_TO_TICKS(1000));
        esp_restart();
    }
}

static void wifi_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data) {
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) esp_wifi_connect();
    else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_wifi_retry_count < WIFI_MAX_RETRIES) { esp_wifi_connect(); s_wifi_retry_count++; }
        else xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *ev = (ip_event_got_ip_t *)data;
        ESP_LOGI(TAG, "WiFi connected — IP: " IPSTR, IP2STR(&ev->ip_info.ip));
        printf("WiFi connected\n");
        s_wifi_retry_count = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static esp_err_t wifi_init_sta(void) {
    s_wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    esp_event_handler_instance_t h1, h2;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, &h1));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, &h2));
    wifi_config_t wc = {0};
    strncpy((char *)wc.sta.ssid, g_config.wifi_ssid, sizeof(wc.sta.ssid) - 1);
    strncpy((char *)wc.sta.password, g_config.wifi_pass, sizeof(wc.sta.password) - 1);
    wc.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wc));
    ESP_ERROR_CHECK(esp_wifi_start());
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT, pdFALSE, pdFALSE, pdMS_TO_TICKS(30000));
    return (bits & WIFI_CONNECTED_BIT) ? ESP_OK : ESP_FAIL;
}

static void build_url(char *buf, size_t sz) {
    bool wp = (g_config.server_port[0] && strcmp(g_config.server_port,"80") && strcmp(g_config.server_port,"443"));
    if (wp) snprintf(buf, sz, "%s:%s%s", g_config.server_url, g_config.server_port, g_config.endpoint);
    else snprintf(buf, sz, "%s%s", g_config.server_url, g_config.endpoint);
}

static bool is_enrolled(void) {
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) return false;
    uint8_t val = 0;
    esp_err_t err = nvs_get_u8(h, NVS_KEY_ENROLLED, &val);
    nvs_close(h);
    return (err == ESP_OK && val == 1);
}

static esp_err_t execute_step0(void) {
    /* Base64 encode MAC and PUF hash for JSON payload */
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    char *mac_b64 = NULL, *puf_b64 = NULL;
    base64_encode_alloc(mac, 6, &mac_b64);
    base64_encode_alloc(g_puf_hash, SHA512_LEN, &puf_b64);
    if (!mac_b64 || !puf_b64) {
        free(mac_b64); free(puf_b64);
        return ESP_ERR_NO_MEM;
    }

    /* Build Step 0 JSON request */
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "Step", 0);
    cJSON_AddStringToObject(root, "Device_Name", g_device_id);
    cJSON_AddStringToObject(root, "Mac_Address", mac_b64);
    cJSON_AddStringToObject(root, "PUF_Hash", puf_b64);
    char *json_str = cJSON_PrintUnformatted(root);

    /* Build enrollment URL from server config */
    char enroll_url[512];
    snprintf(enroll_url, sizeof(enroll_url), "%s:%s/api/v1/enroll",
             g_config.server_url, g_config.server_port);
    ESP_LOGI(TAG, "Step 0 enrollment -> %s", enroll_url);

    /* POST enrollment request */
    char *resp = NULL;
    size_t resp_len = 0;
    esp_err_t err = http_post_and_get_response(enroll_url, json_str, &resp, &resp_len);

    if (err == ESP_OK && resp) {
        cJSON *rj = cJSON_Parse(resp);
        cJSON *pk_field = rj ? cJSON_GetObjectItem(rj, "kyber_pk") : NULL;
        if (pk_field && pk_field->valuestring) {
            uint8_t *pk = NULL;
            size_t pk_len = 0;
            base64_decode_alloc(pk_field->valuestring, &pk, &pk_len);
            if (pk && pk_len > 0) {
                /* Store Kyber pk encrypted in Sec_Store partition */
                uint8_t aes_key[AES_256];
                struct puf_object puf_obj = {0};
                derive_key_from_puf(aes_key, &puf_obj, g_puf_raw, g_puf_raw_len);
                struct aes_256_obj aes;
                create_aes_256_obj(&aes, aes_key);
                write_secure_storage_region(pk, pk_len, "KyberPK", &aes);
                memset(aes_key, 0, sizeof(aes_key));
                free(pk);

                /* Mark device as enrolled */
                nvs_handle_t h;
                if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
                    nvs_set_u8(h, NVS_KEY_ENROLLED, 1);
                    nvs_commit(h);
                    nvs_close(h);
                }
                ESP_LOGI(TAG, "Step 0 complete. Kyber pk stored (%d bytes)", (int)pk_len);
            } else {
                ESP_LOGE(TAG, "Failed to decode Kyber pk from server response");
                err = ESP_FAIL;
            }
        } else {
            ESP_LOGE(TAG, "Server response missing kyber_pk field");
            err = ESP_FAIL;
        }
        cJSON_Delete(rj);
        free(resp);
    } else if (err == ESP_OK) {
        ESP_LOGE(TAG, "Empty response from enrollment server");
        err = ESP_FAIL;
    }

    cJSON_Delete(root);
    free(json_str);
    free(mac_b64);
    free(puf_b64);

    /* Clear raw PUF from memory after enrollment */
    memset(g_puf_raw, 0, sizeof(g_puf_raw));
    g_puf_raw_len = 0;

    return err;
}

static void heartbeat_task(void *pv) {
    char json[128];
    snprintf(json, sizeof(json), "{\"device_id\":\"%s\",\"status\":\"alive\"}", g_device_id);
    while (true) {
        char url[512];
        build_url(url, sizeof(url));
        char *resp = NULL;
        size_t resp_len = 0;
        esp_err_t err = http_post_and_get_response(url, json, &resp, &resp_len);
        if (err == ESP_OK)
            printf("HTTP OK — Heartbeat from %s\n", g_device_id);
        else
            printf("HTTP ERR — %s\n", esp_err_to_name(err));
        free(resp);
        vTaskDelay(pdMS_TO_TICKS(g_config.interval_s * 1000));
    }
}

static void send_event_report(const char *trigger) {
    char json[192];
    snprintf(json, sizeof(json),
             "{\"device_id\":\"%s\",\"type\":\"event\",\"trigger\":\"%s\"}",
             g_device_id, trigger);
    char url[512];
    build_url(url, sizeof(url));
    char *resp = NULL;
    size_t resp_len = 0;
    esp_err_t err = http_post_and_get_response(url, json, &resp, &resp_len);
    if (err == ESP_OK)
        printf("EVENT — %s from %s\n", trigger, g_device_id);
    else
        printf("EVENT ERR — %s\n", esp_err_to_name(err));
    free(resp);
}

static void event_task(void *pv) {
    gpio_config_t io = {
        .pin_bit_mask = (1ULL << EVENT_BUTTON_GPIO),
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    gpio_config(&io);

    bool last_state = true; /* pulled up = not pressed */
    while (true) {
        bool pressed = (gpio_get_level(EVENT_BUTTON_GPIO) == 0);
        if (pressed && last_state) {
            send_event_report("button");
            vTaskDelay(pdMS_TO_TICKS(EVENT_DEBOUNCE_MS));
        }
        last_state = !pressed;
        vTaskDelay(pdMS_TO_TICKS(50));
    }
}

/* ---- ML-DSA-87 benchmark (compile with -DBENCH_MLDSA=ON) ---- */
#ifdef BENCH_MLDSA
#include <math.h>
#define BENCH_N 10000

typedef struct {
    int     n;
    double  mean;
    double  m2;
    int64_t min;
    int64_t max;
} welford_t;

static void welford_init(welford_t *w) {
    w->n = 0; w->mean = 0; w->m2 = 0; w->min = INT64_MAX; w->max = 0;
}

static void welford_update(welford_t *w, int64_t x_us) {
    w->n++;
    double d1 = (double)x_us - w->mean;
    w->mean += d1 / w->n;
    double d2 = (double)x_us - w->mean;
    w->m2 += d1 * d2;
    if (x_us < w->min) w->min = x_us;
    if (x_us > w->max) w->max = x_us;
}

static double welford_std(const welford_t *w) {
    return (w->n > 1) ? sqrt(w->m2 / w->n) : 0;
}

static void ml_dsa_benchmark(void) {
    int cpu_mhz = CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ;
    size_t heap_before = heap_caps_get_free_size(MALLOC_CAP_8BIT);

    ESP_LOGI(TAG, "=== ML-DSA-87 (FIPS 204) Benchmark ===");
    ESP_LOGI(TAG, "CPU: %d MHz | N: %d | Heap: %u B free",
             cpu_mhz, BENCH_N, (unsigned)heap_before);

    uint8_t *pk  = heap_caps_malloc(ML_DSA_PK_BYTES, MALLOC_CAP_8BIT);
    uint8_t *sk  = heap_caps_malloc(ML_DSA_SK_BYTES, MALLOC_CAP_8BIT);
    uint8_t *sig = heap_caps_malloc(ML_DSA_SIG_BYTES, MALLOC_CAP_8BIT);
    if (!pk || !sk || !sig) {
        ESP_LOGE(TAG, "Heap alloc failed");
        free(pk); free(sk); free(sig);
        return;
    }

    const char *test_msg = "did-puf-framework:enrollment-test";
    size_t msglen = strlen(test_msg);
    const char *test_ctx = "enroll";
    size_t ctxlen = strlen(test_ctx);
    size_t siglen = 0;
    int rc;
    welford_t w;

    /* --- Keygen: N fresh keypairs --- */
    ESP_LOGI(TAG, "Running keygen x%d ...", BENCH_N);
    welford_init(&w);
    for (int i = 0; i < BENCH_N; i++) {
        int64_t t0 = esp_timer_get_time();
        rc = ml_dsa_keygen(pk, sk);
        welford_update(&w, esp_timer_get_time() - t0);
        if (rc != 0) { ESP_LOGE(TAG, "Keygen FAILED iter %d rc=%d", i, rc); goto cleanup; }
        if ((i + 1) % 1000 == 0) {
            ESP_LOGI(TAG, "  keygen %d/%d ...", i + 1, BENCH_N);
            vTaskDelay(1);
        } else if ((i + 1) % 50 == 0) {
            vTaskDelay(1);
        }
    }
    ESP_LOGI(TAG, "Keygen:  Mean=%.2f ms | Std=%.2f ms | Min=%lld ms | Max=%lld ms",
             w.mean / 1000.0, welford_std(&w) / 1000.0, w.min / 1000, w.max / 1000);

    /* --- Sign: N signatures, last keypair, fresh randomness each --- */
    ESP_LOGI(TAG, "Running sign x%d ...", BENCH_N);
    welford_init(&w);
    for (int i = 0; i < BENCH_N; i++) {
        int64_t t0 = esp_timer_get_time();
        rc = ml_dsa_sign(sig, &siglen, (const uint8_t *)test_msg, msglen,
                         (const uint8_t *)test_ctx, ctxlen, sk);
        welford_update(&w, esp_timer_get_time() - t0);
        if (rc != 0) { ESP_LOGE(TAG, "Sign FAILED iter %d rc=%d", i, rc); goto cleanup; }
        if ((i + 1) % 1000 == 0) {
            ESP_LOGI(TAG, "  sign %d/%d ...", i + 1, BENCH_N);
            vTaskDelay(1);
        } else if ((i + 1) % 50 == 0) {
            vTaskDelay(1);
        }
    }
    ESP_LOGI(TAG, "Sign:    Mean=%.2f ms | Std=%.2f ms | Min=%lld ms | Max=%lld ms",
             w.mean / 1000.0, welford_std(&w) / 1000.0, w.min / 1000, w.max / 1000);

    /* --- Verify: N verifications of last signature --- */
    ESP_LOGI(TAG, "Running verify x%d ...", BENCH_N);
    welford_init(&w);
    for (int i = 0; i < BENCH_N; i++) {
        int64_t t0 = esp_timer_get_time();
        rc = ml_dsa_verify(sig, siglen, (const uint8_t *)test_msg, msglen,
                           (const uint8_t *)test_ctx, ctxlen, pk);
        welford_update(&w, esp_timer_get_time() - t0);
        if (rc != 0) { ESP_LOGE(TAG, "Verify FAILED iter %d rc=%d", i, rc); goto cleanup; }
        if ((i + 1) % 1000 == 0) {
            ESP_LOGI(TAG, "  verify %d/%d ...", i + 1, BENCH_N);
            vTaskDelay(1);
        } else if ((i + 1) % 50 == 0) {
            vTaskDelay(1);
        }
    }
    ESP_LOGI(TAG, "Verify:  Mean=%.2f ms | Std=%.2f ms | Min=%lld ms | Max=%lld ms",
             w.mean / 1000.0, welford_std(&w) / 1000.0, w.min / 1000, w.max / 1000);

    /* Tamper test (once) */
    rc = ml_dsa_verify(sig, siglen, (const uint8_t *)"tampered", 8,
                       (const uint8_t *)test_ctx, ctxlen, pk);
    ESP_LOGI(TAG, "Tamper:  %s (expected FAIL)", rc != 0 ? "FAIL" : "PASS");

    ESP_LOGI(TAG, "Peak heap used: %u bytes",
             (unsigned)(heap_before - heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT)));
    ESP_LOGI(TAG, "Key sizes: pk=%u B, sk=%u B, sig=%u B",
             (unsigned)ML_DSA_PK_BYTES, (unsigned)ML_DSA_SK_BYTES, (unsigned)siglen);
    ESP_LOGI(TAG, "=== ML-DSA-87 Benchmark Complete ===");

cleanup:
    if (sk) memset(sk, 0, ML_DSA_SK_BYTES);
    free(pk); free(sk); free(sig);
}
#endif /* BENCH_MLDSA */

void app_main(void) {
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, " ROOT OF TRUST — Firmware Funcional v4");
    ESP_LOGI(TAG, "========================================");

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase(); err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

#ifdef BENCH_MLDSA
    ml_dsa_benchmark();
#endif

    /* Try loading PUF from NVS (survives reboots after config) */
    if (load_puf_from_nvs()) {
        ESP_LOGI(TAG, "PUF identity restored from NVS");
    } else {
        /* Use MAC as fallback ID until PUF is received via config */
        uint8_t mac[6];
        esp_read_mac(mac, ESP_MAC_WIFI_STA);
        snprintf(g_device_id, sizeof(g_device_id), "rot-%02x%02x%02x%02x",
                 mac[2], mac[3], mac[4], mac[5]);
        ESP_LOGW(TAG, "No PUF data. Using MAC ID: %s", g_device_id);
    }

    if (!nvs_is_configured()) { uart_init(); config_mode(); return; }

    err = config_load_from_nvs();
    if (err != ESP_OK) {
        nvs_handle_t h;
        if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
            nvs_erase_key(h, NVS_KEY_CONFIGURED); nvs_commit(h); nvs_close(h);
        }
        esp_restart(); return;
    }

    /* Reload PUF identity after config (it was stored during config_mode) */
    if (!g_puf_valid) load_puf_from_nvs();

    err = wifi_init_sta();
    if (err != ESP_OK) { vTaskDelay(pdMS_TO_TICKS(10000)); esp_restart(); return; }

    /* Step 0: enroll with server if not already registered */
    if (g_puf_valid && !is_enrolled()) {
        ESP_LOGI(TAG, "Not enrolled with server. Executing Step 0...");
        err = execute_step0();
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Step 0 failed: %s. Retrying in 30s...", esp_err_to_name(err));
            vTaskDelay(pdMS_TO_TICKS(30000));
            esp_restart();
            return;
        }
    }

    xTaskCreate(heartbeat_task, "heartbeat", 12288, NULL, 5, NULL);
    xTaskCreate(event_task, "event", 8192, NULL, 5, NULL);
    ESP_LOGI(TAG, "Operational: %s -> %s:%s%s every %ds (button on GPIO%d)",
             g_device_id, g_config.server_url, g_config.server_port,
             g_config.endpoint, g_config.interval_s, EVENT_BUTTON_GPIO);
}
