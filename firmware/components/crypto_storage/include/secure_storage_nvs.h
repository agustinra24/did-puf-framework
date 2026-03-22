#ifndef SECURE_STORAGE_NVS_H
#define SECURE_STORAGE_NVS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_log_buffer.h"

#include "nvs.h"
#include "nvs_flash.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"


/* ======================= Configuration Macros ======================= */

#define ALEX_SS_HEADER_LEN        16
#define ALEX_SS_IV_LEN            16
#define ALEX_SS_HMAC_LEN          64
#define ALEX_SS_VERSION           1

#define Secure_Store_Partition    "Sec_Store"
#define Secure_Store_NameSpace    "SecureStore"
#define Tag_SS                    "[SECURE_STORE]"


/* ======================= Secure Storage Record ======================= */

typedef struct __attribute__((packed)) alex_secure_store {
    uint8_t  header[ALEX_SS_HEADER_LEN];
    uint16_t version;
    uint16_t reserved;
    uint32_t counter;

    uint32_t iv_size;
    uint8_t  iv[ALEX_SS_IV_LEN];

    uint32_t hmac_size;
    uint8_t  hmac[ALEX_SS_HMAC_LEN];

    uint32_t data_size;
    uint8_t  data[];
} alex_secstore_record_t;


/* ======================= API Functions ======================= */

esp_err_t sec_store_nvs_init(void);
esp_err_t sec_store_nvs_open(nvs_handle_t *nvs_handle);

esp_err_t sec_store_write_blob(const char *key_name,
                               const void *buf,
                               size_t len);

esp_err_t secstore_read_blob_alloc(const char *key,
                                   void **out_buf,
                                   size_t *out_len);

esp_err_t verify_secstore_read(void **read_buf,
                               size_t read_len,
                               size_t expected);

void create_secure_storage_structure(alex_secstore_record_t *self,
                                     uint32_t counter,
                                     uint8_t *iv,
                                     uint8_t *hmac,
                                     uint32_t data_size,
                                     uint8_t *data);

void print_secure_storage_structure(alex_secstore_record_t *self);
void general_partition_info(const char *name_partition);
void error_handler(esp_err_t err);
void update_hmac_secure_storage_structure(alex_secstore_record_t *self, uint8_t *hmac);

#endif /* SECURE_STORAGE_NVS_H */
