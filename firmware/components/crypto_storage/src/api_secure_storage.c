#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes_cbc.h"
#include "hmac_sha512.h"
#include "pkcs_7.h"
#include "secure_storage_nvs.h"

#include "esp_log.h"
#include "esp_random.h"
#include "esp_err.h"

#include "mbedtls/sha512.h"
#include "api_secure_storage.h"

#define AES_COUNTER 1
#define TAG_SSR "[SECURE STORAGE REGION]"

void sha512_stream(const uint8_t *data, size_t len, uint8_t out[64])
{
    mbedtls_sha512_context ctx;

    mbedtls_sha512_init(&ctx);
    mbedtls_sha512_starts(&ctx, 0);   // 0 = SHA-512
    mbedtls_sha512_update(&ctx, data, len);
    mbedtls_sha512_finish(&ctx, out);
    mbedtls_sha512_free(&ctx);
}

esp_err_t write_secure_storage_region(const uint8_t *plaintext, size_t plaintext_len,
                                      const char *key_name_nvs,
                                      struct aes_256_obj *self_aes)
{
    esp_err_t status = ESP_OK;
    esp_err_t err = ESP_OK;
    int ret = 0;
    uint8_t *ciphertext = NULL;
    size_t ciphertext_len = 0;
    alex_secstore_record_t *secure_store = NULL;

    if (plaintext == NULL || key_name_nvs == NULL || self_aes == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    update_iv_aes(self_aes);

    ret = aes_cbc_encrypt_pkcs7(self_aes->key,
                                self_aes->keybits,
                                self_aes->iv,
                                plaintext,
                                plaintext_len,
                                &ciphertext,
                                &ciphertext_len);
    if (ret != 0) {
        ESP_LOGE(TAG_SSR, "Encrypt failed: -0x%04X", (unsigned)(-ret));
        status = ESP_FAIL;
        goto cleanup;
    }

    size_t total_size = sizeof(alex_secstore_record_t) + ciphertext_len;

    secure_store = malloc(total_size);
    if (secure_store == NULL) {
        ESP_LOGE(TAG_SSR, "Malloc failed");
        status = ESP_ERR_NO_MEM;
        goto cleanup;
    }

    uint8_t hmac[ALEX_SS_HMAC_LEN];
    memset(hmac, 0xff, sizeof(hmac));

    uint32_t counter = AES_COUNTER;

    create_secure_storage_structure(secure_store,
                                    counter,
                                    self_aes->iv,
                                    hmac,
                                    (uint32_t)ciphertext_len,
                                    ciphertext);

    ret = get_hmac_secure_storage(self_aes->key,
                                  AES_256,
                                  secure_store,
                                  hmac);
    if (ret != 0) {
        ESP_LOGE(TAG_SSR, "HMAC generation failed: %d", ret);
        status = ESP_FAIL;
        goto cleanup;
    }

    update_hmac_secure_storage_structure(secure_store, hmac);

    err = sec_store_nvs_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG_SSR, "sec_store_nvs_init failed: %s", esp_err_to_name(err));
        status = err;
        goto cleanup;
    }

    err = sec_store_write_blob(key_name_nvs, secure_store, total_size);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_SSR, "Error writing blob to NVS: %s", esp_err_to_name(err));
        status = err;
        goto cleanup;
    }

    ESP_LOGI(TAG_SSR, "Write to secure storage region success");
    print_secure_storage_structure(secure_store);

cleanup:
    free(ciphertext);
    free(secure_store);

    return status;
}

esp_err_t read_secure_storage_region_alloc(const char *key_name_nvs,
                                           struct aes_256_obj *self_aes,
                                           uint8_t **out_plain,
                                           size_t *out_plain_len)
{
    esp_err_t err = ESP_OK;
    void *read_buf = NULL;
    size_t read_len = 0;
    uint8_t *decrypted = NULL;
    size_t decrypted_len = 0;

    if (!key_name_nvs || !self_aes || !out_plain || !out_plain_len) {
        ESP_LOGE(TAG_SSR, "Invalid Arguments");
        return ESP_ERR_INVALID_ARG;
    }

    *out_plain = NULL;
    *out_plain_len = 0;

    err = sec_store_nvs_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG_SSR, "sec_store_nvs_init failed: %s", esp_err_to_name(err));
        goto cleanup;
    }

    err = secstore_read_blob_alloc(key_name_nvs, &read_buf, &read_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_SSR, "Error reading blob: %s", esp_err_to_name(err));
        goto cleanup;
    }

    if (read_len < sizeof(alex_secstore_record_t)) {
        err = ESP_ERR_INVALID_SIZE;
        ESP_LOGE(TAG_SSR, "Blob too small");
        goto cleanup;
    }

    alex_secstore_record_t *got = (alex_secstore_record_t *)read_buf;
    size_t expected = sizeof(alex_secstore_record_t) + (size_t)got->data_size;

    err = verify_secstore_read(&read_buf, read_len, expected);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_SSR, "Verify blob structure failed: %s", esp_err_to_name(err));
        goto cleanup;
    }

    uint8_t hmac_recovered[ALEX_SS_HMAC_LEN];

    if (get_hmac_secure_storage(self_aes->key, AES_256, got, hmac_recovered) != 0) {
        ESP_LOGE(TAG_SSR, "Failed to compute HMAC");
        err = ESP_FAIL;
        goto cleanup;
    }

    if (!verify_hmac(hmac_recovered, got->hmac, ALEX_SS_HMAC_LEN)) {
        ESP_LOGE(TAG_SSR, "HMAC mismatch");
        err = ESP_FAIL;
        goto cleanup;
    }

    read_and_update_iv_aes(self_aes, got->iv);
    int ret = aes_cbc_decrypt_pkcs7(
        self_aes->key,
        self_aes->keybits,
        got->iv,
        got->data,
        got->data_size,
        &decrypted,
        &decrypted_len
    );

    if (ret != 0) {
        ESP_LOGE(TAG_SSR, "Decrypt failed: -0x%04X", (unsigned)(-ret));
        err = ESP_FAIL;
        goto cleanup;
    }
    print_secure_storage_structure(got);

    *out_plain = decrypted;
    *out_plain_len = decrypted_len;

    decrypted = NULL;

cleanup:
    if (decrypted) {
        memset(decrypted, 0, decrypted_len);
        free(decrypted);
    }

    if (read_buf) {
        free(read_buf);
    }

    return err;
}

bool derive_key_from_puf(uint8_t *key_output, struct puf_object *self,
                         const uint8_t *puf_data, size_t puf_len)
{
    uint8_t h512[64];

    if (puf_data != NULL && puf_len > 0) {
        sha512_stream(puf_data, puf_len, h512);
        memcpy(key_output, h512, AES_256);

        if (self != NULL) {
            memcpy(self->hash, h512, PUF_HASH_LEN);
            self->init = true;
            self->puf_hash_len = PUF_HASH_LEN;
        }

        ESP_LOGI(TAG_SSR, "Key derived from PUF data (%u bytes)", (unsigned)puf_len);
        memset(h512, 0, sizeof(h512));
        return true;
    } else {
        /* Debug/test mode: hardcoded key */
        ESP_LOGW(TAG_SSR, "No PUF data provided, using hardcoded test key");
        uint8_t test_key[16] = {
            0x10, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01
        };

        sha512_stream(test_key, 16, h512);
        memcpy(key_output, h512, AES_256);

        if (self != NULL) {
            memcpy(self->hash, h512, PUF_HASH_LEN);
            self->init = false;
            self->puf_hash_len = PUF_HASH_LEN;
        }

        memset(h512, 0, sizeof(h512));
        return true;
    }
}
