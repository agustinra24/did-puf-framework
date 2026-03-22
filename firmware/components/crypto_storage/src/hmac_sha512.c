#include <string.h>
#include <stdio.h>
#include "hmac_sha512.h"
#include "esp_log.h"
#include "mbedtls/md.h"
#include "secure_storage_nvs.h"

/**
 * @brief Compute an HMAC using SHA-512.
 *
 * This function computes an HMAC-SHA512 over the input plaintext using
 * the provided secret key. Internally, it relies on the mbedTLS message
 * digest API with HMAC enabled.
 *
 * The output HMAC is written into the buffer pointed to by POINTER hmac,
 * which must be at least HMAC_LEN (64 bytes).
 *
 * @param[in]  key             Pointer to the secret key
 * @param[in]  key_size        Length of the secret key in bytes
 * @param[in]  plaintext       Pointer to the input data to authenticate
 * @param[in]  plaintext_len   Length of the input data in bytes
 * @param[out] hmac            Output buffer where the HMAC will be stored
 *
 * @return 0   Success
 * @return -1  Invalid input pointers
 * @return -2  Invalid key size
 * @return -3  SHA-512 algorithm not available
 * @return <0  mbedTLS internal error
 */

int get_hmac(const uint8_t *key, size_t key_size,
             const uint8_t *plaintext, size_t plaintext_len,
             uint8_t *hmac)
{
    /* Validate input parameters */
    if (!key || !plaintext || !hmac) {
        return -1;
    }

    if (key_size == 0) {
        return -2;
    }

    int ret = 0;

    /* Retrieve SHA-512 message-digest information */
    const mbedtls_md_info_t *md =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);

    if (!md) {
        ESP_LOGE(TAG_HMAC, "SHA-512 not available");
        return -3;
    }

    /* Initialize the mbedTLS message-digest context */
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    /* Configure the context for HMAC operation (last parameter = 1) */
    ret = mbedtls_md_setup(&ctx, md, 1);
    if (ret != 0) {
        ESP_LOGE(TAG_HMAC, "md_setup failed: %d", ret);
        goto cleanup;
    }

    /* Start the HMAC computation using the secret key */
    ret = mbedtls_md_hmac_starts(&ctx, key, key_size);
    if (ret != 0) {
        ESP_LOGE(TAG_HMAC, "hmac_starts failed: %d", ret);
        goto cleanup;
    }

    /* Process the input plaintext (can be called multiple times) */
    ret = mbedtls_md_hmac_update(&ctx, plaintext, plaintext_len);
    if (ret != 0) {
        ESP_LOGE(TAG_HMAC, "hmac_update failed: %d", ret);
        goto cleanup;
    }

    /* Finalize the HMAC computation and store the result */
    ret = mbedtls_md_hmac_finish(&ctx, hmac);
    if (ret != 0) {
        ESP_LOGE(TAG_HMAC, "hmac_finish failed: %d", ret);
        goto cleanup;
    }

    ESP_LOGI(TAG_HMAC, "HMAC Success");
    ret = 0;

cleanup:
    /* Free all resources associated with the context */
    mbedtls_md_free(&ctx);
    return ret;
}

/**
 * @brief Verify two HMAC values using constant-time comparison.
 *
 * This function compares two HMAC buffers in constant time to prevent
 * timing side-channel attacks. It is suitable for authentication and
 * integrity verification in secure storage and communication protocols.
 *
 * @param[in] hmac_1  Pointer to the first HMAC buffer
 * @param[in] hmac_2  Pointer to the second HMAC buffer
 * @param[in] len     Length of the HMAC buffers in bytes (typically HMAC_LEN)
 *
 * @return true   HMACs match
 * @return false  HMACs differ or invalid input
 */
bool verify_hmac(const uint8_t *hmac_1, const uint8_t *hmac_2, size_t len)
{
    /* Validate input parameters */
    if (!hmac_1 || !hmac_2) {
        return false;
    }

    uint8_t diff = 0;

    /* Constant-time comparison */
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(hmac_1[i] ^ hmac_2[i]);
    }

    if (diff != 0) {
        ESP_LOGE(TAG_HMAC, "HMAC Mismatch");
        return false;
    }

    ESP_LOGI(TAG_HMAC, "HMAC Verification Success");
    return true;
}

//  create the get hmac function for a specific alex_secure_store

int get_hmac_secure_storage(const uint8_t *key, size_t key_size,
                            const alex_secstore_record_t *self,
                            uint8_t *hmac)
{
    int ret = 0;

    /* Validate input parameters */
    if (key == NULL || self == NULL || hmac == NULL) {
        return -1;
    }

    if (key_size == 0) {
        return -2;
    }

    /* Validate fixed-size fields before using them */
    if (self->iv_size != ALEX_SS_IV_LEN) {
        ESP_LOGE(TAG_HMAC, "Invalid IV size: %lu", (unsigned long)self->iv_size);
        return -3;
    }

    /* Retrieve SHA-512 message-digest information */
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    if (md == NULL) {
        ESP_LOGE(TAG_HMAC, "SHA-512 not available");
        return -4;
    }

    /* Initialize the mbedTLS message-digest context */
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    /* Configure the context for HMAC operation */
    ret = mbedtls_md_setup(&ctx, md, 1);
    if (ret != 0) {
        ESP_LOGE(TAG_HMAC, "md_setup failed: %d", ret);
        goto cleanup;
    }

    /* Start the HMAC computation using the secret key */
    ret = mbedtls_md_hmac_starts(&ctx, key, key_size);
    if (ret != 0) {
        ESP_LOGE(TAG_HMAC, "hmac_starts failed: %d", ret);
        goto cleanup;
    }

    /* Add header */
    ret = mbedtls_md_hmac_update(&ctx,
                                 self->header,
                                 sizeof(self->header));
    if (ret != 0) {
        ESP_LOGE(TAG_HMAC, "hmac_update failed in header: %d", ret);
        goto cleanup;
    }

    /* Add version */
    ret = mbedtls_md_hmac_update(&ctx,
                                 (const unsigned char *)&self->version,
                                 sizeof(self->version));
    if (ret != 0) {
        ESP_LOGE(TAG_HMAC, "hmac_update failed in version: %d", ret);
        goto cleanup;
    }

    /* Add reserved */
    ret = mbedtls_md_hmac_update(&ctx,
                                 (const unsigned char *)&self->reserved,
                                 sizeof(self->reserved));
    if (ret != 0) {
        ESP_LOGE(TAG_HMAC, "hmac_update failed in reserved: %d", ret);
        goto cleanup;
    }

    /* Add counter */
    ret = mbedtls_md_hmac_update(&ctx,
                                 (const unsigned char *)&self->counter,
                                 sizeof(self->counter));
    if (ret != 0) {
        ESP_LOGE(TAG_HMAC, "hmac_update failed in counter: %d", ret);
        goto cleanup;
    }

    /* Add IV size */
    ret = mbedtls_md_hmac_update(&ctx,
                                 (const unsigned char *)&self->iv_size,
                                 sizeof(self->iv_size));
    if (ret != 0) {
        ESP_LOGE(TAG_HMAC, "hmac_update failed in iv_size: %d", ret);
        goto cleanup;
    }

    /* Add IV */
    ret = mbedtls_md_hmac_update(&ctx,
                                 self->iv,
                                 self->iv_size);
    if (ret != 0) {
        ESP_LOGE(TAG_HMAC, "hmac_update failed in iv: %d", ret);
        goto cleanup;
    }

    /* Add data size */
    ret = mbedtls_md_hmac_update(&ctx,
                                 (const unsigned char *)&self->data_size,
                                 sizeof(self->data_size));
    if (ret != 0) {
        ESP_LOGE(TAG_HMAC, "hmac_update failed in data_size: %d", ret);
        goto cleanup;
    }

    /* Add encrypted data */
    ret = mbedtls_md_hmac_update(&ctx,
                                 self->data,
                                 self->data_size);
    if (ret != 0) {
        ESP_LOGE(TAG_HMAC, "hmac_update failed in data: %d", ret);
        goto cleanup;
    }

    /* Finalize the HMAC computation */
    ret = mbedtls_md_hmac_finish(&ctx, hmac);
    if (ret != 0) {
        ESP_LOGE(TAG_HMAC, "hmac_finish failed: %d", ret);
        goto cleanup;
    }

    ESP_LOGI(TAG_HMAC, "HMAC success");
    ret = 0;

cleanup:
    mbedtls_md_free(&ctx);
    return ret;
}