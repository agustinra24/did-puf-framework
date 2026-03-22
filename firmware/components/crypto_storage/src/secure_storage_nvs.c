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

#include "secure_storage_nvs.h"


void update_hmac_secure_storage_structure(alex_secstore_record_t *self, uint8_t *hmac){
    /* Store HMAC size and copy HMAC tag bytes. */
    self->hmac_size = ALEX_SS_HMAC_LEN;
    memcpy(self->hmac, hmac, self->hmac_size);
}

/**
 * @brief Populate a secure storage record structure.
 *
 * This function fills all fields of the secure storage record:
 * - Copies the fixed magic header into @p self->header
 * - Sets version/reserved/counter
 * - Copies IV and HMAC buffers into the record
 * - Copies the variable-length encrypted payload into @p self->data
 *
 * @note This function assumes @p self points to a buffer large enough to hold:
 *       sizeof(alex_secstore_record_t) + data_size bytes.
 *
 * @param[out] self       Pointer to a secure storage record to initialize.
 * @param[in]  counter    Monotonic/anti-rollback counter to store in the record.
 * @param[in]  iv         Pointer to IV buffer (must contain ALEX_SS_IV_LEN bytes).
 * @param[in]  hmac       Pointer to HMAC buffer (must contain ALEX_SS_HMAC_LEN bytes).
 * @param[in]  data_size  Number of bytes to copy into the variable-length payload.
 * @param[in]  data       Pointer to encrypted payload buffer (must contain data_size bytes).
 *
 * @return None.
 */


void create_secure_storage_structure(alex_secstore_record_t *self,
                                    uint32_t counter,
                                    uint8_t *iv,
                                    uint8_t *hmac,
                                    uint32_t data_size,
                                    uint8_t *data)
{
    /** @brief Fixed 16-byte magic header used to identify the record format. */
    uint8_t ALEX_SS_HEADER[ALEX_SS_HEADER_LEN] = {
        '_','_','A','l','e','x','S','e','c','S','t','o','r','e','_','_'
    };

    /* Copy magic header into record. */
    memcpy(self->header, ALEX_SS_HEADER, ALEX_SS_HEADER_LEN);

    /* Set format version and reserved field. */
    self->version  = ALEX_SS_VERSION;
    self->reserved = 0x0;

    /* Set anti-rollback counter. */
    self->counter = counter;

    /* Store IV size and copy IV bytes. */
    self->iv_size = ALEX_SS_IV_LEN;
    memcpy(self->iv, iv, self->iv_size);

    /* Store HMAC size and copy HMAC tag bytes. */
    self->hmac_size = ALEX_SS_HMAC_LEN;
    memcpy(self->hmac, hmac, self->hmac_size);

    /* Store payload size and copy encrypted payload into flexible array. */
    self->data_size = data_size;
    memcpy(self->data, data, self->data_size);
}

/**
 * @brief Print a secure storage record for debugging.
 *
 * Prints all fields of the record in a human-readable format:
 * - Header as ASCII
 * - Version, reserved, counter, IV size, HMAC size, data size
 * - IV, HMAC, and data as hexadecimal
 * - Additionally prints a hexdump using ESP-IDF log helper.
 *
 * @warning This function is for debugging only. Avoid printing secrets in production.
 *
 * @param[in] self Pointer to a populated secure storage record.
 *
 * @return None.
 */
void print_secure_storage_structure(alex_secstore_record_t *self)
{
    printf("--- SECURE STORAGE STRUCTURE ---\n");

    /* Print header as ASCII characters (not null-terminated). */
    printf("[+]Header: ");
    for (int i = 0; i < ALEX_SS_HEADER_LEN; i++) {
        putchar(self->header[i]);
    }
    printf("\n");

    /* Print metadata fields. */
    printf("[+]Version: %u\n", self->version);
    printf("[+]Reserved: %u\n", self->reserved);
    printf("[+]Counter: %lu\n", self->counter);
    printf("[+]IV Size: %lu\n", self->iv_size);

    /* Print IV bytes in hex. */
    printf("[+]IV: ");
    for (int i = 0; i < self->iv_size; i++) {
        printf("%02X", self->iv[i]);
    }
    printf("\n");

    /* Print HMAC size and HMAC bytes in hex. */
    printf("[+]HMAC Size: %lu\n", self->hmac_size);
    printf("[+]HMAC: ");
    for (int i = 0; i < self->hmac_size; i++) {
        printf("%02X", self->hmac[i]);
    }
    printf("\n");

    /* Print encrypted payload size and payload bytes in hex. */
    printf("[+]Data Size: %lu\n", self->data_size);
    printf("[+]Data: ");
    for (int i = 0; i < self->data_size; i++) {
        printf("%02X", self->data[i]);
    }
    printf("\n");

    /* ESP-IDF hexdump helper (logs buffer in hex). */
    ESP_LOG_BUFFER_HEXDUMP("DATA HEX FORMAT", self->data, self->data_size, ESP_LOG_INFO);
    printf("--------------------------------------------\n");
}

/**
 * @brief Initialize the custom NVS partition used for secure storage.
 *
 * Initializes the NVS storage engine on the partition labeled
 * @c Secure_Store_Partition (e.g., "Sec_Store").
 *
 * If the partition has no free pages or an incompatible version is detected,
 * the partition is erased and re-initialized.
 *
 * @return
 *  - ESP_OK on success
 *  - ESP_ERR_* on failure
 */
esp_err_t sec_store_nvs_init(void)
{
    esp_err_t err = nvs_flash_init_partition(Secure_Store_Partition);

    /* Handle common NVS init errors by erasing and retrying. */
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(Tag_SS, "NVS partition needs erase, err=%s", esp_err_to_name(err));
        ESP_ERROR_CHECK(nvs_flash_erase_partition(Secure_Store_Partition));
        err = nvs_flash_init_partition(Secure_Store_Partition);
    }

    return err;
}

/**
 * @brief Open an NVS handle from the custom secure storage partition/namespace.
 *
 * Opens the namespace @c Secure_Store_NameSpace (e.g., "SecureStore") inside the
 * NVS partition @c Secure_Store_Partition (e.g., "Sec_Store") for read/write access.
 *
 * @param[out] nvs_handle Pointer to where the opened NVS handle will be stored.
 *
 * @return
 *  - ESP_OK on success
 *  - ESP_ERR_* on failure
 */
esp_err_t sec_store_nvs_open(nvs_handle_t *nvs_handle)
{
    return nvs_open_from_partition(Secure_Store_Partition,
                                   Secure_Store_NameSpace,
                                   NVS_READWRITE,
                                   nvs_handle);
}

/**
 * @brief Write a binary blob into secure storage NVS.
 *
 * Stores @p buf as a BLOB value associated with @p key_name inside the custom
 * NVS partition/namespace.
 *
 * If @p key_name already exists, the value is overwritten.
 *
 * @param[in] key_name NVS key name (max 15 characters).
 * @param[in] buf      Pointer to data buffer to store.
 * @param[in] len      Size of @p buf in bytes.
 *
 * @return
 *  - ESP_OK on success
 *  - ESP_ERR_INVALID_ARG if key_name/buf is NULL or len==0
 *  - ESP_ERR_* on failure (open/set/commit errors)
 */
esp_err_t sec_store_write_blob(const char *key_name, const void *buf, size_t len)
{
    if (!key_name || !buf || len == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t h;
    esp_err_t err = sec_store_nvs_open(&h);
    if (err != ESP_OK) {
        ESP_LOGE(Tag_SS, "nvs_open_from_partition failed: %s", esp_err_to_name(err));
        return err;
    }

    /* Write blob value. */
    err = nvs_set_blob(h, key_name, buf, len);
    if (err != ESP_OK) {
        ESP_LOGE(Tag_SS, "nvs_set_blob failed: %s", esp_err_to_name(err));
        nvs_close(h);
        return err;
    }

    /* Commit changes to flash. */
    err = nvs_commit(h);
    nvs_close(h);

    if (err != ESP_OK) {
        ESP_LOGE(Tag_SS, "nvs_commit failed: %s\n", esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(Tag_SS, "THE DATA WAS WRITED TO NVS %s", Secure_Store_NameSpace);
    return ESP_OK;
}

/**
 * @brief Read a blob from secure storage NVS and allocate memory for it.
 *
 * This function:
 *  1) Opens the custom NVS partition/namespace
 *  2) Queries the blob size for @p key
 *  3) Allocates a buffer of that size using malloc()
 *  4) Reads the blob into the allocated buffer
 *
 * @note Caller is responsible for freeing @p *out_buf when done.
 *
 * @param[in]  key      NVS key name to read.
 * @param[out] out_buf  Output pointer to allocated buffer (set to NULL on failure).
 * @param[out] out_len  Output length of allocated buffer in bytes (0 on failure).
 *
 * @return
 *  - ESP_OK on success
 *  - ESP_ERR_INVALID_ARG for invalid parameters
 *  - ESP_ERR_NVS_NOT_FOUND if key does not exist
 *  - ESP_ERR_NO_MEM if malloc fails
 *  - ESP_ERR_* on other NVS failures
 */
esp_err_t secstore_read_blob_alloc(const char *key, void **out_buf, size_t *out_len)
{
    if (!key || !out_buf || !out_len) {
        return ESP_ERR_INVALID_ARG;
    }

    *out_buf = NULL;
    *out_len = 0;

    nvs_handle_t h;
    esp_err_t err = sec_store_nvs_open(&h);
    if (err != ESP_OK) {
        ESP_LOGE(Tag_SS, "nvs_open_from_partition failed: %s", esp_err_to_name(err));
        return err;
    }

    /* Query the required size of the blob. */
    size_t required = 0;
    err = nvs_get_blob(h, key, NULL, &required);
    if (err != ESP_OK) {
        nvs_close(h);

        if (err == ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGW(Tag_SS, "Blob key '%s' not found", key);
        } else {
            ESP_LOGE(Tag_SS, "nvs_get_blob(size) failed: %s", esp_err_to_name(err));
        }
        return err;
    }

    /* Allocate buffer for the blob. */
    void *buf = malloc(required);
    if (!buf) {
        nvs_close(h);
        ESP_LOGE(Tag_SS, "malloc(%u) failed", (unsigned)required);
        return ESP_ERR_NO_MEM;
    }

    /* Read the blob into the allocated buffer. */
    err = nvs_get_blob(h, key, buf, &required);
    nvs_close(h);

    if (err != ESP_OK) {
        free(buf);
        ESP_LOGE(Tag_SS, "nvs_get_blob(read) failed: %s", esp_err_to_name(err));
        return err;
    }

    *out_buf = buf;
    *out_len = required;

    ESP_LOGI(Tag_SS, "Read OK (len=%u)", (unsigned)required);
    return ESP_OK;
}

/**
 * @brief Verify a read blob buffer against basic expected constraints.
 *
 * Checks:
 *  - Buffer pointers are valid
 *  - read_len is at least the fixed record header size
 *  - read_len matches @p expected
 *
 * On failure, this function frees @p *read_buf, sets it to NULL,
 * and returns an error code.
 *
 * @param[in,out] read_buf  Pointer to the allocated buffer pointer.
 * @param[in]     read_len  Actual length of the buffer.
 * @param[in]     expected  Expected total record size.
 *
 * @return
 *  - ESP_OK on success
 *  - ESP_ERR_INVALID_ARG if read_buf or *read_buf is NULL
 *  - ESP_ERR_INVALID_SIZE if size checks fail
 */
esp_err_t verify_secstore_read(void **read_buf, size_t read_len, size_t expected)
{
    if (read_buf == NULL || *read_buf == NULL) {
        ESP_LOGE(Tag_SS, "Invalid buffer pointer");
        return ESP_ERR_INVALID_ARG;
    }

    /* Minimum size check: must contain fixed header portion. */
    if (read_len < sizeof(alex_secstore_record_t)) {
        ESP_LOGE(Tag_SS, "Blob too small: got=%zu, need>=%zu",
                 read_len, sizeof(alex_secstore_record_t));
        free(*read_buf);
        *read_buf = NULL;
        return ESP_ERR_INVALID_SIZE;
    }

    /* Full size check: must match expected total size. */
    if (expected != read_len) {
        ESP_LOGE(Tag_SS, "Size mismatch: expected=%zu, got=%zu", expected, read_len);
        free(*read_buf);
        *read_buf = NULL;
        return ESP_ERR_INVALID_SIZE;
    }

    ESP_LOGI(Tag_SS, "Verification success");
    return ESP_OK;
}

/**
 * @brief Print statistics for an NVS partition.
 *
 * Retrieves and prints:
 *  - used entries
 *  - free entries
 *  - total entries
 *  - number of namespaces
 *
 * @param[in] name_partition NVS partition label (e.g., "Sec_Store").
 *
 * @return None.
 */
void general_partition_info(const char *name_partition)
{
    nvs_stats_t handler;
    esp_err_t err = nvs_get_stats(name_partition, &handler);
    if (err != ESP_OK) {
        ESP_LOGE(Tag_SS, "Failed to get NVS stats for %s: %s",
                 name_partition, esp_err_to_name(err));
        return;
    }

    ESP_LOGI(Tag_SS,
             "used: %d, free: %d, total: %d, namespace count: %d",
             handler.used_entries,
             handler.free_entries,
             handler.total_entries,
             handler.namespace_count);
}

/**
 * @brief Fatal error handler for secure storage.
 *
 * If @p err is not ESP_OK, logs the error and enters an infinite loop
 * with a periodic delay to avoid busy-waiting.
 *
 * @param[in] err ESP-IDF error code.
 *
 * @return None (does not return on error).
 */
void error_handler(esp_err_t err)
{
    if (err != ESP_OK) {
        ESP_LOGE(Tag_SS, "FATAL ERROR: %s", esp_err_to_name(err));
        while (true) {
            vTaskDelay(pdMS_TO_TICKS(1000));
        }
    }
}
