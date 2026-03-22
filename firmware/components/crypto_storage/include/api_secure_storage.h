#ifndef API_SECURE_STORAGE
#define API_SECURE_STORAGE

#include "aes_cbc.h"
#include "hmac_sha512.h"
#include "pkcs_7.h"
#include "secure_storage_nvs.h"
#define PUF_HASH_LEN 64

struct puf_object{
    bool init;
    size_t puf_hash_len;
    uint8_t hash[PUF_HASH_LEN];
};

void sha512_stream(const uint8_t *data, size_t len, uint8_t out[64]);

esp_err_t write_secure_storage_region(const uint8_t *plaintext, size_t plaintext_len,
                                      const char *key_name_nvs,
                                      struct aes_256_obj *self_aes);

esp_err_t read_secure_storage_region_alloc(const char *key_name_nvs,
                                           struct aes_256_obj *self_aes,
                                           uint8_t **out_plain,
                                           size_t *out_plain_len);

/* Derive AES-256 key from raw PUF bytes via SHA-512.
 * puf_data: raw PUF response bytes (from NVS or UART).
 * puf_len: length of PUF data.
 * If puf_data is NULL, uses a hardcoded test key (debug mode). */
bool derive_key_from_puf(uint8_t *key_output, struct puf_object *self,
                         const uint8_t *puf_data, size_t puf_len);

#endif // API_SECURE_STORAGE
