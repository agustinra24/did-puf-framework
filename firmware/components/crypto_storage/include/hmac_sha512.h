#ifndef HMAC_SHA512_H
#define HMAC_SHA512_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "secure_storage_nvs.h"

#define HMAC_LEN 64
#define TAG_HMAC "[HMAC]"

int get_hmac(const uint8_t *key, size_t key_size,
             const uint8_t *plaintext, size_t plaintext_len,
             uint8_t *hmac);

bool verify_hmac(const uint8_t *hmac_1,
                 const uint8_t *hmac_2,
                 size_t len);

int get_hmac_secure_storage(const uint8_t *key, size_t key_size,
                            const alex_secstore_record_t *self,
                            uint8_t *hmac);

#endif /* HMAC_SHA512_H */
