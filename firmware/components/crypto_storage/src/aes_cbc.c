#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "esp_log.h"
#include "esp_system.h"          // esp_fill_random()
#include "mbedtls/aes.h"
#include "esp_random.h"
#include "pkcs_7.h"
#include "aes_cbc.h"


void create_aes_256_obj(struct aes_256_obj *self, uint8_t *key){
    memcpy(self->key, key, AES_256);

    // Generate IV
    uint8_t iv[IV_AES];
    esp_fill_random(iv, IV_AES);
    memcpy(self->iv, iv, IV_AES);

    self->keybits = 256;
}

void read_and_update_iv_aes(struct aes_256_obj *self, uint8_t *iv){
    memcpy(self->iv, iv, IV_AES);
}

void update_iv_aes(struct aes_256_obj *self){
    // Generate IV
    uint8_t iv[IV_AES];
    esp_fill_random(iv, IV_AES);
    memcpy(self->iv, iv, IV_AES);
}


/**
 * @brief Encrypt plaintext using AES-CBC + PKCS#7 padding (AES block size = 16 bytes).
 *
 * IMPORTANT NOTES:
 *  - keybits must be 128, 192, or 256 (AES key size in bits)
 *  - iv_in must be exactly 16 bytes (CBC IV size = AES block size)
 *  - CBC requires the SAME IV for decryption, so you must store/transmit iv_in
 *  - This function allocates the ciphertext buffer with malloc()
 *    -> caller must free(*ciphertext)
 *
 * @param[in]  key            AES key bytes (length must match keybits/8)
 * @param[in]  keybits        AES key size in bits: 128 / 192 / 256
 * @param[in]  iv_in          16-byte Initialization Vector (IV)
 * @param[in]  plaintext      Input plaintext bytes
 * @param[in]  plaintext_len  Length of plaintext in bytes
 * @param[out] ciphertext     Output pointer to allocated ciphertext buffer
 * @param[out] ciphertext_len Output length (ciphertext bytes)
 *
 * @return 0 on success
 *         -1 invalid args
 *         -2 malloc failed
 *         otherwise: mbedTLS error code from mbedtls_aes_* functions
 */
int aes_cbc_encrypt_pkcs7(const uint8_t *key, unsigned keybits,
                                const uint8_t iv_in[16],
                                const uint8_t *plaintext, size_t plaintext_len,
                                uint8_t **ciphertext, size_t *ciphertext_len)
{
    int ret = 0;                     // Will store return codes from functions
    mbedtls_aes_context aes;          // mbedTLS AES context (holds key schedule, etc.)
    uint8_t iv[16];                  // Local IV copy (mbedtls_aes_crypt_cbc updates IV)
    uint8_t *padded = NULL;          // Will hold PKCS#7 padded plaintext (malloc'd)
    size_t padded_len = 0;           // Length of padded plaintext (multiple of 16)

    /*  Validate input pointers (avoid crashes / undefined behavior) */
    if (key == NULL || iv_in == NULL || plaintext == NULL ||
        ciphertext == NULL || ciphertext_len == NULL) {
        return -1;
    }

    /*  PKCS#7 pad plaintext so its length becomes a multiple of 16 bytes */
    ret = pkcs7_pad_16(plaintext, plaintext_len, &padded, &padded_len);
    if (ret != 0) {
        return ret;                  // pkcs7_pad_16 failed; nothing allocated to free here
    }

    /*  Allocate output buffer for ciphertext (same length as padded plaintext) */
    uint8_t *out = (uint8_t *)malloc(padded_len);
    if (out == NULL) {
        free(padded);                // padded was allocated; free it on failure
        return -2;
    }

    /*  Copy IV into a local buffer because CBC encryption updates IV in-place */
    memcpy(iv, iv_in, sizeof(iv));   // sizeof(iv) == 16

    /*  Initialize AES context (must be done before using it) */
    mbedtls_aes_init(&aes);

    /* Set the AES encryption key (prepares internal round keys) */
    ret = mbedtls_aes_setkey_enc(&aes, key, keybits);
    if (ret != 0) {
        mbedtls_aes_free(&aes);      // release internal resources
        free(padded);
        free(out);
        return ret;
    }

    /* Encrypt using AES-CBC.
     *    - MBEDTLS_AES_ENCRYPT selects encryption mode
     *    - padded_len MUST be a multiple of 16 (ensured by PKCS#7 padding)
     *    - iv will be modified by this call (streaming behavior)
     */
    ret = mbedtls_aes_crypt_cbc(&aes,
                                MBEDTLS_AES_ENCRYPT,
                                padded_len,
                                iv,
                                padded,
                                out);

    /*  Clean up AES context and temporary padded plaintext */
    mbedtls_aes_free(&aes);
    free(padded);

    /*  If encryption failed, free the output buffer and return error */
    if (ret != 0) {
        free(out);
        return ret;
    }

    /*  Return ciphertext pointer and length to caller */
    *ciphertext = out;
    *ciphertext_len = padded_len;

    return 0;                        // Success
}

/**
 * @brief Decrypt ciphertext using AES-CBC and then remove PKCS#7 padding.
 *
 * REQUIREMENTS:
 *  - keybits must be 128, 192, or 256
 *  - iv_in must be 16 bytes (AES block size)
 *  - ciphertext_len must be a multiple of 16 bytes (CBC works on full blocks)
 *
 * MEMORY:
 *  - Allocates plaintext buffer (output) using malloc()
 *    -> caller must free(*plaintext)
 *
 * @param[in]  key             AES key bytes (size must match keybits/8)
 * @param[in]  keybits         AES key size in bits: 128/192/256
 * @param[in]  iv_in           16-byte IV used during encryption (must be the same)
 * @param[in]  ciphertext      Input ciphertext
 * @param[in]  ciphertext_len  Length of ciphertext (must be multiple of 16)
 * @param[out] plaintext       Output pointer to allocated plaintext (unpadded)
 * @param[out] plaintext_len   Output length (unpadded plaintext length)
 *
 * @return 0 on success
 *         -1 invalid args
 *         -2 invalid ciphertext length
 *         -3 malloc failed
 *         otherwise: mbedTLS or unpadding error code
 */
int aes_cbc_decrypt_pkcs7(const uint8_t *key, unsigned keybits,
                                const uint8_t iv_in[16],
                                const uint8_t *ciphertext, size_t ciphertext_len,
                                uint8_t **plaintext, size_t *plaintext_len)
{
    int ret = 0;                    // Holds return codes from called functions
    mbedtls_aes_context aes;         // mbedTLS AES context
    uint8_t iv[16];                 // Local IV copy (CBC updates IV in-place)

    /*  Validate pointers */
    if (key == NULL || iv_in == NULL || ciphertext == NULL ||
        plaintext == NULL || plaintext_len == NULL) {
        return -1;
    }

    /*  Validate ciphertext length:
     *    - must not be zero
     *    - must be a multiple of 16 bytes (AES block size)
     */
    if (ciphertext_len == 0 || (ciphertext_len % 16) != 0) {
        return -2;
    }

    /*  Allocate a temporary buffer for the raw decrypted data (still padded).
     *    Decryption output length equals ciphertext length in CBC mode.
     */
    uint8_t *tmp = (uint8_t *)malloc(ciphertext_len);
    if (tmp == NULL) {
        return -3;
    }

    /*  Copy IV into a local variable because mbedtls_aes_crypt_cbc modifies it */
    memcpy(iv, iv_in, sizeof(iv));  // sizeof(iv) == 16

    /*  Initialize AES context */
    mbedtls_aes_init(&aes);

    /*  Load AES key for decryption (builds decryption key schedule) */
    ret = mbedtls_aes_setkey_dec(&aes, key, keybits);
    if (ret != 0) {
        mbedtls_aes_free(&aes);
        free(tmp);
        return ret;
    }

    /*  Decrypt using AES-CBC
     *    - MBEDTLS_AES_DECRYPT selects decryption mode
     *    - ciphertext_len must be a multiple of 16 (validated above)
     *    - iv is updated in-place (streaming behavior)
     */
    ret = mbedtls_aes_crypt_cbc(&aes,
                                MBEDTLS_AES_DECRYPT,
                                ciphertext_len,
                                iv,
                                ciphertext,
                                tmp);

    /*  AES context is no longer needed */
    mbedtls_aes_free(&aes);

    /*  If decryption failed, free tmp and return error */
    if (ret != 0) {
        free(tmp);
        return ret;
    }

    /*  Remove PKCS#7 padding.
     *     This allocates a new buffer 'out' that contains ONLY the real plaintext.
     */
    uint8_t *out = NULL;
    size_t out_len = 0;

    ret = pkcs7_unpad_16(tmp, ciphertext_len, &out, &out_len);

    /*  tmp is no longer needed (we either have out, or we failed) */
    free(tmp);

    /*  If unpadding failed, return error (caller gets no plaintext buffer) */
    if (ret != 0) {
        return ret;
    }

    /*  Return final plaintext buffer and length to the caller */
    *plaintext = out;
    *plaintext_len = out_len;

    return 0;                       // Success
}
