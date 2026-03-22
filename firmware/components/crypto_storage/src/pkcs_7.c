#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "esp_log.h"
#include "esp_system.h"          // esp_fill_random()
#include "pkcs_7.h"
#define AES_BLOCK_SIZE 16 

/**
 * @brief Apply PKCS#7 padding to arbitrary data for AES-CBC.
 *
 * AES operates on 16-byte blocks. This function pads the input
 * data so its length becomes a multiple of 16 bytes, following
 * the PKCS#7 specification.
 *
 * Padding rule:
 *   - Let N = number of padding bytes required
 *   - Append N bytes, each with value N (0x01 .. 0x10)
 *   - Padding is ALWAYS added, even if input is already aligned
 *
 * Memory:
 *   - Output buffer is dynamically allocated
 *   - Caller is responsible for calling free()
 *
 * @param[in]  input        Pointer to input data
 * @param[in]  input_len    Length of input data in bytes
 * @param[out] output       Pointer to padded buffer (allocated inside)
 * @param[out] output_len   Length of padded buffer
 *
 * @return 0 on success
 * @return -1 invalid parameters
 * @return -2 memory allocation failure
 */

int pkcs7_pad_16(const uint8_t *input, size_t input_len,
                 uint8_t **output, size_t *output_len) {
    /* ----------------------------------------------------------
     * Validate input parameters
     * ---------------------------------------------------------- */
    if (input == NULL || output == NULL || output_len == NULL) {
        return -1;  // Invalid arguments
    }

    /* ----------------------------------------------------------
     * Calculate required padding length
     *
     * AES block size = 16 bytes
     * ---------------------------------------------------------- */
    size_t padding_len = AES_BLOCK_SIZE - (input_len % AES_BLOCK_SIZE);

    /* ----------------------------------------------------------
     * PKCS#7 rule: always add padding
     *
     * If input length is already a multiple of 16,
     * we add a full block of padding (16 bytes).
     * ---------------------------------------------------------- */
    if (padding_len == 0) {
        padding_len = AES_BLOCK_SIZE;
    }

    /* ----------------------------------------------------------
     * Compute total output length
     * ---------------------------------------------------------- */
    size_t total_len = input_len + padding_len;

    /* ----------------------------------------------------------
     * Allocate output buffer
     * ---------------------------------------------------------- */
    uint8_t *buf = (uint8_t *)malloc(total_len); // creates a pointer
    if (buf == NULL) {
        return -2;  // Heap allocation failed
    }

    /* ----------------------------------------------------------
     * Copy original input data
     * ---------------------------------------------------------- */
    memcpy(buf, input, input_len); // pointer dest, pointer src, len
    

    /* ----------------------------------------------------------
     * Append PKCS#7 padding bytes
     *
     * Each padding byte has the value of padding_len.
     * ---------------------------------------------------------- */
    memset(buf + input_len, (uint8_t)padding_len, padding_len); // buf + input_len This points exactly to the first byte AFTER the original data

    /* ----------------------------------------------------------
     * Return results to caller
     * ---------------------------------------------------------- */
    *output = buf;
    *output_len = total_len;

    return 0;  // Success
}


/**
 * @brief Remove PKCS#7 padding for AES (16-byte block size).
 *
 * Input must be a multiple of 16 bytes (AES block size).
 * Valid PKCS#7 padding values for AES: 1..16.
 *
 * Output buffer is allocated with malloc; caller must free().
 *
 * @param[in]  input       Decrypted data that still contains PKCS#7 padding
 * @param[in]  input_len   Length of input in bytes (must be multiple of 16)
 * @param[out] output      Pointer to allocated plaintext buffer (no padding)
 * @param[out] output_len  Plaintext length (without padding)
 *
 * @return  0  Success
 * @return -1  Invalid arguments (NULL pointers)
 * @return -2  Invalid length (0 or not multiple of 16)
 * @return -3  Invalid padding length byte (must be 1..16)
 * @return -4  Padding bytes do not match expected PKCS#7 pattern
 * @return -5  Memory allocation failure
 */
int pkcs7_unpad_16(const uint8_t *input,
                          size_t input_len,
                          uint8_t **output,
                          size_t *output_len)
{
    // Basic argument validation
    if (input == NULL || output == NULL || output_len == NULL) {
        return -1;
    }

    // AES-CBC plaintext after decryption must be block-aligned (16 bytes)
    if (input_len == 0 || (input_len % AES_BLOCK_SIZE) != 0) {
        return -2;
    }

    // The last byte indicates how many padding bytes were added (PKCS#7)
    uint8_t pad = input[input_len - 1];

    // For AES block size 16, valid padding length is 1..16
    if (pad == 0 || pad > AES_BLOCK_SIZE) {
        return -3;
    }

    //Validate that the last 'pad' bytes all equal 'pad'
    //    Example: if pad=0x04, the last 4 bytes must be 04 04 04 04
    for (size_t i = 0; i < (size_t)pad; i++) {
        if (input[input_len - 1 - i] != pad) {
            return -4;
        }
    }

    // Compute length without padding
    size_t plain_len = input_len - (size_t)pad;

    // Allocate output (+1 optional null terminator for debugging prints)
    uint8_t *buf = (uint8_t *)malloc(plain_len + 1);
    if (buf == NULL) {
        return -5;
    }

    // Copy only plaintext
    memcpy(buf, input, plain_len);

    //Add null terminator for convenience (safe for printing)
    buf[plain_len] = 0;

    // Return outputs
    *output = buf;
    *output_len = plain_len;

    return 0;
}
