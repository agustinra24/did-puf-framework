#ifndef PKCS_7_H
#define PKCS_7_H

#include <stddef.h>   // size_t
#include <stdint.h>   // uint8_t

int pkcs7_pad_16(const uint8_t *input, size_t input_len,
                 uint8_t **output, size_t *output_len);

int pkcs7_unpad_16(const uint8_t *input, size_t input_len,
                   uint8_t **output, size_t *output_len);

#endif // PKCS_7_H
