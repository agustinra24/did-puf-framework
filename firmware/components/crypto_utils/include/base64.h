#ifndef BASE64_UTILS_H
#define BASE64_UTILS_H

#include <stddef.h>
#include <stdint.h>

int base64_encode_alloc(const uint8_t *in, size_t in_len, char **out_b64);
/* out_b64 is a null-terminated string, caller must free() */

int base64_decode_alloc(const char *in_b64, uint8_t **out, size_t *out_len);
/* out is binary buffer, caller must free() */

#endif
