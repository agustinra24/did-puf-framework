#include <stdlib.h>
#include <string.h>
#include "mbedtls/base64.h"
#include "base64.h"
#include "esp_log.h"

#define BASE64_TAG "[BASE64]"
#define BASE64_MAX_OUTPUT (32 * 1024)

int base64_encode_alloc(const uint8_t *in, size_t in_len, char **out_b64)
{
    if (!in || !out_b64){
        ESP_LOGE(BASE64_TAG, "There is not a valiad in or in_len");
        return -1;
    }

    *out_b64 = NULL;
    size_t olen = 0;

    int ret = mbedtls_base64_encode(NULL, 0, &olen, in, in_len);

    if (olen == 0){
        ESP_LOGE(BASE64_TAG, "The size is 0, empty. Nothing to decode");
        return -2;
    }

    if (olen > BASE64_MAX_OUTPUT){
        ESP_LOGE(BASE64_TAG, "The size exceeded the MAX OUTPUT, preventing overflow");
        return -3;
    }

    char *buf = (char *)malloc(olen + 1);
    if (!buf){
        ESP_LOGE(BASE64_TAG, "Not Allocating Memory");
        return -4;
    }

    size_t actual_size = 0;

    ret = mbedtls_base64_encode((unsigned char *)buf, olen + 1, &actual_size, in, in_len);
    if (ret != 0) {
        free(buf);
        ESP_LOGE(BASE64_TAG, "Not Decoding");
        return -5;
    }

    buf[actual_size] = '\0';

    *out_b64 = buf;
    return 0;
}

int base64_decode_alloc(const char *in_b64, uint8_t **out, size_t *out_len)
{
    if (!in_b64 || !out || !out_len){
        ESP_LOGE(BASE64_TAG, "There is not a valid in or in_len");
        return -1;
    }

    *out = NULL;
    *out_len = 0;

    const size_t in_len = strlen(in_b64);
    if (in_len == 0){
        ESP_LOGE(BASE64_TAG, "The size is 0, empty. Nothing to decode");
        return -2;
    }

    size_t olen = 0;

    int ret = mbedtls_base64_decode(NULL, 0, &olen,
                                    (const unsigned char *)in_b64, in_len);

    if (olen == 0){
        ESP_LOGE(BASE64_TAG, "Buffer to small");
        return -3;
    }
    if (olen > BASE64_MAX_OUTPUT){
        ESP_LOGE(BASE64_TAG, "The size exceeded the MAX OUTPUT, preventing overflow");
        return -4;
    }

    uint8_t *buf = (uint8_t *)malloc(olen);
    if (!buf){
        ESP_LOGE(BASE64_TAG, "Not Allocating Memory");
        return -5;
    }

    size_t actual_size = 0;

    ret = mbedtls_base64_decode(buf, olen, &actual_size,
                                (const unsigned char *)in_b64, in_len);
    if (ret != 0) {
        free(buf);
        ESP_LOGE(BASE64_TAG, "Not Decoding");
        return -6;
    }

    *out = buf;
    *out_len = actual_size;
    return 0;
}
