#ifndef HTTP_CLIENT_HELPER_H
#define HTTP_CLIENT_HELPER_H

#include <stddef.h>
#include "esp_err.h"
#include "esp_http_client.h"

typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
} http_resp_t;

esp_err_t http_get_and_parse(const char *http_address,
                             char **output_base,
                             size_t *output_length);

esp_err_t http_event_handler(esp_http_client_event_t *evt);

esp_err_t http_post_and_get_response(const char *http_address,
                                     const char *json_body_to_post,
                                     char **response_output,
                                     size_t *response_length);

#endif
