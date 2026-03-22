#include <string.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_http_client.h"
#include "cJSON.h"
#include "http_transactions.h"

#define TAG_HTTP_GET   "HTTP_GET"
#define TAG_HTTP_POST  "HTTP_POST"

esp_err_t http_get_and_parse(const char *http_address,
                             char **output_base,
                             size_t *output_length)
{
    if (!http_address || !output_base || !output_length) {
        return ESP_ERR_INVALID_ARG;
    }

    *output_base = NULL;
    *output_length = 0;

    esp_http_client_config_t config = {
        .url = http_address,
        .method = HTTP_METHOD_GET,
        .timeout_ms = 8000,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        ESP_LOGE(TAG_HTTP_GET, "HTTP Client doesn't start");
        return ESP_FAIL;
    }

    esp_err_t err = esp_http_client_perform(client);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_HTTP_GET, "HTTP perform failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return err;
    }

    int status = esp_http_client_get_status_code(client);
    if (status < 200 || status >= 300) {
        ESP_LOGE(TAG_HTTP_GET, "HTTP status error: %d", status);
        esp_http_client_cleanup(client);
        return ESP_FAIL;
    }

    int content_length = esp_http_client_get_content_length(client);
    if (content_length <= 0) {
        ESP_LOGE(TAG_HTTP_GET, "Invalid or unknown Content-Length: %d", content_length);
        esp_http_client_cleanup(client);
        return ESP_FAIL;
    }

    char *buf = (char *)malloc((size_t)content_length + 1);
    if (!buf) {
        ESP_LOGE(TAG_HTTP_GET, "Memory allocation failed");
        esp_http_client_cleanup(client);
        return ESP_ERR_NO_MEM;
    }

    int read_len = esp_http_client_read_response(client, buf, content_length);
    if (read_len < 0) {
        ESP_LOGE(TAG_HTTP_GET, "Response read failed");
        free(buf);
        esp_http_client_cleanup(client);
        return ESP_FAIL;
    }

    buf[read_len] = '\0';

    *output_base = buf;
    *output_length = (size_t)read_len;

    ESP_LOGI(TAG_HTTP_GET, "HTTP response received (%d bytes)", read_len);

    esp_http_client_cleanup(client);
    return ESP_OK;
}

esp_err_t http_event_handler(esp_http_client_event_t *evt)
{
    http_resp_t *resp = (http_resp_t *)evt->user_data;

    switch (evt->event_id) {

    case HTTP_EVENT_ON_DATA:
        if (resp && evt->data && evt->data_len > 0) {

            size_t needed = resp->len + (size_t)evt->data_len + 1;

            if (needed > resp->cap) {

                size_t new_cap = (resp->cap == 0) ? 512 : resp->cap;
                while (new_cap < needed)
                    new_cap *= 2;

                char *new_buf = (char *)realloc(resp->buf, new_cap);
                if (!new_buf) {
                    ESP_LOGE(TAG_HTTP_POST, "realloc failed");
                    return ESP_ERR_NO_MEM;
                }

                resp->buf = new_buf;
                resp->cap = new_cap;
            }

            memcpy(resp->buf + resp->len,
                   evt->data,
                   (size_t)evt->data_len);

            resp->len += (size_t)evt->data_len;

            resp->buf[resp->len] = '\0';
        }
        break;

    default:
        break;
    }

    return ESP_OK;
}

esp_err_t http_post_and_get_response(const char *http_address,
                                     const char *json_body_to_post,
                                     char **response_output,
                                     size_t *response_length)
{
    if (!http_address || !json_body_to_post ||
        !response_output || !response_length) {
        return ESP_ERR_INVALID_ARG;
    }

    *response_output = NULL;
    *response_length = 0;

    http_resp_t *resp = (http_resp_t *)calloc(1, sizeof(http_resp_t));
    if (!resp) {
        return ESP_ERR_NO_MEM;
    }

    esp_http_client_config_t config = {
        .url = http_address,
        .method = HTTP_METHOD_POST,
        .event_handler = http_event_handler,
        .user_data = resp,
        .timeout_ms = 8000,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        free(resp);
        return ESP_FAIL;
    }

    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_header(client, "Accept", "application/json");

    esp_http_client_set_post_field(client,
                                   json_body_to_post,
                                   (int)strlen(json_body_to_post));

    esp_err_t err = esp_http_client_perform(client);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_HTTP_POST,
                 "HTTP POST failed: %s",
                 esp_err_to_name(err));
        goto cleanup_fail;
    }

    int status = esp_http_client_get_status_code(client);
    if (status < 200 || status >= 300) {
        ESP_LOGE(TAG_HTTP_POST,
                 "Server returned error status %d",
                 status);
        err = ESP_FAIL;
        goto cleanup_fail;
    }

    if (!resp->buf || resp->len == 0) {
        ESP_LOGE(TAG_HTTP_POST, "Empty response body");
        err = ESP_FAIL;
        goto cleanup_fail;
    }

    *response_output = resp->buf;
    *response_length = resp->len;

    resp->buf = NULL;
    resp->len = 0;
    resp->cap = 0;

    esp_http_client_cleanup(client);
    free(resp);

    return ESP_OK;

cleanup_fail:
    esp_http_client_cleanup(client);
    free(resp->buf);
    free(resp);
    return err;
}
