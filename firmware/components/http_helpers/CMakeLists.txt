idf_component_register(
    SRCS "src/http_transactions.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_http_client json
)
