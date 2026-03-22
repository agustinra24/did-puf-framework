idf_component_register(
    SRCS
        "src/aes_cbc.c"
        "src/hmac_sha512.c"
        "src/pkcs_7.c"
        "src/secure_storage_nvs.c"
        "src/api_secure_storage.c"
    INCLUDE_DIRS "include"
    PRIV_REQUIRES mbedtls nvs_flash esp_system
)
