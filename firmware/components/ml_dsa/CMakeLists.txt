# ML-DSA (FIPS 204) component for ESP-IDF
#
# Wraps mldsa-native (https://github.com/pq-code-package/mldsa-native)
# for ESP32 targets. Uses the Single Compilation Unit (SCU) build.
#
# Configuration: ML-DSA-87 (NIST Level 5) with reduced RAM.

# The SCU file (mldsa_native.c) #includes all source files internally.
# We only compile the SCU file itself.
idf_component_register(
    SRCS "mldsa/mldsa_native.c"
    INCLUDE_DIRS "include" "mldsa"
    PRIV_REQUIRES esp_system
)

# Use our ESP32 config instead of the default.
# PUBLIC so consumers (main.c) also see ML-DSA-87 parameter set.
target_compile_definitions(${COMPONENT_LIB} PUBLIC
    MLD_CONFIG_FILE="mldsa_config_esp32.h"
)

# Include paths: public for the config header, private for internal sources
target_include_directories(${COMPONENT_LIB} PUBLIC
    "${CMAKE_CURRENT_LIST_DIR}/src"
)
target_include_directories(${COMPONENT_LIB} PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/mldsa/src"
)
