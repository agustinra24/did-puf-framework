cmake_minimum_required(VERSION 3.16)

set(EXTRA_COMPONENT_DIRS
    ${CMAKE_CURRENT_LIST_DIR}/../components/crypto_utils
    ${CMAKE_CURRENT_LIST_DIR}/../components/crypto_storage
    ${CMAKE_CURRENT_LIST_DIR}/../components/http_helpers
    ${CMAKE_CURRENT_LIST_DIR}/../components/ml_dsa
)

option(BENCH_MLDSA "Run ML-DSA-87 benchmark at boot (N=10000, ~45 min)" OFF)
if(BENCH_MLDSA)
    add_compile_definitions(BENCH_MLDSA)
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(root_of_trust_fw)
