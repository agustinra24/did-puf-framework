cmake_minimum_required(VERSION 3.16)

set(EXTRA_COMPONENT_DIRS
    ${CMAKE_CURRENT_LIST_DIR}/../components/crypto_utils
    ${CMAKE_CURRENT_LIST_DIR}/../components/crypto_storage
    ${CMAKE_CURRENT_LIST_DIR}/../components/http_helpers
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(root_of_trust_fw)
