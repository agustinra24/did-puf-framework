cmake_minimum_required(VERSION 3.16)

set(EXTRA_COMPONENT_DIRS ${CMAKE_CURRENT_LIST_DIR}/../components/esp32_puflib)

# PUF measurement profiles: "basic" (200, ~5 min), "strong" (1000, ~25 min)
if(NOT DEFINED PUF_PROFILE)
    set(PUF_PROFILE "basic")
endif()

if(PUF_PROFILE STREQUAL "strong")
    add_compile_definitions(PROVISIONING_MEASUREMENTS=1000)
    message(STATUS "PUF Profile: strong (1000 measurements)")
else()
    add_compile_definitions(PROVISIONING_MEASUREMENTS=200)
    message(STATUS "PUF Profile: basic (200 measurements)")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(puf_provisioning)
