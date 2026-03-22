cmake_minimum_required(VERSION 3.16)

# Indicar al build system dónde encontrar el componente puflib
set(EXTRA_COMPONENT_DIRS ${CMAKE_CURRENT_LIST_DIR}/../components/esp32_puflib)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(puf_provisioning)
