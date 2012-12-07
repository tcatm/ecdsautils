cmake_minimum_required(VERSION 2.8.3)
project(ECDSAUTIL C)

set(CMAKE_MODULE_PATH ${ECDSAUTIL_SOURCE_DIR})
set(CMAKE_C_FLAGS -std=c99)

find_package(UECC REQUIRED)

add_subdirectory(src)
