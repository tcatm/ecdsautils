cmake_minimum_required(VERSION 2.8.3)
project(ECDSAUTIL C)

set(CMAKE_MODULE_PATH ${ECDSAUTIL_SOURCE_DIR})
find_package(libuecc REQUIRED)

add_subdirectory(src)
