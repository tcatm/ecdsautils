cmake_minimum_required(VERSION 2.8.3)
project(ECDSAUTIL C)

find_package(PkgConfig REQUIRED)
pkg_check_modules(UECC REQUIRED libuecc>=2)

set(CMAKE_MODULE_PATH ${ECDSAUTIL_SOURCE_DIR})
set(CMAKE_C_FLAGS "-std=c99 -Wall")

add_subdirectory(src)
