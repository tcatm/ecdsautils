cmake_minimum_required(VERSION 2.8.3)
project(ECDSAUTIL C)

find_package(PkgConfig REQUIRED)
pkg_check_modules(UECC REQUIRED libuecc>=3)

set(CMAKE_MODULE_PATH ${ECDSAUTIL_SOURCE_DIR})

add_subdirectory(src)
