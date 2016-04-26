cmake_minimum_required(VERSION 2.8.3)
project(ECDSAUTIL C)
set(ECDSAUTIL_VERSION 0.3.2)

set(CMAKE_MODULE_PATH ${ECDSAUTIL_SOURCE_DIR})
find_package(libuecc REQUIRED)


set(LIBDIR "lib${LIB_SUFFIX}")

set(BUILD_SHARED_LIBS TRUE CACHE BOOL "Build shared libraries")

add_subdirectory(src)
