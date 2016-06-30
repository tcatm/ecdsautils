cmake_minimum_required(VERSION 2.8.3)
project(ECDSAUTIL C)
set(ECDSAUTIL_VERSION 0.4.0)

set(CMAKE_MODULE_PATH ${ECDSAUTIL_SOURCE_DIR})
find_package(libuecc REQUIRED)

set(DOXYFILE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/lib")
set(DOXYFILE_EXTRA_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/include")
include(UseDoxygen OPTIONAL)

set(LIBDIR "lib${LIB_SUFFIX}")

set(BUILD_SHARED_LIBS TRUE CACHE BOOL "Build shared libraries")

add_subdirectory(src)
