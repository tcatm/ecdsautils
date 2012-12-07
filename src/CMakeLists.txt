include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${ECDSAUTIL_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR} ${UECC_INCLUDE_DIR})

add_executable(ecdsakeygen keygen.c)

target_link_libraries(ecdsakeygen ${UECC_LIBRARY})

install(TARGETS ecdsakeygen RUNTIME DESTINATION sbin)
