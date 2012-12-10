INCLUDE(TestBigEndian)
TEST_BIG_ENDIAN(BIGENDIAN)
IF(${BIGENDIAN})
  ADD_DEFINITIONS(-DWORDS_BIGENDIAN)
ENDIF(${BIGENDIAN})

include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${ECDSAUTIL_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR} ${UECC_INCLUDE_DIR})

add_executable(ecdsakeygen keygen.c hexutil.c random.c ecdsa.c)
add_executable(ecdsasign sign.c hexutil.c random.c ecdsa.c sha256_file.c sha256sum.c)
add_executable(ecdsaverify verify.c hexutil.c random.c sha256_file.c sha256sum.c)

target_link_libraries(ecdsakeygen ${UECC_LIBRARY})
target_link_libraries(ecdsasign ${UECC_LIBRARY})
target_link_libraries(ecdsaverify ${UECC_LIBRARY})

install(TARGETS ecdsakeygen ecdsasign ecdsaverify RUNTIME DESTINATION bin)
