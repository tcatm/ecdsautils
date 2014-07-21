INCLUDE(TestBigEndian)
TEST_BIG_ENDIAN(BIGENDIAN)
IF(${BIGENDIAN})
  ADD_DEFINITIONS(-DWORDS_BIGENDIAN)
ENDIF(${BIGENDIAN})

include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${ECDSAUTIL_BINARY_DIR}
  ${CMAKE_CURRENT_BINARY_DIR} ${UECC_INCLUDE_DIRS})
link_directories(${UECC_LIBRARY_DIRS})

add_executable(ecdsakeygen keygen.c hexutil.c random.c ecdsa.c version.c)
add_executable(ecdsasign sign.c hexutil.c random.c ecdsa.c hmac_sha256.c sha256_file.c sha256sum.c)
add_executable(ecdsaverify verify.c hexutil.c random.c ecdsa.c sha256_file.c sha256sum.c array.c)

set_target_properties(ecdsakeygen PROPERTIES COMPILE_FLAGS "-std=c99 -Wall" ${UECC_CFLAGS_OTHER} LINK_FLAGS "" ${UECC_LDFLAGS_OTHER})
target_link_libraries(ecdsakeygen ${UECC_LIBRARIES})

set_target_properties(ecdsasign PROPERTIES COMPILE_FLAGS "-std=c99 -Wall" ${UECC_CFLAGS_OTHER} LINK_FLAGS "" ${UECC_LDFLAGS_OTHER})
target_link_libraries(ecdsasign ${UECC_LIBRARIES})

set_target_properties(ecdsaverify PROPERTIES COMPILE_FLAGS "-std=c99 -Wall" ${UECC_CFLAGS_OTHER} LINK_FLAGS "" ${UECC_LDFLAGS_OTHER})
target_link_libraries(ecdsaverify ${UECC_LIBRARIES})

install(TARGETS ecdsakeygen ecdsasign ecdsaverify RUNTIME DESTINATION bin)
