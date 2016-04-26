set(ECDSAUTIL_ABI 0) # Increment for ABI-breaking changes

include(TestBigEndian)
test_big_endian(BIGENDIAN)
if(BIGENDIAN)
  add_definitions(-DWORDS_BIGENDIAN)
endif(BIGENDIAN)

add_library(libecdsautil
  ecdsa.c
  sha256.c
)
set_target_properties(libecdsautil PROPERTIES
  OUTPUT_NAME ecdsautil
  SOVERSION ${ECDSAUTIL_ABI}
  COMPILE_FLAGS "-Wall -std=c99 ${LIBUECC_CFLAGS_OTHER}"
  LINK_FLAGS "${LIBUECC_LDFLAGS_OTHER}"
)
target_link_libraries(libecdsautil ${LIBUECC_LIBRARIES})

install(TARGETS libecdsautil
  ARCHIVE DESTINATION ${LIBDIR}
  LIBRARY DESTINATION ${LIBDIR}
  RUNTIME DESTINATION bin
)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ecdsautil.pc.in ${CMAKE_CURRENT_BINARY_DIR}/ecdsautil.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ecdsautil.pc DESTINATION "${LIBDIR}/pkgconfig")

file(GLOB include_files "${ECDSAUTIL_SOURCE_DIR}/include/ecdsautil/*.h")
install(FILES ${include_files} DESTINATION "include/ecdsautil-${ECDSAUTIL_VERSION}/ecdsautil")
