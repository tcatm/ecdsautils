add_definitions(-DECDSAUTIL_VERSION="${ECDSAUTIL_VERSION}")


add_executable(ecdsautil ecdsautil.c keygen.c sign.c verify.c hexutil.c random.c version.c sha256_file.c set.c)

set_target_properties(ecdsautil PROPERTIES COMPILE_FLAGS "-std=c99 -Wall ${LIBUECC_CFLAGS_OTHER}" LINK_FLAGS "${LIBUECC_LDFLAGS_OTHER}")
target_link_libraries(ecdsautil libecdsautil ${LIBUECC_LIBRARIES})

install(TARGETS ecdsautil RUNTIME DESTINATION bin)

if(CMAKE_HOST_UNIX)
  install(CODE "
    EXECUTE_PROCESS(
      COMMAND ln -sf ecdsautil ecdsakeygen
      COMMAND ln -sf ecdsautil ecdsasign
      COMMAND ln -sf ecdsautil ecdsaverify
      WORKING_DIRECTORY \$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin
    )
  ")
endif(CMAKE_HOST_UNIX)
