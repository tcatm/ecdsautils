add_definitions(-D_GNU_SOURCE)
add_definitions(-DECDSAUTIL_VERSION="${ECDSAUTIL_VERSION}")


list(APPEND CMAKE_REQUIRED_DEFINITIONS '-D_GNU_SOURCE')

include(CheckPrototypeDefinition)
check_prototype_definition(qsort_r
 "void qsort_r(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *, void *), void *arg)"
 ""
 "stdlib.h"
 LINUX_QSORT_R)

if(LINUX_QSORT_R)
  add_definitions(-DLINUX_QSORT_R)
endif(LINUX_QSORT_R)

check_prototype_definition(qsort_r
 "void qsort_r(void *base, size_t nel, size_t width, void *thunk, int (*compar)(void *, const void *, const void *))"
 ""
 "stdlib.h"
 BSD_QSORT_R)

if(BSD_QSORT_R)
  add_definitions(-DBSD_QSORT_R)
endif(BSD_QSORT_R)


add_executable(ecdsautil ecdsautil.c keygen.c sign.c verify.c hexutil.c random.c version.c sha256_file.c array.c)

set_target_properties(ecdsautil PROPERTIES COMPILE_FLAGS "-std=c99 -Wall ${LIBUECC_CFLAGS_OTHER}" LINK_FLAGS "${LIBUECC_LDFLAGS_OTHER}")
target_link_libraries(ecdsautil libecdsautil ${LIBUECC_LIBRARIES})

install(TARGETS ecdsautil RUNTIME DESTINATION bin)

if(CMAKE_HOST_UNIX)
  install(CODE "
    EXECUTE_PROCESS(
      COMMAND ln -sf ecdsautil ecdsakeygen
      COMMAND ln -sf ecdsautil ecdsasign
      COMMAND ln -sf ecdsautil ecdsaverify
      WORKING_DIRECTORY ${CMAKE_INSTALL_PREFIX}/bin
    )
  ")
endif(CMAKE_HOST_UNIX)
