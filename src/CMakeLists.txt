SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

SET(DAEMONSRC daemon.c defs.h browse.h browse.c schema.h schema.c cmd.h cmd.c service.h service.c service_list.h service_list.c publish.h publish.c service.h service.c util.h util.c extern/base32.h extern/base32.c extern/jsmn.h extern/jsmn.c)
SET(LIBSRC commotion-service-manager.h commotion-service-manager.c)

SET(DAEMONLIBS commotion commotion_serval-sas m avahi-common)
SET(LIBLIBS commotion)

IF(OPENWRT OR USE_UCI)
  SET(DAEMONSRC ${DAEMONSRC} uci-utils.h uci-utils.c)
  SET(DAEMONLIBS ${DAEMONLIBS} uci)
ENDIF()

IF(CLIENT)
  SET(DAEMONLIBS ${DAEMONLIBS} avahi-client)
ELSE()
  SET(DAEMONLIBS ${DAEMONLIBS} avahi-core)
ENDIF()

ADD_EXECUTABLE(daemon ${DAEMONSRC})
ADD_LIBRARY(library SHARED ${LIBSRC})

TARGET_LINK_LIBRARIES(daemon ${DAEMONLIBS} library)
TARGET_LINK_LIBRARIES(library ${LIBLIBS})

SET_TARGET_PROPERTIES(daemon PROPERTIES OUTPUT_NAME commotion-service-manager)
SET_TARGET_PROPERTIES(library PROPERTIES OUTPUT_NAME commotion-service-manager)

INSTALL(TARGETS library DESTINATION lib)
INSTALL(FILES commotion-service-manager.h DESTINATION include)
INSTALL(TARGETS daemon RUNTIME DESTINATION sbin)