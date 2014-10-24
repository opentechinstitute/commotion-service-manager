cmake_minimum_required(VERSION 2.6)

set(PROJECT_NAME_STR commotion-service-manager)
PROJECT(${PROJECT_NAME_STR})
SET(NO_OPTIMIZE OFF CACHE BOOL "Turn on/off optimization flags.")
SET(DEBUG OFF CACHE BOOL "Turn on/off debugging.")
SET(OPENWRT OFF CACHE BOOL "Enable/disable subsystems that are unnecessary for OpenWRT platform.")
SET(USE_UCI ON CACHE BOOL "Enable/disable UCI integration.")
SET(CLIENT OFF CACHE BOOL "Run full mDNS stack, or act as client to running Avahi daemon.")
SET(CMAKE_VERBOSE_MAKEFILE OFF)

SET(CSM_PIDFILE \"/var/run/commotion/commotion-service-manager.pid\")
SET(CSM_SCHEMA_DIR \"/etc/commotion/csm/schemas.d/\")
SET(COMMOTION_MANAGESOCK \"/var/run/commotiond.sock\")
SET(CSM_MANAGESOCK \"/var/run/commotion-service-manager.sock\")
SET(UCIPATH \"/var/run/uci\")

CONFIGURE_FILE( "${CMAKE_SOURCE_DIR}/config.h.in" "${PROJECT_SOURCE_DIR}/config.h" )

ADD_DEFINITIONS(-Os -Wall --std=gnu99 -Wmissing-declarations -DNDEBUG -DHAVE_STDINT_H)

IF(DEBUG)
  ADD_DEFINITIONS(-g3)
  REMOVE_DEFINITIONS(-DNDEBUG)
  IF(NO_OPTIMIZE)
    ADD_DEFINITIONS(-O0)
  ENDIF()
ENDIF()

SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

SET(DAEMONSRC daemon.c)
SET(LIBSRC defs.h browse.h browse.c schema.h schema.c cmd.h cmd.c service.h service.c service_list.h service_list.c commotion-service-manager.h commotion-service-manager.c publish.h publish.c service.h service.c util.h util.c extern/base32.h extern/base32.c extern/jsmn.h extern/jsmn.c)
# SET(CLIENTSRC client.c ${LIBSRC})

SET(DAEMONLIBS commotion avahi-core avahi-common)
SET(LIBLIBS commotion commotion_serval-sas m)

IF(OPENWRT OR USE_UCI)
  ADD_DEFINITIONS(-DUSE_UCI)
  SET(DAEMONSRC ${DAEMONSRC} uci-utils.h uci-utils.c)
  SET(DAEMONLIBS ${DAEMONLIBS} uci)
ENDIF()

IF(CLIENT)
  ADD_DEFINITIONS(-DCLIENT)
  SET(DAEMONLIBS ${DAEMONLIBS} avahi-client)
ENDIF()

IF(OPENWRT)
  ADD_DEFINITIONS(-DOPENWRT)
  REMOVE_DEFINITIONS(-DCLIENT)
  SET(UCIPATH \"/etc/config\")
ENDIF()

ADD_EXECUTABLE(daemon ${DAEMONSRC})
ADD_LIBRARY(library SHARED ${LIBSRC})
# ADD_EXECUTABLE(client ${CLIENTSRC})

TARGET_LINK_LIBRARIES(daemon ${DAEMONLIBS} library)
TARGET_LINK_LIBRARIES(library ${LIBLIBS})
# TARGET_LINK_LIBRARIES(client commotion-service-manager)

SET_TARGET_PROPERTIES(daemon PROPERTIES OUTPUT_NAME commotion-service-manager)
# SET_TARGET_PROPERTIES(client PROPERTIES OUTPUT_NAME csm-client)
SET_TARGET_PROPERTIES(library PROPERTIES OUTPUT_NAME commotion-service-manager)

INSTALL(TARGETS library DESTINATION lib)
INSTALL(FILES commotion-service-manager.h DESTINATION include)
INSTALL(TARGETS daemon RUNTIME DESTINATION sbin)
# INSTALL(TARGETS client RUNTIME DESTINATION bin)
