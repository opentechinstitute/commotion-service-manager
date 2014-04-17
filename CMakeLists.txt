cmake_minimum_required(VERSION 2.6)

set(PROJECT_NAME_STR commotion-service-manager)
PROJECT(${PROJECT_NAME_STR})
SET(NO_OPTIMIZE ON CACHE BOOL "Disable optimization flags.")
SET(DEBUG ON CACHE BOOL "Turn on debugging.")
SET(OPENWRT OFF CACHE BOOL "Disable subsystems that are unnecessary for OpenWRT platform.")
SET(USE_UCI OFF CACHE BOOL "Disable UCI integration.")
SET(CMAKE_VERBOSE_MAKEFILE OFF)

SET(CSM_DUMPFILE \"/tmp/local-services.out\") # Name of file to output list of services when daemon receives USR1 signal
SET(CSM_PIDFILE \"/var/run/commotion/commotion-service-manager.pid\")
SET(COMMOTION_MANAGESOCK \"/var/run/commotiond.sock\")
SET(CSM_MANAGESOCK \"/var/run/commotion-service-manager.sock\")

CONFIGURE_FILE( "${CMAKE_SOURCE_DIR}/config.h.in" "${PROJECT_SOURCE_DIR}/config.h" )

ADD_DEFINITIONS(-Os -Wall --std=gnu99 -fms-extensions -Wmissing-declarations -D_GNU_SOURCE -DUSESYSLOG -DCLIENT -DNDEBUG -DHAVE_STDINT_H)

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

SET(DAEMONSRC defs.h debug.h browse.h browse.c publish.h publish.c daemon.c service.h service.c util.h util.c extern/base32.h extern/base32.c)
SET(LIBSRC defs.h debug.h commotion-service-manager.h commotion-service-manager.c)
# SET(CLIENTSRC client.c ${LIBSRC})

ADD_EXECUTABLE(daemon ${DAEMONSRC})
ADD_LIBRARY(library SHARED ${LIBSRC})
# ADD_EXECUTABLE(client ${CLIENTSRC})

TARGET_LINK_LIBRARIES(daemon commotion commotion_serval-sas avahi-core avahi-common m)
TARGET_LINK_LIBRARIES(library commotion)
# TARGET_LINK_LIBRARIES(client commotion-service-manager)

IF(OPENWRT OR LUCI)
  ADD_DEFINITIONS(-DUSE_UCI)
  SET(DAEMONSRC ${DAEMONSRC} uci-utils.h uci-utils.c)
  TARGET_LINK_LIBRARIES(daemon uci)
ENDIF()

IF(OPENWRT)
  ADD_DEFINITIONS(-DOPENWRT)
  REMOVE_DEFINITIONS(-DCLIENT)
ELSE()
  TARGET_LINK_LIBRARIES(daemon avahi-client)
  IF(LUCI)
    ADD_DEFINITIONS(-DUCIPATH="\"/opt/luci-commotion/etc/config\"")
  ENDIF()
ENDIF()

SET_TARGET_PROPERTIES(daemon PROPERTIES OUTPUT_NAME commotion-service-manager)
# SET_TARGET_PROPERTIES(client PROPERTIES OUTPUT_NAME csm-client)
SET_TARGET_PROPERTIES(library PROPERTIES OUTPUT_NAME commotion-service-manager)

INSTALL(TARGETS library DESTINATION lib)
INSTALL(FILES commotion-service-manager.h DESTINATION include)
INSTALL(TARGETS daemon RUNTIME DESTINATION sbin)
# INSTALL(TARGETS client RUNTIME DESTINATION bin)
