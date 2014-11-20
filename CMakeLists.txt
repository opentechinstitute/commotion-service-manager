cmake_minimum_required(VERSION 2.6)

set(PROJECT_NAME_STR commotion-service-manager)
PROJECT(${PROJECT_NAME_STR})
SET(NO_OPTIMIZE OFF CACHE BOOL "Turn on/off optimization flags.")
SET(DEBUG OFF CACHE BOOL "Turn on/off debugging.")
SET(OPENWRT OFF CACHE BOOL "Enable/disable subsystems that are unnecessary for OpenWRT platform.")
SET(USE_UCI ON CACHE BOOL "Enable/disable UCI integration.")
SET(CLIENT OFF CACHE BOOL "Run full mDNS stack, or act as client to running Avahi daemon.")
SET(LUA OFF CACHE BOOL "Compile Lua client library.")
SET(CMAKE_VERBOSE_MAKEFILE OFF)

SET(CSM_PIDFILE \"/var/run/commotion/commotion-service-manager.pid\")
SET(CSM_SCHEMA_DIR \"/etc/commotion/csm/schemas.d/\")
SET(COMMOTION_MANAGESOCK \"/var/run/commotiond.sock\")
SET(CSM_MANAGESOCK \"/var/run/commotion-service-manager.sock\")
SET(UCIPATH \"/var/run/uci\")

ADD_DEFINITIONS(-Os -Wall --std=gnu99 -Wmissing-declarations -DNDEBUG -DHAVE_STDINT_H -DUSESYSLOG)

IF(DEBUG)
  ADD_DEFINITIONS(-g3)
  REMOVE_DEFINITIONS(-DNDEBUG -DUSESYSLOG)
  IF(NO_OPTIMIZE)
    ADD_DEFINITIONS(-O0)
  ENDIF()
ENDIF()

IF(OPENWRT)
  ADD_DEFINITIONS(-DOPENWRT)
  REMOVE_DEFINITIONS(-DCLIENT)
  SET(UCIPATH \"/etc/config\")
  SET(LUA ON)
  SET(USE_UCI ON)
ENDIF()

IF(USE_UCI)
  ADD_DEFINITIONS(-DUSE_UCI)
ENDIF()

IF(CLIENT)
  ADD_DEFINITIONS(-DCLIENT)
ENDIF()

ADD_SUBDIRECTORY(src)

IF(LUA)
  ADD_SUBDIRECTORY(lua)
ENDIF()

CONFIGURE_FILE( "${CMAKE_SOURCE_DIR}/src/config.h.in" "${PROJECT_SOURCE_DIR}/src/config.h" )

INSTALL(DIRECTORY files/schemas.d DESTINATION /etc/commotion/csm/schemas.d/)