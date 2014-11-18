/**
 *       @file  csm_lua.c
 *      @brief  Lua bindings for Commotion Service Manager
 *
 *     @author  Dan Staples (dismantl), danstaples@opentechinstitute.org
 *
 * This file is part of Commotion, Copyright (c) 2013, Josh King 
 * 
 * Commotion is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published 
 * by the Free Software Foundation, either version 3 of the License, 
 * or (at your option) any later version.
 * 
 * Commotion is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Commotion.  If not, see <http://www.gnu.org/licenses/>.
 *
 * =====================================================================================
 */

#define LUA_LIB
#include <assert.h>
#include <string.h>
#include <lua.h>
#include <lauxlib.h>
#include <malloc.h>

#include <commotion/debug.h>

#include "../src/commotion-service-manager.h"

#define CSM_LIBNAME "commotion-service-manager"
#define CSM_CONFIG_KEY "csm_config"

#define LUA_ERROR(L, M, ...) luaL_error(L, "(%s:%d) " M, __FILE__, __LINE__, ##__VA_ARGS__)
#define LUA_CHECK(A, M, ...) do { if(!(A)) { LUA_ERROR(L, M, ##__VA_ARGS__); } } while (0)
#define LUA_CHECK_MEM(A) LUA_CHECK((A), "Out of memory.")
#define LUA_CHECK_N_ARGS(L,N) LUA_CHECK(lua_gettop(L) == N, "Invalid number of arguments")

/*
 * CONFIG functions
 */

static void *
_csm_fetch_config_from_registry(lua_State *L)
{
  /* Fetch global config from registry */
  lua_pushstring(L,CSM_CONFIG_KEY); 
  lua_gettable(L, LUA_REGISTRYINDEX);
  void **config = (void**)luaL_checkudata(L, -1, "csm.config");
  LUA_CHECK(config, "Cannot fetch CSM config");
  lua_pop(L,1);
  assert(*config);
  return *config;
}

// CSMConfig *csm_config_create(void);
static int
_l_csm_config_create(lua_State *L)
{
  LUA_CHECK_N_ARGS(L,0);
  
  lua_pushstring(L, CSM_CONFIG_KEY);
  
  void **config = lua_newuserdata(L,sizeof(void*));
  LUA_CHECK_MEM(config);
  luaL_getmetatable(L, "csm.config");
  lua_setmetatable(L, -2);
  
  *config = csm_config_create();
  LUA_CHECK_MEM(*config);
  
  /* store generated CSM config in the registry */
  lua_settable(L, LUA_REGISTRYINDEX);
  return 0;
}

// int csm_config_set_mgmt_sock(CSMConfig *config, const char *sock)
static int
_l_csm_config_set_mgmt_sock(lua_State *L)
{
  LUA_CHECK_N_ARGS(L,1);
  void *config = _csm_fetch_config_from_registry(L);
  
  LUA_CHECK(csm_config_set_mgmt_sock(
    config,
    luaL_checkstring(L,1)) == CSM_OK,
    "Failed to set CSM management socket");
  return 0;
}

// void csm_config_free(CSMConfig *config);
static int
_l_csm_config_free(lua_State *L)
{
  LUA_CHECK_N_ARGS(L,0);
  void *config = _csm_fetch_config_from_registry(L);
  csm_config_free(config);
  return 0;
}

/*
 * SCHEMA functions
 */

static void *
_csm_check_schema(lua_State *L, int index)
{
  void **schema = (void**)luaL_checkudata(L, index, "csm.schema");
  luaL_argcheck(L, schema != NULL, index, "`schema' expected");
  assert(*schema);
  return *schema;
}

/**
 * @return schema object, # fields
 */
// int csm_schema_fetch(CSMSchema **schema, CSMConfig *config);
static int
_l_csm_schema_fetch(lua_State *L)
{
  LUA_CHECK_N_ARGS(L,0);
  void *config = _csm_fetch_config_from_registry(L);
  
  // create a full userdata object with points to a CSM-allocated schema
  void **schema = lua_newuserdata(L, sizeof(void*));
  LUA_CHECK_MEM(schema);
  luaL_getmetatable(L, "csm.schema");
  lua_setmetatable(L, -2);
  
  int nfields = csm_schema_fetch(schema, config);
  LUA_CHECK(nfields > 0, "Failed to fetch schema");
  
  lua_getfenv( L, -1 ); // put fenv on stack, so we can set table entries
  
  /** Get major version */
  int major = csm_schema_get_major_version(config);
  LUA_CHECK(major != CSM_ERROR, "Failed to fetch major schema version");
  lua_pushstring(L,"major");
  lua_pushnumber(L, major);
  lua_rawset( L, -3 );
  
  /** Get minor version */
  double minor = csm_schema_get_minor_version(config);
  LUA_CHECK(minor != CSM_ERROR, "Failed to fetch major schema version");
  lua_pushstring(L,"minor");
  lua_pushnumber(L, minor);
  lua_rawset( L, -3 );
  
  lua_pushstring(L,"__len");
  lua_pushnumber(L, nfields);
  lua_rawset( L, -3 );
  
  lua_pop( L, 1 ); // remove fenv from stack
  
  /** Return number of schema fields */
  lua_pushnumber(L, nfields);
  return 2;
}

// int csm_schema_free(CSMSchema *schema);
static int
_l_csm_schema_free(lua_State *L)
{
  LUA_CHECK_N_ARGS(L,1);
  void *schema = _csm_check_schema(L,1);
  LUA_CHECK(csm_schema_free(schema) == CSM_OK, "Failed to free schema");
  return 0;
}

/**
 * SCHEMA FIELD functions
 */

static void *
_csm_check_schemafield(lua_State *L, int index)
{
  void **schema_field = (void**)luaL_checkudata(L, index, "csm.schemafield");
  luaL_argcheck(L, schema_field != NULL, index, "`schemafield' expected");
  assert(*schema_field);
  return *schema_field;
}

static void
_csm_schema_field_get_properties(lua_State *L)
{
  void *field = _csm_check_schemafield(L,-1); // expects schemafield userdata to be on top of stack
  
  lua_getfenv( L, -1 ); // put fenv on stack, so we can set table entries
  
  char *name = csm_schema_field_get_name(field);
  LUA_CHECK(name, "Failed to fetch schema field name");
  lua_pushstring(L,"name");
  lua_pushstring(L,name);
  lua_rawset( L, -3 );
  
  bool required;
  LUA_CHECK(csm_schema_field_get_required(field, &required) == CSM_OK,
	    "Failed to fetch schema field required");
  lua_pushstring(L,"required");
  lua_pushboolean(L,required);
  lua_rawset( L, -3 );
  
  bool generated;
  LUA_CHECK(csm_schema_field_get_generated(field, &generated) == CSM_OK,
	    "Failed to fetch schema field generated");
  lua_pushstring(L,"generated");
  lua_pushboolean(L,generated);
  lua_rawset( L, -3 );
  
  // TODO return string instead of field_type enum
  int field_type = csm_schema_field_get_type(field);
  LUA_CHECK(field_type != CSM_ERROR,
	    "Failed to fetch schema field type");
  lua_pushstring(L,"field_type");
  lua_pushnumber(L,field_type);
  lua_rawset( L, -3 );
  
  switch (field_type) {
    case CSM_FIELD_LIST: ;
      int subtype = csm_schema_field_get_list_subtype(field);
      LUA_CHECK(subtype != CSM_ERROR,
		"Failed to fetch schema list field subtype");
      lua_pushstring(L,"subtype");
      lua_pushnumber(L,subtype);
      lua_rawset( L, -3 );
      break;
    case CSM_FIELD_INT: ;
      long limit;
      int ret = csm_schema_field_get_min(field, &limit);
      LUA_CHECK(ret != CSM_ERROR,
		"Failed to fetch schema field minimum");
      lua_pushstring(L,"min");
      if (ret == CSM_OK)
	lua_pushnumber(L,limit);
      else
	lua_pushnil(L);
      lua_rawset( L, -3 );
      
      ret = csm_schema_field_get_max(field, &limit);
      LUA_CHECK(ret != CSM_ERROR,
		"Failed to fetch schema field maximum");
      lua_pushstring(L,"max");
      if (ret == CSM_OK)
	lua_pushnumber(L,limit);
      else
	lua_pushnil(L);
      lua_rawset( L, -3 );
      break;
    case CSM_FIELD_STRING:
    case CSM_FIELD_HEX: ;
      int length = csm_schema_field_get_string_length(field);
      LUA_CHECK(length != CSM_ERROR,
		"Failed to fetch schema string field length");
      lua_pushstring(L,"length");
      if (length > 0)
	lua_pushnumber(L,length);
      else
	lua_pushnil(L);
      lua_rawset( L, -3 );
      break;
  }
  
  lua_pop( L, 1 ); // remove fenv from stack, leaving stack as it was passed to us
}

// CSMSchemaField *csm_schema_get_next_field(CSMSchema *schema, CSMSchemaField *current, char **name);
static int
_l_csm_schema_get_next_field(lua_State *L)
{
  LUA_CHECK_N_ARGS(L,2);
  void *schema = _csm_check_schema(L,1);
  void *current = NULL;
  if (!lua_isnil(L,2))
    current = _csm_check_schemafield(L,2);
  void *field = csm_schema_get_next_field(schema, current, NULL);
  if (!field) return 0;
  
  void **schema_field = lua_newuserdata(L, sizeof(void*));
  LUA_CHECK_MEM(schema_field);
  luaL_getmetatable(L, "csm.schemafield");
  lua_setmetatable(L, -2);
  
  *schema_field = field;
  
  _csm_schema_field_get_properties(L);
  
  return 1;
}

// CSMSchemaField *csm_schema_get_field_by_index(CSMSchema *schema, int index, char **name);
static int
_l_csm_schema_get_field_by_index(lua_State *L)
{
  LUA_CHECK_N_ARGS(L,2);
  void *schema = _csm_check_schema(L,1);
  char *name = NULL;
  void *field = csm_schema_get_field_by_index(schema, luaL_checkint(L,2), &name);
  LUA_CHECK(field, "Failed to get schema field at index %d", luaL_checkint(L,2));
  
  void **schema_field = lua_newuserdata(L, sizeof(void*));
  LUA_CHECK_MEM(schema_field);
  luaL_getmetatable(L, "csm.schemafield");
  lua_setmetatable(L, -2);
  
  *schema_field = field;
  
  _csm_schema_field_get_properties(L);
  
  return 1;
}

// CSMSchemaField *csm_schema_get_field_by_name(CSMSchema *schema, char *name);
static int
_l_csm_schema_get_field_by_name(lua_State *L)
{
  LUA_CHECK_N_ARGS(L,2);
  void *schema = _csm_check_schema(L,1);
  void *field = csm_schema_get_field_by_name(schema, (char*)luaL_checkstring(L,2));
  LUA_CHECK(field, "Failed to get schema field of name %s", luaL_checkstring(L,2));
  
  void **schema_field = lua_newuserdata(L, sizeof(void*));
  LUA_CHECK_MEM(schema_field);
  luaL_getmetatable(L, "csm.schemafield");
  lua_setmetatable(L, -2);
  
  *schema_field = field;
  
  _csm_schema_field_get_properties(L);
  
  return 1;
}

/**
 * SERVICE LIST functions
 */

static void *
_csm_check_servicelist(lua_State *L, int index)
{
  void **list = (void**)luaL_checkudata(L, index, "csm.servicelist");
  luaL_argcheck(L, list != NULL, index, "`servicelist' expected");
  assert(*list);
  return *list;
}

static int _l_csm_services_get_next_service(lua_State *L);
static void *_csm_check_service(lua_State *L, int index);

// int csm_services_fetch(CSMServiceList **service_list, CSMConfig *config);
static int
_l_csm_services_fetch(lua_State *L)
{
  LUA_CHECK_N_ARGS(L,0);
  void *config = _csm_fetch_config_from_registry(L);
  
  // create a full userdata object with points to a CSM-allocated service list
  void **list = lua_newuserdata(L, sizeof(void*));
  LUA_CHECK_MEM(list);
  luaL_getmetatable(L, "csm.servicelist");
  lua_setmetatable(L, -2);
  
  int len = csm_services_fetch(list, config);
  LUA_CHECK(len >= 0, "Failed to fetch service list");
  
  lua_getfenv( L, -1 ); // put fenv on stack, so we can set table entries
  
  lua_pushstring(L,"__len");
  lua_pushnumber(L,len);
  lua_rawset( L, -3 );
  
  lua_pop(L,1); // remove service list env from stack
  
  lua_pushnumber(L, len);
  return 2;
}

static int _l_csm_services_get_by_key(lua_State *L);

static int _l_csm_servicelist_index( lua_State* L )
{
  /* servicelist, service key */
  void *l = _csm_check_servicelist(L,1);
  
  /* first check list of services */
  if (lua_isstring(L,2) && csm_services_get_by_key(l, (char*)luaL_checkstring(L,2)))
    return _l_csm_services_get_by_key(L);
  
  /* second check the environment */ 
  lua_getfenv( L, -2 );
  lua_pushvalue( L, -2 );
  lua_rawget( L, -2 );
  if( lua_isnoneornil( L, -1 ) == 0 )
  {
    return 1;
  }
  
  lua_pop( L, 2 );
  
  /* third check the metatable */
  lua_getmetatable( L, -2 );
  lua_pushvalue( L, -2 );
  lua_rawget( L, -2 );
  
  /* nil or otherwise, we return here */
  return 1;
}

// int csm_services_free(CSMServiceList *service_list);
static int
_l_csm_services_free(lua_State *L)
{
  LUA_CHECK_N_ARGS(L,1);
  void *list = _csm_check_servicelist(L,1);
  LUA_CHECK(csm_services_free(list) == CSM_OK, "Failed to free service list");
  return 0;
}

/**
 * SERVICE functions
 */

static void *
_csm_check_service(lua_State *L, int index)
{
  void **s = (void**)luaL_checkudata(L, index, "csm.service");
  luaL_argcheck(L, s != NULL, index, "`service' expected");
  assert(*s);
  return *s;
}

static void
_csm_service_get_properties(lua_State *L)
{
  void *s = _csm_check_service(L,-1);
  
  lua_getfenv( L, -1 ); // put fenv on stack, so we can set table entries
  
  lua_pushstring(L,"islocal");
  lua_pushboolean(L, csm_service_is_local(s));
  lua_rawset( L, -3 );
  
  int len = csm_service_fields_get_length(s);
  LUA_CHECK(len != CSM_ERROR, "Failed to get number of service fields");
  lua_pushstring(L,"__len");
  lua_pushnumber(L,len);
  lua_rawset( L, -3 );
  
  lua_pop( L, 1 ); // remove fenv from stack, leaving stack as it was passed to us
}

// CSMService *csm_services_get_next_service(CSMServiceList *service_list, CSMService *current);
static int
_l_csm_services_get_next_service(lua_State *L)
{
//   LUA_CHECK_N_ARGS(L,2);
  LUA_CHECK(lua_gettop(L) >= 2, "Invalid number of arguments");
  void *list = _csm_check_servicelist(L,-2);
  void *current = NULL;
  if (!lua_isnil(L,-1))
    current = _csm_check_service(L,-1);
  void *service = csm_services_get_next_service(list, current);
  if (!service) return 0;
  
  void **s = lua_newuserdata(L, sizeof(void*));
  LUA_CHECK_MEM(s);
  luaL_getmetatable(L, "csm.service");
  lua_setmetatable(L, -2);
  
  *s = service;
  
  _csm_service_get_properties(L);
  
  return 1;
}

// CSMService *csm_services_get_by_index(CSMServiceList *service_list, int index);
static int
_l_csm_services_get_by_index(lua_State *L)
{
  LUA_CHECK_N_ARGS(L,2);
  void *list = _csm_check_servicelist(L,1);
  void *service = csm_services_get_by_index(list, luaL_checkint(L,2));
  LUA_CHECK(service, "Failed to get service at index %d", luaL_checkint(L,2));
  
  void **s = lua_newuserdata(L, sizeof(void*));
  LUA_CHECK_MEM(s);
  luaL_getmetatable(L, "csm.service");
  lua_setmetatable(L, -2);
  
  *s = service;
  
  _csm_service_get_properties(L);
  
  return 1;
}

// CSMService *csm_services_get_by_key(CSMServiceList *service_list, char *key);
static int
_l_csm_services_get_by_key(lua_State *L)
{
  LUA_CHECK_N_ARGS(L,2);
  void *schema = _csm_check_servicelist(L,1);
  void *service = csm_services_get_by_key(schema, (char*)luaL_checkstring(L,2));
  LUA_CHECK(service, "Failed to get service of key %s", luaL_checkstring(L,2));
  
  void **s = lua_newuserdata(L, sizeof(void*));
  LUA_CHECK_MEM(s);
  luaL_getmetatable(L, "csm.service");
  lua_setmetatable(L, -2);
  
  *s = service;
  
  _csm_service_get_properties(L);
  
  return 1;
}

static int _l_csm_service_get_field_by_name(lua_State *L);

static int _l_csm_service_index( lua_State* L )
{
  /* service, property */
  void *s = _csm_check_service(L,1);
  
  /* first check service fields */
  if (lua_isstring(L,2) && csm_service_get_field_by_name(s, luaL_checkstring(L,2)))
    return _l_csm_service_get_field_by_name(L);
  
  /* second check the environment */ 
  lua_getfenv( L, -2 );
  lua_pushvalue( L, -2 );
  lua_rawget( L, -2 );
  if( lua_isnoneornil( L, -1 ) == 0 )
  {
    return 1;
  }
  
  lua_pop( L, 2 );
  
  /* third check the metatable */
  lua_getmetatable( L, -2 );
  lua_pushvalue( L, -2 );
  lua_rawget( L, -2 );
  
  /* nil or otherwise, we return here */
  return 1;
}

static int
_l_csm_service_newindex(lua_State *L)
{
  /* object, key, val */
  LUA_CHECK_N_ARGS(L,3);
  void *s = _csm_check_service(L,1);
  char *key = (char*)luaL_checkstring(L,2);
  if (lua_isnil(L,3)) {
    LUA_CHECK(csm_service_remove_field(s,key) == CSM_OK,
	      "Failed to remove service field %s", key);
    DEBUG("Removing service field %s",key);
  } else if (lua_type(L,3) == LUA_TNUMBER) { // because lua_isnumber will return true for strings such as "2.0", not what we want
    LUA_CHECK(csm_service_set_int(s,key,luaL_checklong(L,3)) == CSM_OK,
	      "Failed to set integer service field %s", key);
    DEBUG("Setting integer service field %s",key);
  } else if (lua_isstring(L,3)) {
    LUA_CHECK(csm_service_set_string(s,key,luaL_checkstring(L,3)) == CSM_OK,
	      "Failed to set string service field %s", key);
    DEBUG("Setting string service field %s",key);
  } else if (lua_istable(L,3)) {
    DEBUG("Setting list service field %s",key);
    LUA_CHECK(csm_service_remove_field(s,key) == CSM_OK,
	      "Failed to remove list service field %s", key);
    lua_pushnil(L);  /* first key */
    int subtype = 0;
    while (lua_next(L, 3) != 0) {
      /* uses 'key' (at index -2) and 'value' (at index -1) */
      luaL_checkint(L,-2); // must be numerically-indexed array
      if (lua_isnumber(L,-1)) {
	LUA_CHECK(subtype == 0 || subtype == CSM_FIELD_INT, "Service field lists must have consistent type");
	subtype = CSM_FIELD_INT;
	LUA_CHECK(csm_service_list_append_int(s,key,luaL_checklong(L,-1)) == CSM_OK,
		  "Failed to append integer to service field %s", key);
      } else if (lua_isstring(L,-1)) {
	LUA_CHECK(subtype == 0 || subtype == CSM_FIELD_STRING, "Service field lists must have consistent type");
	subtype = CSM_FIELD_STRING;
	LUA_CHECK(csm_service_list_append_string(s,key,luaL_checkstring(L,-1)) == CSM_OK,
		  "Failed to append string to service field %s", key);
      } else {
	LUA_ERROR(L,"Invalid list service field");
      }
      /* removes 'value'; keeps 'key' for next iteration */
      lua_pop(L, 1);
    }
  } else {
    LUA_ERROR(L,"Invalid service field");
  }
  return 0;
}

// CSMService *csm_service_create(void);
static int
_l_csm_service_create(lua_State *L)
{
  LUA_CHECK_N_ARGS(L,0);
  void *service = csm_service_create();
  LUA_CHECK_MEM(service);
  
  void **s = lua_newuserdata(L, sizeof(void*));
  LUA_CHECK_MEM(s);
  luaL_getmetatable(L, "csm.service");
  lua_setmetatable(L, -2);
  
  *s = service;
  
  lua_getfenv( L, -1 ); // put fenv on stack, so we can set table entries
  lua_pushstring(L,"islocal");
  lua_pushboolean(L, true);
  lua_rawset( L, -3 );
  lua_pop( L, 1 ); // remove fenv from stack, leaving stack as it was passed to us
  
  return 1;
}

// void csm_service_destroy(CSMService *service);
static int
_l_csm_service_free(lua_State *L)
{
  LUA_CHECK_N_ARGS(L,1);
  csm_service_destroy(_csm_check_service(L,1));
  return 0;
}

// int csm_service_commit(CSMService *service, CSMConfig *config);
static int
_l_csm_service_commit(lua_State *L)
{
  LUA_CHECK_N_ARGS(L,1);
  void *config = _csm_fetch_config_from_registry(L);
  LUA_CHECK(csm_service_commit(_csm_check_service(L,1), config) == CSM_OK,
	    "Failed to commit service");
  return 0;
}

// int csm_service_remove(CSMService *service, CSMConfig *config);
static int
_l_csm_service_remove(lua_State *L)
{
  LUA_CHECK_N_ARGS(L,1);
  void *config = _csm_fetch_config_from_registry(L);
  LUA_CHECK(csm_service_remove(_csm_check_service(L,1), config) == CSM_OK,
	    "Failed to remove service");
  return 0;
}

/**
 * SERVICE FIELD functions
 */

static void *
_csm_check_servicefield(lua_State *L, int index)
{
  void **f = (void**)luaL_checkudata(L, index, "csm.servicefield");
  luaL_argcheck(L, f != NULL, index, "`servicefield' expected");
  assert(*f);
  return *f;
}

static void
_csm_service_field_get_properties(lua_State *L)
{
  void *field = _csm_check_servicefield(L,-1); // expects schemafield userdata to be on top of stack
  
  lua_getfenv( L, -1 ); // put fenv on stack, so we can set table entries
  
  char *name = csm_field_get_name(field);
  LUA_CHECK(name, "Failed to fetch service field name");
  lua_pushstring(L,"name");
  lua_pushstring(L,name);
  lua_rawset( L, -3 );
  
  // TODO return string instead of field_type enum
  int field_type = csm_field_get_type(field);
  LUA_CHECK(field_type != CSM_ERROR,
	    "Failed to fetch service field type");
  lua_pushstring(L,"field_type");
  lua_pushnumber(L,field_type);
  lua_rawset( L, -3 );
  
  switch (field_type) {
    case CSM_FIELD_LIST: ;
      int subtype = csm_field_get_list_subtype(field);
      LUA_CHECK(subtype != CSM_ERROR,
		"Failed to fetch schema list field subtype");
      lua_pushstring(L,"subtype");
      lua_pushnumber(L,subtype);
      lua_rawset( L, -3 );
      int length = csm_field_get_list_length(field);
      LUA_CHECK(length != CSM_ERROR, "Failed to get list service field length");
      lua_pushstring(L,"__len");
      lua_pushnumber(L,length);
      lua_rawset( L, -3 );
      lua_pushstring(L,"value");
      lua_createtable(L,length,0);
      for (; length; length--) {
	switch (subtype) {
	  case CSM_FIELD_INT: ;
	    long val;
	    LUA_CHECK(csm_field_get_list_int(field, length-1, &val) != CSM_ERROR,
		      "Failed to fetch list service field integer value");
	    lua_pushnumber(L,val);
	    lua_rawseti(L,-2,length); // lua arrays are 1-indexed
	    break;
	  case CSM_FIELD_STRING:
	  case CSM_FIELD_HEX: ;
	    char *str = csm_field_get_list_string(field, length-1);
	    LUA_CHECK(str, "Failed to fetch list service field string/hex value");
	    lua_pushstring(L,str);
	    lua_rawseti(L,-2,length); // lua arrays are 1-indexed
	    break;
	}
      }
      lua_rawset( L, -3 );
      break;
    case CSM_FIELD_INT: ;
      long val;
      LUA_CHECK(csm_field_get_int(field, &val) != CSM_ERROR,
		"Failed to fetch integer service field value");
      lua_pushstring(L,"value");
      lua_pushnumber(L,val);
      lua_rawset( L, -3 );
      break;
    case CSM_FIELD_STRING:
    case CSM_FIELD_HEX: ;
      char *str = csm_field_get_string(field);
      LUA_CHECK(str, "Failed to fetch string/hex service field value");
      lua_pushstring(L,"value");
      lua_pushstring(L,str);
      lua_rawset( L, -3 );
      break;
  }
  
  lua_pop( L, 1 ); // remove fenv from stack, leaving stack as it was passed to us
}

// CSMField *csm_service_get_next_field(CSMService *service, CSMField *current, char **name); // set name if not NULL
static int
_l_csm_service_get_next_field(lua_State *L)
{
  LUA_CHECK(lua_gettop(L) >= 2, "Invalid number of arguments");
  void *s = _csm_check_service(L,-2);
  void *current = NULL;
  if (!lua_isnil(L,-1))
    current = _csm_check_servicefield(L,-1);
  char *name = NULL;
  void *field = csm_service_get_next_field(s, current, &name);
  if (!field) return 0;
  
  void **f = lua_newuserdata(L, sizeof(void*));
  LUA_CHECK_MEM(f);
  luaL_getmetatable(L, "csm.servicefield");
  lua_setmetatable(L, -2);
  
  *f = field;
  
  _csm_service_field_get_properties(L);
  
  lua_pushstring(L,name);
  
  return 2;
}

// CSMField *csm_service_get_field_by_name(CSMService *service, const char *name);
static int
_l_csm_service_get_field_by_name(lua_State *L)
{
  LUA_CHECK_N_ARGS(L,2);
  void *s = _csm_check_service(L,1);
  void *field = csm_service_get_field_by_name(s, luaL_checkstring(L,2));
  LUA_CHECK(field, "Failed to get service field of name %s", luaL_checkstring(L,2));
  
  void **f = lua_newuserdata(L, sizeof(void*));
  LUA_CHECK_MEM(f);
  luaL_getmetatable(L, "csm.servicefield");
  lua_setmetatable(L, -2);
  
  *f = field;
  
  _csm_service_field_get_properties(L);
  
  return 1;
}

static int
_l_csm_print_field(lua_State *L)
{
  LUA_CHECK_N_ARGS(L,1);
  _csm_check_servicefield(L,1);
  // get field value from field's env
  lua_getfenv( L, 1 );
  lua_pushstring(L,"value");
  lua_rawget( L, -2 );
  LUA_CHECK( lua_isnoneornil( L, -1 ) == 0, "Failed to fetch service field value");
  return 1;
}

static int
_l_csm_servicefield_newindex(lua_State *L)
{
  /* object, key, val */
  LUA_CHECK_N_ARGS(L,3);
  void *f = _csm_check_servicefield(L,1);
  LUA_CHECK(csm_field_get_type(f) == CSM_FIELD_LIST,
	    "Cannot set properties of non-list field");
  int key = luaL_checkint(L,2);
  int subtype = csm_field_get_list_subtype(f);
  LUA_CHECK(subtype != CSM_ERROR, "Failed to fetch service field list subtype");
  int length = csm_field_get_list_length(f);
  LUA_CHECK(length != CSM_ERROR, "Failed to fetch service field list length");
  LUA_CHECK(key <= length, "Out of bounds index for service field list");
  
  if (lua_isnil(L,3)) {
    DEBUG("Removing key %d from service list",key);
    LUA_CHECK(length > 1, "Cannot remove element from service field list of size 1, must remove entire field");
    if (subtype == CSM_FIELD_INT) {
      long array[length - 1];
      for (int i = 0, j = 0; j < length; j++) {
	if (j + 1 != key) {
	  long val;
	  LUA_CHECK(csm_field_get_list_int(f, j, &val) == CSM_OK,
		    "Failed to get integer from service field list");
	  array[i] = val;
	  i++;
	}
      }
      LUA_CHECK(csm_field_set_int_list_from_array(f, array, length - 1) == CSM_OK,
		"Failed to update service field list");
    } else { // string/hex
      char *array[length - 1];
      for (int i = 0, j = 0; j < length; j++) {
	if (j + 1 != key) {
	  char *val = csm_field_get_list_string(f, j);
	  LUA_CHECK(val, "Failed to get string from service field list");
	  array[i] = calloc(256,sizeof(char));
	  LUA_CHECK_MEM(array[i]);
	  strcpy(array[i],val);
	  i++;
	}
      }
      LUA_CHECK(csm_field_set_string_list_from_array(f, (const char**)array, length - 1) == CSM_OK,
		"Failed to update service field list");
      for (int i = 0; i < length - 1; i++) {
	free(array[i]);
      }
    }
  } else if (lua_isnumber(L,3)) {
    DEBUG("Replacing integer key %d from service list",key);
    LUA_CHECK(subtype == CSM_FIELD_INT, "New list member must be integer");
    long array[length];
    for (int j = 0; j < length; j++) {
      if (j + 1 != key) {
	long val;
	LUA_CHECK(csm_field_get_list_int(f, j, &val) == CSM_OK,
		  "Failed to get integer from service field list");
	array[j] = val;
      } else {
	array[j] = luaL_checklong(L,3);
      }
    }
    LUA_CHECK(csm_field_set_int_list_from_array(f, array, length) == CSM_OK,
	      "Failed to update service field list");
  } else if (lua_isstring(L,3)) {
    DEBUG("Replacing string key %d from service list",key);
    LUA_CHECK(subtype == CSM_FIELD_STRING || subtype == CSM_FIELD_HEX, "New list member must be string/hex");
    char *array[length];
    for (int j = 0; j < length; j++) {
      array[j] = calloc(256,sizeof(char));
      LUA_CHECK_MEM(array[j]);
      if (j + 1 != key) {
	char *val = csm_field_get_list_string(f, j);
	LUA_CHECK(val, "Failed to get string from service field list");
	strcpy(array[j], val);
      } else {
	strcpy(array[j], luaL_checkstring(L,3));
      }
    }
    LUA_CHECK(csm_field_set_string_list_from_array(f, (const char**)array, length) == CSM_OK,
	      "Failed to update service field list");
    for (int i = 0; i < length; i++) {
      free(array[i]);
    }
  } else {
    LUA_ERROR(L,"Invalid service field list member type");
  }
  return 0;
}

/**
 * Metamethods
 */

static int _l_csm_index( lua_State* L )
{
  /* object, key */
  /* first check the environment */ 
  lua_getfenv( L, -2 );
  lua_pushvalue( L, -2 );
  lua_rawget( L, -2 );
  if( lua_isnoneornil( L, -1 ) == 0 )
  {
    return 1;
  }
  
  lua_pop( L, 2 );
  
  /* second check the metatable */
  lua_getmetatable( L, -2 );
  lua_pushvalue( L, -2 );
  lua_rawget( L, -2 );
  
  /* nil or otherwise, we return here */
  return 1;
}

static int _l_csm_len(lua_State *L) {
  lua_pop(L,1);
  lua_pushstring(L,"__len");
  return _l_csm_index(L);
}

static const struct luaL_reg _l_csm_schema_m [] = {
  {"free", _l_csm_schema_free},
  {"__next", _l_csm_schema_get_next_field},
  {"get_by_index", _l_csm_schema_get_field_by_index},
  {"get_by_name", _l_csm_schema_get_field_by_name},
  {NULL, NULL}
};

static const struct luaL_reg _l_csm_servicelist_m [] = {
  {"__index", _l_csm_servicelist_index},
  {"__next", _l_csm_services_get_next_service},
  {"get_by_index", _l_csm_services_get_by_index},
  {"get_by_key", _l_csm_services_get_by_key},
  {"free", _l_csm_services_free},
  {NULL, NULL}
};

static const struct luaL_reg _l_csm_service_m [] = {
  {"__index", _l_csm_service_index},
  {"__newindex", _l_csm_service_newindex},
  {"__next", _l_csm_service_get_next_field},
  {"free", _l_csm_service_free},
  {"commit", _l_csm_service_commit},
  {"remove", _l_csm_service_remove},
  {"field", _l_csm_service_get_field_by_name},
  {NULL, NULL}
};

static const struct luaL_reg _l_csm_service_field_m [] = {
  {"__newindex", _l_csm_servicefield_newindex},
  {"__tostring", _l_csm_print_field},
  {NULL, NULL}
};

/** General functions */
static const luaL_Reg csmlib[] = {
  {"__index", _l_csm_index},
  {"__len", _l_csm_len},
  {"init", _l_csm_config_create},
  {"config_set_mgmt_sock", _l_csm_config_set_mgmt_sock},
  {"shutdown", _l_csm_config_free},
  {"fetch_schema", _l_csm_schema_fetch},
  {"fetch_services", _l_csm_services_fetch},
  {"new_service", _l_csm_service_create},
  {NULL, NULL}
};

/*
 * Register functions
 */

LUALIB_API int luaopen_csm (lua_State *L);
LUALIB_API int luaopen_csm (lua_State *L) {
  // register general functions
  luaL_register(L, "csm", csmlib);
  
  luaL_newmetatable(L, "csm.config");
  lua_pop(L,1); // remove config metatable from stack
  
  luaL_newmetatable(L, "csm.schema");
  lua_pushstring(L, "__index");
  lua_pushstring(L, "__index");
  lua_gettable(L, 1);  /* get csm.get */
  lua_settable(L, 2);  /* metatable.__index = csm.__index */
  
  lua_pushstring(L, "__len");
  lua_pushstring(L, "__len");
  lua_gettable(L, 1); /* get csm.set */
  lua_settable(L, 2); /* metatable.__len = csm.__len */
  
  luaL_openlib(L, NULL, _l_csm_schema_m, 0); // set the rest of the metamethods for schema
  lua_pop(L,1); // remove schema metatable from stack
  
  luaL_newmetatable(L, "csm.schemafield");
  lua_pushstring(L, "__index");
  lua_pushstring(L, "__index");
  lua_gettable(L, 1);  /* get csm.__index */
  lua_settable(L, 2);  /* metatable.__index = csm.__index */
  
  lua_pop(L,1); // remove schemafield metatable from stack
  
  luaL_newmetatable(L, "csm.servicelist");
  
  lua_pushstring(L, "__len");
  lua_pushstring(L, "__len");
  lua_gettable(L, 1); /* get csm.__len */
  lua_settable(L, 2); /* metatable.__len = csm.__len */
  
  luaL_openlib(L, NULL, _l_csm_servicelist_m, 0); // set the rest of the metamethods for servicelist
  lua_pop(L,1); // remove servicelist metatable from stack
  
  luaL_newmetatable(L, "csm.service");
  
  lua_pushstring(L, "__len");
  lua_pushstring(L, "__len");
  lua_gettable(L, 1); /* get csm.__len */
  lua_settable(L, 2); /* metatable.__len = csm.__len */
  
  luaL_openlib(L, NULL, _l_csm_service_m, 0); // set the rest of the metamethods for servicelist
  lua_pop(L,1); // remove service metatable from stack
  
  luaL_newmetatable(L, "csm.servicefield");
  lua_pushstring(L, "__index");
  lua_pushstring(L, "__index");
  lua_gettable(L, 1);  /* get csm.__index */
  lua_settable(L, 2);  /* metatable.__index = csm.__index */
  
  lua_pushstring(L, "__newindex");
  lua_pushstring(L, "__newindex");
  lua_gettable(L, 1);  /* get csm.__newindex */
  lua_settable(L, 2);  /* metatable.__newindex = csm.__newindex */
  
  lua_pushstring(L, "__len");
  lua_pushstring(L, "__len");
  lua_gettable(L, 1); /* get csm.__len */
  lua_settable(L, 2); /* metatable.__len = csm.__len */
  
  luaL_openlib(L, NULL, _l_csm_service_field_m, 0); // set the rest of the metamethods for servicelist
  lua_pop(L,1); // remove servicefield metatable from stack
  
  return 1;
}