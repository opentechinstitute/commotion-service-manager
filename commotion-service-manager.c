/**
 *       @file  commotion-service-manager.c
 *      @brief  client API for the Commotion Service Manager
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

#include <ctype.h>

#include <commotion/debug.h>
#include <commotion/obj.h>
#include <commotion/list.h>
#include <commotion/tree.h>
#include <commotion.h>

#include "extern/halloc.h"

#include "defs.h"
#include "commotion-service-manager.h"

static int
is_hex(const char *str, size_t len)
{
  int i;
  for (i = 0; i < len; ++i) {
    if (!isxdigit(str[i]))
      return 0;
  }
  return 1;
}

/** returns number of services */
int
csm_services_fetch(void **services) {
  co_obj_t *request = NULL,
	    *response = NULL,
	    *conn = NULL;
  int ret = 0;
  
  co_init();
  conn = co_connect(CSM_MANAGESOCK, sizeof(CSM_MANAGESOCK));
  CHECK(conn != NULL, "Failed to connect to CSM at %s\n", CSM_MANAGESOCK);
  CHECK_MEM((request = co_request_create()));
  
  co_call(conn, &response, "list_services", sizeof("list_services"), request);
  CHECK(response != NULL, "Invalid response");
  
  // check response for success, then set return val accordingly
  CHECK(CO_TYPE(co_response_get(response,"success",sizeof("success"))) == _true,
	"Failed to get list of services");
  
  co_obj_t *service_list = co_response_get(response,"services",sizeof("services"));
  CHECK(CO_TYPE(service_list) == _list16,"Invalid response");
  
  *services = (void*)service_list;
  
  ret = co_list_length(service_list);
error:
  if (request) co_free(request);
  
  /* Close commotiond socket connection */
  co_disconnect(conn);
  return ret;
}

int
csm_services_free(void *services) {
  CHECK(IS_LIST((co_obj_t*)services),
	"Not a valid list");
  co_obj_free(services);
  return CSM_OK;
error:
  return CSM_ERROR;
}

CSMService *
csm_service_create(void) {
// csm_service_create(CSMServiceList *services) {
  co_obj_t *service = co_tree16_create();
  CHECK_MEM(service);
//   CHECK(co_list_append(services,service), "Failed to add service to list");
  return (CSMService*)service;
error:
  return NULL;
}

/**
 * adds or updates service, also generates key and signature
 */
int csm_service_commit(CSMService *service) {
  co_obj_t *request = NULL,
	    *response = NULL,
	    *conn = NULL;
  int ret = CSM_ERROR;
  
  CHECK(IS_TREE(service),"Invalid service");
  
  co_obj_t *current_key = co_tree_find(service,"key",sizeof("key"));
  
  /* Initialize socket pool for connecting to CSM */
  co_init();
  conn = co_connect(CSM_MANAGESOCK, sizeof(CSM_MANAGESOCK));
  CHECK(conn != NULL, "Failed to connect to CSM at %s\n", CSM_MANAGESOCK);
  
  CHECK_MEM((request = co_request_create()));
  
  CHECK(co_request_append(request,service),"Failed to append service to request");
  
  co_call(conn, &response, "commit_service", sizeof("commit_service"), request);
  CHECK(response != NULL, "Invalid response");
  
  // check response for success, then set return val accordingly
  // response should contain key and signature
  CHECK(CO_TYPE(co_response_get(response,"success",sizeof("success"))) == _true,"Failed to add/update service");
  
  // TODO we may just want to skip this, since the client should update its service list with csm_services_fetch() anyway
  char *key = NULL, *signature = NULL;
  CHECK(co_response_get_str(response,&key,"key",sizeof("key")),"Failed to fetch key from response");
  CHECK(co_response_get_str(response,&signature,"signature",sizeof("signature")),"Failed to fetch signature from response");
  INFO("Successfully added/updated service %s with signature %s",key,signature);
  
  if (!current_key) {
    co_obj_t *key_obj = co_str8_create(key,strlen(key)+1,0);
    CHECK_MEM(key_obj);
    co_tree_insert_force(service,"key",sizeof("key"),key_obj);
  } else {
    CHECK(co_str_cmp_str(current_key,key) == 0,"Received invalid key");
  }
  co_obj_t *signature_obj = co_str8_create(signature,strlen(signature)+1,0);
  CHECK_MEM(signature_obj);
  co_tree_insert_force(service,"signature",sizeof("signature"),signature_obj);
  
  ret = CSM_OK;
error:
  if (request) co_free(request);
  
  /* TODO cleanup co_call to deep copy rtree into response so it can be freed by caller */
//   if (response) co_free(response);
  
  /* Close commotiond socket connection */
  co_disconnect(conn);
  return ret;
}

int csm_service_remove(CSMService *service) {
  co_obj_t *request = NULL,
	    *response = NULL,
	    *conn = NULL;
  int ret = CSM_ERROR;
  
  CHECK(IS_TREE(service),"Invalid service");
  co_obj_t *key_obj = co_tree_find(service,"key",sizeof("key"));
  CHECK(key_obj,"Service doesn't have valid key");
  char *key = co_obj_data_ptr(key_obj);
  
  /* Initialize socket pool for connecting to CSM */
  co_init();
  conn = co_connect(CSM_MANAGESOCK, sizeof(CSM_MANAGESOCK));
  CHECK(conn != NULL, "Failed to connect to CSM at %s\n", CSM_MANAGESOCK);
  
  CHECK_MEM((request = co_request_create()));
  
  CHECK(co_request_append(request,key_obj),"Failed to append key to request");
  
  co_call(conn, &response, "remove_service", sizeof("remove_service"), request);
  CHECK(response != NULL, "Invalid response");
  
  // check response for success, then set return val accordingly
  CHECK(CO_TYPE(co_response_get(response,"success",sizeof("success"))) == _true,"Failed to remove service %s",key);
  INFO("Successfully removed service %s",key);
  
  ret = CSM_OK;
error:
  if (request) co_free(request);
  
  /* TODO cleanup co_call to deep copy rtree into response so it can be freed by caller */
//   if (response) co_free(response);
  
  /* Close commotiond socket connection */
  co_disconnect(conn);
  return ret;
}

void *
csm_services_get_by_index(void *services, int index) {
  CHECK(IS_LIST((co_obj_t*)services),"Not a valid list");
  CHECK(index >= 0 && index < co_list_length((co_obj_t*)services), "Out of bounds index");
  return (void*)co_list_element((co_obj_t*)services,(unsigned int)index);
error:
  return NULL;
}

static co_obj_t *
_csm_services_get_by_key_i(co_obj_t *list, co_obj_t *current, void *context)
{
  CHECK(IS_TREE(current), "Invalid service");
  co_obj_t *key = co_tree_find(current, "key", strlen("key")+1);
  if (key && strcmp(co_obj_data_ptr(key), (char*)context) == 0)
    return current;
error:
  return NULL;
}

void *
csm_services_get_by_key(void *services, char *key) {
  CHECK(IS_LIST((co_obj_t*)services),"Not a valid list");
  return (void*)co_list_parse((co_obj_t*)services, _csm_services_get_by_key_i, key);
error:
  return NULL;
}

int
csm_service_is_local(void *service)
{
  CHECK(IS_TREE((co_obj_t*)service), "Invalid service");
  co_obj_t *local = co_tree_find((co_obj_t*)service, "local", strlen("local")+1);
  if (local && (int32_t)*co_obj_data_ptr(local) == 1)
    return 1;
error:
  return 0;
}

int
csm_service_fields_get_length(void *service)
{
  CHECK(IS_TREE((co_obj_t*)service), "Invalid service");
  return (int)co_tree_length((co_obj_t*)service);
error:
  return CSM_ERROR;
}

void *
csm_service_field_get_next(void *service, void *current, char **name)
{
  CHECK(IS_TREE((co_obj_t*)service), "Invalid service");
  CHECK(CO_TYPE(current) == _str8, "Invalid service field");
  co_obj_t *next = co_tree_next((co_obj_t*)service, current);
  CHECK(next, "No more service fields, or current service field not found");
  char *key = co_obj_data_ptr(next);
  if (name) *name = key;
  return (void*)co_tree_find_node(co_tree_root(service), key, strlen(key)+1);
error:
  return NULL;
}

void *
csm_service_field_get_by_name(void *service, const char *name)
{
  _treenode_t *node = NULL;
  CHECK(IS_TREE((co_obj_t*)service), "Invalid service");
  node = co_tree_find_node(co_tree_root(service), name, strlen(name)+1);
  if (!node) ERROR("Field %s not found", name);
error:
  return node;
}

char *
csm_field_get_name(void *field)
{
  co_obj_t *key = NULL;
  if (field && (key = co_node_key(field)))
    return co_obj_data_ptr(key);
  ERROR("Invalid field");
  return NULL;
}

int
csm_field_get_type(void *field)
{
  co_obj_t *val = NULL;
  CHECK(field && (val = co_node_value((_treenode_t*)field)),
	"Invalid field");
  if (IS_INT(val))
    return CSM_FIELD_INT;
  else if (IS_STR(val)) {
    char *str = co_obj_data_ptr(val);
    return (is_hex(str,strlen(str))) ? CSM_FIELD_HEX : CSM_FIELD_STRING;
  } else if (IS_LIST(val)) {
    return CSM_FIELD_LIST;
  }
error:
  return CSM_ERROR;
}

int
csm_field_get_int(void *field, long *out)
{
  co_obj_t *val = NULL;
  CHECK(field
        && (val = co_node_value((_treenode_t*)field))
	&& IS_INT(val),
	"Invalid int field");
  *out = (long)*co_obj_data_ptr(val);
  return CSM_OK;
error:
  return CSM_ERROR;
}

char *
csm_field_get_string(void *field)
{
  co_obj_t *val = NULL;
  CHECK(field
        && (val = co_node_value((_treenode_t*)field))
	&& IS_STR(val),
	"Invalid string field");
  return co_obj_data_ptr(val);
error:
  return NULL;
}

int
csm_field_get_list_subtype(void *field)
{
  co_obj_t *val = NULL;
  CHECK(field
        && (val = co_node_value((_treenode_t*)field))
	&& IS_LIST(val),
	"Invalid list field");
  ssize_t llen = co_list_length(val);
  CHECK(llen, "Empty list, cannot determine type");
  co_obj_t *first = co_list_get_first(val);
  if (IS_INT(first))
    return CSM_FIELD_INT;
  else if (IS_STR(first)) {
    char *str = co_obj_data_ptr(first);
    return (is_hex(str,strlen(str))) ? CSM_FIELD_HEX : CSM_FIELD_STRING;
  } else if (IS_LIST(first)) {
    return CSM_FIELD_LIST;
  }
error:
  return CSM_ERROR;
}

int
csm_field_get_list_length(void *field)
{
  co_obj_t *val = NULL;
  CHECK(field
        && (val = co_node_value((_treenode_t*)field))
	&& IS_LIST(val),
	"Invalid list field");
  return co_list_length(val);
error:
  return CSM_ERROR;
}

int
csm_field_get_list_int(void *field, int index, long *out)
{
  co_obj_t *val = NULL;
  CHECK(field
        && (val = co_node_value((_treenode_t*)field))
	&& IS_LIST(val),
	"Invalid list field");
  CHECK(index >= 0 && index < co_list_length(val), "Out of bounds index");
  co_obj_t *ret = co_list_element(val, (unsigned int)index);
  CHECK(IS_INT(ret), "Invalid int field");
  *out = (long)*co_obj_data_ptr(ret);
  return CSM_OK;
error:
  return CSM_ERROR;
}

char *
csm_field_get_list_string(void *field, int index)
{
  co_obj_t *val = NULL;
  CHECK(field
        && (val = co_node_value((_treenode_t*)field))
	&& IS_LIST(val),
	"Invalid list field");
  CHECK(index >= 0 && index < co_list_length(val), "Out of bounds index");
  co_obj_t *ret = co_list_element(val, (unsigned int)index);
  CHECK(IS_STR(ret), "Invalid int field");
  return co_obj_data_ptr(ret);
error:
  return NULL;
}

int
csm_field_set_int(void *field, long n)
{
  _treenode_t *node = (_treenode_t*)field;
  CHECK(node && node->key, "Invalid field");
  if(node->value != NULL) {
    co_obj_free(node->value);
  }
  node->value = co_int32_create(n, 0);
  CHECK_MEM(node->value);
  hattach(node->value, node);
  node->value->_ref++;
  return CSM_OK;
error:
  return CSM_ERROR;
}

int
csm_field_set_string(void *field, const char *str)
{
  CHECK(strlen(str) < 256, "String too long");
  _treenode_t *node = (_treenode_t*)field;
  CHECK(node && node->key, "Invalid field");
  if(node->value != NULL) {
    co_obj_free(node->value);
  }
  node->value = co_str8_create(str, strlen(str)+1, 0);
  CHECK_MEM(node->value);
  hattach(node->value, node);
  node->value->_ref++;
  return CSM_OK;
error:
  return CSM_ERROR;
}

int
csm_field_set_int_list_from_array(void *field, long *array, int length)
{
  _treenode_t *node = (_treenode_t*)field;
  CHECK(node && node->key, "Invalid field");
  if(node->value != NULL) {
    co_obj_free(node->value);
  }
  node->value = co_list16_create();
  CHECK_MEM(node->value);
  hattach(node->value, node);
  node->value->_ref++;
  for (int i = 0; i < length; i++) {
    co_obj_t *n = co_int32_create(array[i],0);
    CHECK_MEM(n);
    CHECK(co_list_append(node->value, n), "Failed to add int to field list");
  }
  return CSM_OK;
error:
  return CSM_ERROR;
}

int
csm_field_set_string_list_from_array(void *field, const char **array, int length)
{
  _treenode_t *node = (_treenode_t*)field;
  CHECK(node && node->key, "Invalid field");
  if(node->value != NULL) {
    co_obj_free(node->value);
  }
  node->value = co_list16_create();
  CHECK_MEM(node->value);
  hattach(node->value, node);
  node->value->_ref++;
  for (int i = 0; i < length; i++) {
    CHECK(strlen(array[i]) < 256, "String too long");
    co_obj_t *str = co_str8_create(array[i], strlen(array[i])+1, 0);
    CHECK_MEM(str);
    CHECK(co_list_append(node->value, str), "Failed to add string to field list");
  }
  return CSM_OK;
error:
  return CSM_ERROR;
}

int
csm_field_list_append_int(void *field, long n)
{
  _treenode_t *node = (_treenode_t*)field;
  CHECK(node && node->key && node->value && IS_LIST(node->value), "Invalid field");
  co_obj_t *new = co_int32_create(n,0);
  CHECK_MEM(new);
  CHECK(co_list_append(node->value, new), "Failed to add int to field list");
  return CSM_OK;
error:
  return CSM_ERROR;
}

int
csm_field_list_append_str(void *field, const char *str)
{
  CHECK(strlen(str) < 256, "String too long");
  _treenode_t *node = (_treenode_t*)field;
  CHECK(node && node->key && node->value && IS_LIST(node->value), "Invalid field");
  co_obj_t *new = co_str8_create(str, strlen(str)+1, 0);
  CHECK_MEM(new);
  CHECK(co_list_append(node->value, new), "Failed to add int to field list");
  return CSM_OK;
error:
  return CSM_ERROR;
}

int csm_service_set_int(CSMService *service, const char *field, long n)
{
  CHECK(csm_service_is_local(service), "Cannot modify service");
  co_obj_t *o = co_int32_create(n, 0);
  CHECK_MEM(o);
  CHECK(co_tree_insert_force(service,
			     field,
			     strlen(field) + 1,
			     o),
	"Failed to insert %s into service", field);
  return CSM_OK;
error:
  return CSM_ERROR;
}

int
csm_service_set_string(CSMService *service, const char *field, const char *str)
{
  CHECK(csm_service_is_local(service), "Cannot modify service");
  CHECK(strlen(str) < 256, "String too long");
  co_obj_t *o = co_str8_create(str, strlen(str) + 1, 0);
  CHECK_MEM(o);
  CHECK(co_tree_insert_force(service,
			    field, \
			    strlen(field) + 1,
			    o),
	"Failed to insert %s into service", field);
  return CSM_OK;
error:
  return CSM_ERROR;
}

int
csm_service_set_int_list_from_array(CSMService *service, const char *field, long *array, int length)
{
  CHECK(csm_service_is_local(service), "Cannot modify service");
  co_obj_t *field_list = co_list16_create();
  CHECK_MEM(field_list);
  for (int i = 0; i < length; i++) {
    co_obj_t *field_obj = co_int32_create(array[i],0);
    CHECK_MEM(field_obj);
    CHECK(co_list_append(field_list, field_obj),
	  "Failed to add int %ld to field list %s", array[i], field);
  }
  CHECK(co_tree_insert_force(service, field, strlen(field) + 1, field_list),
	"Failed to insert list %s into service", field);
  return CSM_OK;
error:
  return CSM_ERROR;
}

int
csm_service_set_string_list_from_array(CSMService *service, const char *field, const char **array, int length)
{
  CHECK(csm_service_is_local(service), "Cannot modify service");
  co_obj_t *field_list = co_list16_create();
  CHECK_MEM(field_list);
  for (int i = 0; i < length; i++) {
    co_obj_t *field_obj = co_str8_create(array[i], strlen(array[i])+1, 0);
    CHECK_MEM(field_obj);
    CHECK(co_list_append(field_list, field_obj),
	  "Failed to add string %s to field list %s", array[i], field);
  }
  CHECK(co_tree_insert_force(service, field, strlen(field) + 1, field_list),
	"Failed to insert list %s into service", field);
  return CSM_OK;
error:
  return CSM_ERROR;
}

int csm_service_list_append_int(CSMService *service, const char *field, long n)
{
  CHECK(csm_service_is_local(service), "Cannot modify service");
  co_obj_t *field_list = co_tree_find(service,field,strlen(field) + 1);
  if (!field_list || !IS_LIST(field_list)) {
    field_list = co_list16_create();
    CHECK_MEM(field_list);
    CHECK(co_tree_insert_force(service, field, strlen(field) + 1, field_list),
	  "Failed to insert list %s into service", field);
  }
  co_obj_t *field_obj = co_int32_create(n,0);
  CHECK_MEM(field_obj);
  CHECK(co_list_append(field_list, field_obj),
	"Failed to add int %ld to field list %s", n, field);
  return CSM_OK;
error:
  return CSM_ERROR;
}

int csm_service_list_append_string(CSMService *service, const char *field, const char *str)
{
  CHECK(csm_service_is_local(service), "Cannot modify service");
  co_obj_t *field_list = co_tree_find(service,field,strlen(field) + 1);
  if (!field_list || !IS_LIST(field_list)) {
    field_list = co_list16_create();
    CHECK_MEM(field_list);
    CHECK(co_tree_insert_force(service, field, strlen(field) + 1, field_list),
	  "Failed to insert list %s into service", field);
  }
  co_obj_t *field_obj = co_str8_create(str,strlen(str)+1,0);
  CHECK_MEM(field_obj);
  CHECK(co_list_append(field_list, field_obj),
	"Failed to add string %s to field list %s", str, field);
  return CSM_OK;
error:
  return CSM_ERROR;
}

int csm_service_remove_field(CSMService *service, const char *field)
{
  CHECK(csm_service_is_local(service), "Cannot modify service");
  co_obj_t *val = co_tree_delete(service, field, strlen(field) + 1);
  if (val)
    co_obj_free(val);
  return CSM_OK;
error:
  return CSM_ERROR;
}