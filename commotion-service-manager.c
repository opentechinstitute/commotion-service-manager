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

#include <commotion/debug.h>
#include <commotion/obj.h>
#include <commotion/list.h>
#include <commotion/tree.h>
#include <commotion.h>

#include "extern/halloc.h"

#include "defs.h"
#include "commotion-service-manager.h"

CSMService *service_create(CSMServiceList *services) {
  co_obj_t *service = co_tree16_create();
  CHECK_MEM(service);
  co_list_append(services,service);
  
  /* Set defaults */
  CHECK(service_set_ttl(service,5),"Failed to set default TTL");
  CHECK(service_set_lifetime(service,0),"Failed to set default lifetime");
  
  return (CSMService*)service;
error:
  return NULL;
}

#define SERVICE_SET_STR(M) \
int \
service_set_##M(CSMService *s, char const *m) \
{ \
  CHECK(IS_TREE(s),"Not a valid service"); \
  if (m) { \
    co_obj_t *o = co_str8_create(m, strlen(m) + 1, 0); \
    CHECK_MEM(o); \
    CHECK(co_tree_insert_force(s, \
			      "M", \
			      sizeof("M"), \
			      o), \
	  "Failed to insert M into service"); \
  } else { \
    co_obj_t *val = co_tree_delete(s, "M", sizeof("M")); \
    if (val) \
      co_obj_free(val); \
  } \
  return 1; \
error: \
  return 0; \
}
SERVICE_SET_STR(name);
SERVICE_SET_STR(description);
SERVICE_SET_STR(uri);
SERVICE_SET_STR(icon);
#undef SERVICE_SET_STR

int
service_set_ttl(CSMService *service, int ttl)
{
  CHECK(IS_TREE(service),"Not a valid service");
  co_obj_t *o = co_uint8_create(ttl, 0);
  CHECK_MEM(o);
  CHECK(co_tree_insert_force(service,
			     "ttl",
			     sizeof("ttl"),
			     o),
	"Failed to insert ttl into service");
  return 1;
error:
  return 0;
}

int service_set_lifetime(CSMService *service, long lifetime) {
  CHECK(IS_TREE(service),"Not a valid service");
  co_obj_t *o = co_uint32_create(lifetime, 0);
  CHECK_MEM(o);
  CHECK(co_tree_insert_force(service,
			     "lifetime",
			     sizeof("lifetime"),
			     o),
	"Failed to insert lifetime into service");
  return 1;
error:
  return 0;
}

int service_set_categories(CSMService *service, char const * const *categories, size_t cat_len) {
  CHECK(IS_TREE(service),"Not a valid service");
  CHECK(cat_len < UINT16_MAX && cat_len >= 0,"Too many categories/invalid category count");
  if (cat_len) {
    co_obj_t *category_list = co_list16_create();
    CHECK_MEM(category_list);
    for (int i = 0; i < cat_len; i++) {
      co_obj_t *category = co_str8_create(categories[i],strlen(categories[i])+1,0);
      CHECK_MEM(category);
      CHECK(co_list_append(category_list,category),"Failed to insert category");
    }
    CHECK(co_tree_insert_force(service,
			      "categories",
			      sizeof("categories"),
			      category_list),
	  "Failed to insert categories into service");
  } else {
    co_obj_t *cat_obj = co_tree_delete(service, "categories", sizeof("categories"));
    if (cat_obj)
      co_obj_free(cat_obj);
  }
  return 1;
error:
  return 0;
}

int service_add_category(CSMService *service, char const *category) {
  CHECK(IS_TREE(service),"Not a valid service");
  CHECK(category, "Invalid category");
  if (!IS_LIST(co_tree_find(service,"categories",sizeof("categories")))) {
    CHECK(service_set_categories(service,&category,1),"Failed to add category");
  } else {
    co_obj_t *category_obj = co_str8_create(category,strlen(category)+1,0);
    CHECK_MEM(category_obj);
    CHECK(co_list_append(co_tree_find(service,"categories",sizeof("categories")),
			 category_obj),
	  "Failed to add category");
  }
  return 1;
error:
  return 0;
}

static co_obj_t *_categories_contains_str_i(co_obj_t *list, co_obj_t *current, void *str) {
  if (IS_LIST(current)) return NULL;
  char *the_str = (char*)current;
  if (co_str_cmp_str(current,the_str) == 0)
    return current;
  return NULL;
}

int service_remove_category(CSMService *service, char const *category) {
  CHECK(IS_TREE(service),"Not a valid service");
  
  co_obj_t *categories = co_tree_find(service,"categories",sizeof("categories"));
  CHECK(IS_LIST(categories),"Invalid category list");
  
  co_obj_t *to_remove = co_list_parse(categories,_categories_contains_str_i,(char*)category);
  CHECK(to_remove,"Service doesn't contain category");
  
  CHECK(co_list_delete(categories,to_remove),"Failed to remove category");
  
  return 1;
error:
  return 0;
}

char *service_get_key(CSMService *service) {
  CHECK(IS_TREE(service),"Not a valid service");
  co_obj_t *field = co_tree_find(service,"key",sizeof("key"));
  CHECK(field,"Service does not have key");
  return ((co_str8_t*)field)->data;
error:
  return NULL;
}

char *service_get_name(CSMService *service) {
  CHECK(IS_TREE(service),"Not a valid service");
  co_obj_t *field = co_tree_find(service,"name",sizeof("name"));
  CHECK(field,"Service does not have name");
  return ((co_str8_t*)field)->data;
error:
  return NULL;
}

char *service_get_description(CSMService *service) {
  CHECK(IS_TREE(service),"Not a valid service");
  co_obj_t *field = co_tree_find(service,"description",sizeof("description"));
  CHECK(field,"Service does not have description");
  return ((co_str8_t*)field)->data;
error:
  return NULL;
}

char *service_get_uri(CSMService *service) {
  CHECK(IS_TREE(service),"Not a valid service");
  co_obj_t *field = co_tree_find(service,"uri",sizeof("uri"));
  CHECK(field,"Service does not have uri");
  return ((co_str8_t*)field)->data;
error:
  return NULL;
}

char *service_get_icon(CSMService *service) {
  CHECK(IS_TREE(service),"Not a valid service");
  co_obj_t *field = co_tree_find(service,"icon",sizeof("icon"));
  CHECK(field,"Service does not have icon");
  return ((co_str8_t*)field)->data;
error:
  return NULL;
}

int service_get_ttl(CSMService *service) {
  CHECK(IS_TREE(service),"Not a valid service");
  co_obj_t *field = co_tree_find(service,"ttl",sizeof("ttl"));
  CHECK(field,"Service does not have ttl");
  return ((co_uint8_t*)field)->data;
error:
  return -1;
}

long service_get_lifetime(CSMService *service) {
  CHECK(IS_TREE(service),"Not a valid service");
  co_obj_t *field = co_tree_find(service,"lifetime",sizeof("lifetime"));
  CHECK(field,"Service does not have lifetime");
  return ((co_uint32_t*)field)->data;
error:
  return -1;
}

int service_get_categories(CSMService *service, CategoryList **categories) {
  CHECK(IS_TREE(service),"Not a valid service");
  co_obj_t *cats = (void*)co_tree_find(service,"categories",sizeof("categories"));
  CHECK(IS_LIST(cats),"Invalid categories field");
  *categories = cats;
  return co_list_length(cats);
error:
  return 0;
}

char *categories_get(CategoryList *categories, int index) {
  CHECK(IS_LIST(categories),"Not a valid category list");
  return ((co_str8_t*)co_list_element(categories,index))->data;
error:
  return NULL;
}

char *service_get_signature(CSMService *service) {
  CHECK(IS_TREE(service),"Not a valid service");
  co_obj_t *field = co_tree_find(service,"signature",sizeof("signature"));
  CHECK(field,"Service does not have signature");
  return ((co_str8_t*)field)->data;
error:
  return NULL;
}

/**
 * adds or updates service, also generates key and signature
 */
int service_commit(CSMService *service) {
  co_obj_t *request = NULL,
	    *response = NULL,
	    *conn = NULL;
  int ret = 0;
  
  CHECK(IS_TREE(service),"Invalid service");
  CHECK(/*co_tree_find(service,"key",sizeof("key"))
        && */co_tree_find(service,"name",sizeof("name"))
        && co_tree_find(service,"description",sizeof("description"))
        && co_tree_find(service,"uri",sizeof("uri"))
        && co_tree_find(service,"icon",sizeof("icon")),
	"Service missing required fields");
  
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
  
  ret = 1;
error:
  if (request) co_free(request);
  
  /* TODO cleanup co_call to deep copy rtree into response so it can be freed by caller */
//   if (response) co_free(response);
  
  /* Close commotiond socket connection */
  co_disconnect(conn);
  return ret;
}

/* calls service_free() */
int service_remove(CSMService *service) {
  co_obj_t *request = NULL,
	    *response = NULL,
	    *conn = NULL;
  int ret = 0;
  
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
  
  ret = 1;
error:
  if (request) co_free(request);
  
  /* TODO cleanup co_call to deep copy rtree into response so it can be freed by caller */
//   if (response) co_free(response);
  
  /* Close commotiond socket connection */
  co_disconnect(conn);
  return ret;
}

int services_fetch(void **services) {
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
  CHECK(CO_TYPE(co_response_get(response,"success",sizeof("success"))) == _true,"Failed to get list of services");
  
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

void *services_get(void *services, int index) {
  CHECK(IS_LIST((co_obj_t*)services),"Not a valid list");
  return (void*)co_list_element((co_obj_t*)services,(unsigned int)index);
error:
  return NULL;
}

int services_free(void *services) {
  CHECK(IS_LIST((co_obj_t*)services) && co_list_length((co_obj_t*)services) > 0,"Not a valid list");
  co_obj_free(services);
  return 1;
error:
  return 0;
}
