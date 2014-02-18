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

#include <stdlib.h>

#include "commotion/obj.h"
#include "commotion/list.h"
#include "commotion/tree.h"
#include "commotion/extern/halloc.h"
#include "commotion.h"

#include "debug.h"
#include "defs.h"
#include "commotion-service-manager.h"

#if 0
typedef struct CSMService {
	char *key;
	char *signature;
	char *name;
	char *description;
	char *uri;
	char *icon;
	int ttl;
	long lifetime;
	char **categories;
	size_t cat_len;
} CSMService;

// #define REQUEST_INSERT_STR2(K) CHECK(co_tree_insert(params,K,sizeof(K),co_str8_create((K),strlen((K))+1,0)),"Failed to insert" #K "into request tree");
// #define REQUEST_INSERT_STR(K) CHECK(co_request_append_str(request,(K),strlen(K)+1),"Failed to insert" #K "into request");

CSMService *service_new(void) {
  CSMService *service = h_calloc(1,sizeof(CSMService));
  // TODO create and set serval key, using commotiond serval plugin
  CHECK_MEM((service->key = h_strdup("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")));
  hattach(service->key,service);
  return service;
error:
  return NULL;
}

void service_free(CSMService *service) {
  if (service)
    h_free(service);
}

int service_set_key(CSMService *service,  const *key) {
  CHECK_MEM(service);
  CHECK_MEM((service->key = h_strdup(key)));
  hattach(service->key,service);
  return 1;
error:
  return 0;
}

int service_set_name(CSMService *service, char const *name) {
  CHECK_MEM(service);
  CHECK_MEM((service->name = h_strdup(name)));
  hattach(service->name,service);
  return 1;
error:
  return 0;
}

int service_set_description(CSMService *service, char const *description) {
  CHECK_MEM(service);
  CHECK_MEM((service->description = h_strdup(description)));
  hattach(service->description,service);
  return 1;
error:
  return 0;
}

int service_set_uri(CSMService *service, char const *uri) {
  CHECK_MEM(service);
  CHECK_MEM((service->uri = h_strdup(uri)));
  hattach(service->uri,service);
  return 1;
error:
  return 0;
}

int service_set_icon(CSMService *service, char const *icon) {
  CHECK_MEM(service);
  CHECK_MEM((service->icon = h_strdup(icon)));
  hattach(service->icon,service);
  return 1;
error:
  return 0;
}

int service_set_ttl(CSMService *service, int ttl) {
  CHECK_MEM(service);
  service->ttl = ttl;
  return 1;
error:
  return 0;
}

int service_set_lifetime(CSMService *service, long lifetime) {
  CHECK_MEM(service);
  service->lifetime = lifetime;
  return 1;
error:
  return 0;
}

int service_set_categories(CSMService *service, StringArray const categories, size_t cat_len) {
  CHECK_MEM(service);
  CHECK_MEM((service->categories = h_calloc(cat_len,sizeof(char*))));
  hattach(service->categories,service);
  service->cat_len = cat_len;
  for (int i; i < cat_len; i++) {
    CHECK_MEM((service->categories[i] = h_strdup(categories[i])));
    hattach(service->categories[i],service);
  }
  return 1;
error:
  return 0;
}

static int _service_find_category(CSMService *service, char const *category) {
  for (int i; i < service->cat_len; i++) {
    if (strcmp(service->categories[i],category) == 0)
      return i;
  }
  return -1;
}

int service_add_category(CSMService *service, char const *category) {
  CHECK_MEM(service);
  CHECK(_service_find_category(service,category) == -1,"Service already has category");
  CHECK_MEM((service->categories = h_realloc(service->categories,service->cat_len+1)));
  CHECK_MEM((service->categories[service->cat_len] = h_strdup(category)));
  hattach(service->categories[service->cat_len],service);
  service->cat_len++;
  return 1;
error:
  return 0;
}
int service_remove_category(CSMService *service, char const *category) {
  CHECK_MEM(service);
  CHECK((int the_category = _service_find_category(service,category)) != -1,"Service does not contain category");
  service->categories[the_category] = service->categories[service->cat_len];
  service->cat_len--;
  return 1;
error:
  return 0;
}

char *service_get_key(CSMService *service) {
  CHECK_MEM(service);
  return service->key;
}

char *service_get_name(CSMService *service) {
  CHECK_MEM(service);
  return service->name;
}

char *service_get_description(CSMService *service) {
  CHECK_MEM(service);
  return service->description;
}

char *service_get_uri(CSMService *service) {
  CHECK_MEM(service);
  return service->uri;
}

char *service_get_icon(CSMService *service) {
  CHECK_MEM(service);
  return service->icon;
}

int service_get_ttl(CSMService *service) {
  CHECK_MEM(service);
  return service->ttl;
}

long service_get_lifetime(CSMService *service) {
  CHECK_MEM(service);
  return service->lifetime;
}

int service_get_categories(CSMService *service, StringArray *categories) {
  CHECK_MEM(service);
  *categories = service->categories;
  return service->cat_len;
}

char *service_get_signature(CSMService *service) {
  CHECK_MEM(service);
  return service->signature;
}

int commit_service(CSMService *service, char **signature) {
  co_obj_t *request = NULL,
	    *params = NULL,
	    *response = NULL,
	    *conn = NULL;
  co_obj_t *cats = NULL;
  int ret = 0;
  
  CHECK(service->key &&
        service->name &&
        service->description &&
        service->uri &&
        service->icon,
	"Invalid service");
  
  /* Initialize socket pool for connecting to CSM */
  co_init();
  conn = co_connect(CSM_MANAGESOCK, sizeof(CSM_MANAGESOCK));
  CHECK(conn != NULL, "Failed to connect to CSM at %s\n", CSM_MANAGESOCK);
  
  CHECK_MEM((request = co_request_create()));
  
  CHECK_MEM((params = co_tree16_create()));
  
#define REQUEST_ITEM(M,O) { \
  CHECK(co_tree_insert(params,\
		       (#M),\
		       sizeof(#M),\
		       (O),\
	"Failed to insert" #M "into request parameters"); \
  }
#define REQUEST_ITEM_STR(M) REQUEST_ITEM(M,co_str8_create(service->M,strlen(service->M)+1,0))
  REQUEST_ITEM_STR(key);
  REQUEST_ITEM_STR(name);
  REQUEST_ITEM_STR(description);
  REQUEST_ITEM_STR(uri);
  REQUEST_ITEM_STR(icon);
  REQUEST_ITEM(ttl,co_uint8_create(service->ttl,0));
  REQUEST_ITEM(lifetime,co_uint32_create(service->lifetime,0));
  
  if (service->cat_len && service->categories) {
    CHECK_MEM((cats = co_list16_create()));
    for (int i = 0; i < service->cat_len; i++)
      CHECK(co_list_append(cats,co_str8_create(service->categories[i],strlen(service->categories[i])+1,0)),"Failed to insert category into request parameters");
    REQUEST_ITEM(categories,cats);
  }
  
  CHECK(co_request_append(request,params),"Failed to add parameters to request");
  
  co_call(conn, &response, "commit_service", sizeof("commit_service"), request);
  CHECK(response != NULL, "Invalid response");
  
  // check response for success, then set return val accordingly
  // response should contain created signature
  CHECK(CO_TYPE(co_response_get(response,"success",sizeof("success"))) == _true,"Failed to add/update service %s",service->key);

  INFO("Successfully added/updated service %s",service->key);
  CHECK(co_response_get_str(response,signature,"signature",sizeof("signature")),"Failed to fetch signature from response");
  ret = 1;
error:
  if (request) co_free(request);
  
  /* TODO cleanup co_call to deep copy rtree into response so it can be freed by caller */
//   if (response) co_free(response);
  
  /* Close commotiond socket connection */
  co_disconnect(conn);
  return ret;
}

int remove_service(CSMService *service) {
  co_obj_t *request = NULL,
	    *response = NULL,
	    *conn = NULL;
  int ret = 0;
  
  /* Initialize socket pool for connecting to CSM */
  co_init();
  conn = co_connect(CSM_MANAGESOCK, sizeof(CSM_MANAGESOCK));
  CHECK(conn != NULL, "Failed to connect to CSM at %s\n", CSM_MANAGESOCK);
  
  CHECK_MEM((request = co_request_create()));
  
  CHECK(co_response_append_str(request,
			       "key",
			       sizeof("key"),
			       co_str8_create(service->key,strlen(service->key)+1,0)),
	"Failed to append key to request");
  
  co_call(conn, &response, "remove_service", sizeof("remove_service"), request);
  CHECK(response != NULL, "Invalid response");
  
  // check response for success, then set return val accordingly
  CHECK(CO_TYPE(co_response_get(response,"success",sizeof("success"))) == _true,"Failed to remove service %s",service->key);
  INFO("Successfully removed service %s",service->key);
  
  CHECK(service_free(service),"Failed to free service");
  
  ret = 1;
error:
  if (request) co_free(request);
  
  /* TODO cleanup co_call to deep copy rtree into response so it can be freed by caller */
//   if (response) co_free(response);
  
  /* Close commotiond socket connection */
  co_disconnect(conn);
  return ret;
}
#endif












CSMService *service_new(CSMServiceList *services) {
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

#define SERVICE_SET(M,O) { \
  CHECK(IS_TREE(service),"Not a valid service");\
  CHECK(co_tree_insert_force(service,\
		       (#M),\
		       sizeof(#M),\
		       (O)),\
	"Failed to insert" #M "into service"); \
  }
#define SERVICE_SET_STR(S) SERVICE_SET((S),co_str8_create((S),strlen(S)+1,0))
int service_set_name(CSMService *service, char const *name) {
  SERVICE_SET_STR(name);
  return 1;
error:
  return 0;
}

int service_set_description(CSMService *service, char const *description) {
  SERVICE_SET_STR(description);
  return 1;
error:
  return 0;
}

int service_set_uri(CSMService *service, char const *uri) {
  SERVICE_SET_STR(uri);
  return 1;
error:
  return 0;
}

int service_set_icon(CSMService *service, char const *icon) {
  SERVICE_SET_STR(icon);
  return 1;
error:
  return 0;
}

int service_set_ttl(CSMService *service, int ttl) {
  SERVICE_SET(ttl,co_uint8_create(ttl,0));
  return 1;
error:
  return 0;
}

int service_set_lifetime(CSMService *service, long lifetime) {
  SERVICE_SET(lifetime,co_uint32_create(lifetime,0));
  return 1;
error:
  return 0;
}

int service_set_categories(CSMService *service, char const * const *categories, size_t cat_len) {
  CHECK(cat_len < UINT16_MAX,"Too many categories");
  co_obj_t *category_list = co_list16_create();
  CHECK_MEM(category_list);
  for (int i = 0; i < cat_len; i++) {
    CHECK(co_list_append(category_list,co_str8_create(categories[i],strlen(categories[i])+1,0)),"Failed to insert category");
  }
  SERVICE_SET(categories,category_list);
  return 1;
error:
  return 0;
}

int service_add_category(CSMService *service, char const *category) {
  CHECK(IS_TREE(service),"Not a valid service");
  if (!IS_LIST(co_tree_find(service,"categories",sizeof("categories")))) {
    CHECK(service_set_categories(service,&category,1),"Failed to add category");
    return 1;
  } else {
    CHECK(co_list_append(co_tree_find(service,"categories",sizeof("categories")),
			 co_str8_create(category,strlen(category)+1,0)),
	  "Failed to add category");
    return 1;
  }
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
  
  co_tree_insert_force(service,"key",sizeof("key"),co_str8_create(key,strlen(key)+1,0));
  co_tree_insert_force(service,"signature",sizeof("signature"),co_str8_create(signature,strlen(signature)+1,0));
  
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
//   return (void*)service_list;
  
// #define FETCH_STR(M) strdup(co_obj_data_ptr(co_tree_find(service_list[i],#M,sizeof(#M))))
//   CSMService *services = h_calloc(co_list_length(service_list),sizeof(CSMService));
//   for (int i = 0; i < co_list_length(service_list); i++) {
//     services[i] = {.key = FETCH_STR(key),
// 		   .name = FETCH_STR(name),
// 		   .description = FETCH_STR(description),
// 		   .uri = FETCH_STR(uri),
// 		   .icon = FETCH_STR(icon),
// 		   ...
//     };
//     hattach()????  
//   }
  
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

// int free_services(CSMServiceArray services, int n_services) {
//   for (int i = 0; i < n, i++) {
//     CHECK(service_free(services[i]),"Failed to free service %d",i);
//   }
//   return 1;
// error:
//   return 0;
// }

#ifdef CLIENT_MAIN
int main(int argc, char*argv[]) {
//   CSMCategory *cat = calloc(1,sizeof(CSMCategory) + 5);
//   strcpy(cat->category,"test1");
//   CSMCategory *cat2 = calloc(1,sizeof(CSMCategory) + 5);
//   strcpy(cat2->category,"test2");
//   cat->_next = cat2;
  
  /*add_service("key",
	      "name",
	      "desc",
	      "uri",
	      "icon",
	      5,
	      123,
	      cat);*/
//   remove_service("blah");
  return 0;
}
#endif