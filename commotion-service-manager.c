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
#include "commotion.h"

#include "internal.h"
#include "commotion-service-manager.h"

#define REQUEST_INSERT_STR(K) CHECK(co_tree_insert(params,#K,sizeof(#K),co_str8_create((K),strlen((K))+1,0)),"Failed to insert" #K "into request tree");

int add_service(char const *key,
		char const *name,
		char const *description,
		char const *uri,
		char const *icon,
		uint8_t ttl,
		long lifetime,
		CSMCategory const *categories) {
  
  co_obj_t *request = NULL, 
	    *params = NULL,
	    *response = NULL,
	    *conn = NULL;
  co_obj_t *cats = NULL;
  int ret = 0;
  
  /* Initialize socket pool for connecting to CSM */
  CHECK(co_init(),"Failed to initialize CSM client");
  conn = co_connect(DEFAULT_CSM_SOCK, sizeof(DEFAULT_CSM_SOCK));
  CHECK(conn != NULL, "Failed to connect to CSM at %s\n", DEFAULT_CSM_SOCK);
  
  request = co_request_create();
  CHECK_MEM(request);
  
  params = co_tree16_create();
  CHECK_MEM(params);
//   CHECK(co_tree_insert(params,"key",sizeof("key"),co_str8_create(key,strlen(key)+1,0)),"Failed to insert key into request tree");
//   CHECK(co_tree_insert(params,"name",sizeof("name"),co_str8_create(name,strlen(name)+1,0)),"Failed to insert name into request tree");
//   CHECK(co_tree_insert(params,"description",sizeof("description"),co_str8_create(description,strlen(description)+1,0)),"Failed to insert description into request tree");
//   CHECK(co_tree_insert(params,"uri",sizeof("uri"),co_str8_create(uri,strlen(uri)+1,0)),"Failed to insert uri into request tree");
//   CHECK(co_tree_insert(params,"icon",sizeof("icon"),co_str8_create(icon,strlen(icon)+1,0)),"Failed to insert icon into request tree");
  REQUEST_INSERT_STR(key);
  REQUEST_INSERT_STR(name);
  REQUEST_INSERT_STR(description);
  REQUEST_INSERT_STR(uri);
  REQUEST_INSERT_STR(icon);
  CHECK(co_tree_insert(params,"ttl",sizeof("ttl"),co_uint8_create(ttl,0)),"Failed to insert ttl into request tree");
  CHECK(co_tree_insert(params,"lifetime",sizeof("lifetime"),co_int32_create(lifetime,0)),"Failed to insert lifetime into request tree");
  
  if (categories) {
    cats = co_list16_create();
    while (categories) {
      CHECK(co_list_append(cats,co_str8_create(categories->category,strlen(categories->category)+1,0)),"Failed to insert category");
      categories = categories->_next;
    }
    CHECK(co_tree_insert(params,"categories",sizeof("categories"),cats),"Failed to insert categories into request tree");
  }
  
  CHECK(co_request_append(request,params),"Failed to append service info to request");
  
  if(co_call(conn, &response, "add_service", sizeof("add_service"), request)) ret = 0;
  CHECK(response != NULL, "Invalid response");
  
  // check response for success, then set ret accordingly
  
error:
  if (request) co_free(request);
  if (params) co_free(params);
  
  /* TODO cleanup co_call to deep copy rtree into response so it can be freed by caller */
//   if (response) co_free(response);
  
  /* Close commotiond socket connection */
  co_shutdown();
  return ret;
}

int remove_service(char const *key) {
  return 1;
}

int get_services(CSMService **services) {
  return 1;
}
