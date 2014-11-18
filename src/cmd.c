/**
 *       @file  cmd.c
 *      @brief  command handlers for Commotion Service Manager
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

#define _GNU_SOURCE         /* asprintf */

#include "cmd.h"

#include <stdio.h>

#include <commotion/obj.h>
#include <commotion/list.h>
#include <commotion/tree.h>
#include <commotion/cmd.h>

#include "extern/halloc.h"

#include "defs.h"
#include "publish.h"
#include "service.h"
#include "service_list.h"
#include "util.h"

static co_obj_t *
_cmd_help_i(co_obj_t *data, co_obj_t *current, void *context) 
{
  char *cmd_name = NULL;
  size_t cmd_len = 0;
  CHECK((cmd_len = co_obj_data(&cmd_name, ((co_cmd_t *)current)->name)) > 0, "Failed to read command name.");
  DEBUG("Command: %s, Length: %d", cmd_name, (int)cmd_len);
  co_tree_insert((co_obj_t *)context, cmd_name, cmd_len, ((co_cmd_t *)current)->usage);
  return NULL;
error:
  return NULL;
}

int
cmd_help(co_obj_t *self, co_obj_t **output, co_obj_t *params)
{
  CHECK(IS_LIST(params),"Received invalid params");
  
  *output = co_tree16_create();
  if (co_list_length(params) > 1)
  {
    co_obj_t *cmd = co_list_element(params, 1);
    if (cmd != NULL && IS_STR(cmd))
    {
      char *cstr = NULL;
      size_t clen = co_obj_data(&cstr, cmd);
      if (clen > 0)
      {
	co_tree_insert(*output, cstr, clen, co_cmd_desc(cmd));
	return 1;
      }
    }
    else return 0;
  }
  return co_cmd_process(_cmd_help_i, (void *)*output);
error:
  return 0;
}

/** 
 * Add OR update a service
 * NOTE: this can be called to create new local services, as well as from uci_read to
 * import local and non-local services from UCI
 */
int
cmd_commit_service(co_obj_t *self, co_obj_t **output, co_obj_t *params)
{
  csm_service *s = NULL, *existing = NULL;
  char *version_str = NULL;
  co_obj_t *key_obj = NULL, *sig_obj = NULL, *ptr_obj = NULL;
  int added = 0;
  
  CHECK(IS_LIST(params) && co_list_length(params) == 3,"Received invalid params");
  co_obj_t *ctx_obj = co_list_element(params,0);
  CHECK(IS_CTX(ctx_obj),"Received invalid ctx");
  csm_ctx *ctx = ((co_ctx_t*)ctx_obj)->ctx;
  
  co_obj_t *service_fields = co_list_element(params,1);
  CHECK(IS_TREE(service_fields),"Received invalid service fields");
  
  co_obj_t *local = co_list_element(params,2);
  CHECK(IS_BOOL(local),"Received invalid local param");
  
  // create new service
  s = csm_service_new(AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, NULL, "_commotion._tcp", "mesh.local");
  CHECK_MEM(s);
  
  if (IS_TRUE(local))
    s->local = 1;
  
  // attach passed list of service fields to our newly created/updated service
  CHECK(co_list_delete(params, service_fields), "Failed to remove service fields from cmd params list");
  s->fields = service_fields;
  service_attach(s->fields, s);
  
  ptr_obj = co_tree_find(s->fields, "lifetime", sizeof("lifetime"));
  CHECK(ptr_obj, "Service doesn't contain lifetime field");
  s->lifetime = (long)((co_int32_t*)ptr_obj)->data;
  
  ptr_obj = co_tree_find(s->fields, "version", sizeof("version"));
  if (ptr_obj) {
    char *version_str = strdup(co_obj_data_ptr(ptr_obj));
    char *dot = strchr(version_str, '.');
    CHECK(dot,"Invalid version string; doesn't use semantic versioning");
    *dot = '\0';
    s->version.major = atoi(version_str);
    s->version.minor = atof(dot + 1);
  } else {
    s->version = ctx->schema->version;
    CHECK(asprintf(&version_str, "%d.%f", s->version.major, s->version.minor) != -1, "Failed to generate version string");
    CHECK(csm_service_set_str(s, "version", version_str), "Failed to set version");
  }
  
  ptr_obj = co_tree_find(s->fields, "signature", sizeof("signature"));
  if (ptr_obj) {
    if (s->local)
      co_tree_delete(s->fields,"signature",sizeof("signature"));
    else
      s->signature = co_obj_data_ptr(ptr_obj);
  }
  ptr_obj = co_tree_find(s->fields, "key", sizeof("key"));
  if (ptr_obj) {
    s->key = co_obj_data_ptr(ptr_obj);
    // look for existing service in service list
    char *key = NULL;
    size_t key_size = co_obj_data(&key, ptr_obj);
    char uuid[UUID_LEN + 1] = {0};
    CHECK(get_uuid(key,key_size - 1,uuid,UUID_LEN + 1) == UUID_LEN, "Failed to get UUID");
    existing = csm_find_service(ctx->service_list, uuid);
    if (!existing)
      INFO("Could not find service with provided key, creating new service");
    else {
      // unpublish and remove existing service from service list
      if (s->local) {
	CHECK(!ENTRY_GROUP_EMPTY(existing->l.group),"EMPTY ENTRY GROUP");
	s->l.group = existing->l.group;
	s->l.uptodate = 0;
      }
//       CHECK(csm_unpublish_service(existing, ctx), "Failed to unpublish service");
      CHECK(csm_remove_service(ctx->service_list, existing), "Failed to remove old service");
      s->uuid = h_strdup(uuid);
      CHECK_MEM(s->uuid);
      service_attach(s->uuid, s);
    }
  }
  
  CHECK(csm_add_service(ctx->service_list, s, ctx), "Failed to add service");
  added = 1;
  if (s->local && !csm_publish_service(s, ctx))
    ERROR("Failed to publish service");
  if (existing) {
    existing->l.group = NULL;
    csm_service_destroy(existing);
  }
  
  // send back success, key, signature
  CHECK(s->key && s->signature && s->uuid, "Failed to get key and signature");
  
  key_obj = co_str8_create(s->key,strlen(s->key)+1,0);
  CHECK_MEM(key_obj);
  CMD_OUTPUT("key",key_obj);
  key_obj = NULL;
  sig_obj = co_str8_create(s->signature,strlen(s->signature)+1,0);
  CHECK_MEM(sig_obj);
  CMD_OUTPUT("signature",sig_obj);
  
  CMD_OUTPUT("success",co_bool_create(true,0));
  
  free(version_str);
  return 1;

error:
  CMD_OUTPUT("success",co_bool_create(false,0));
  if (s && !added)
    csm_service_destroy(s);
  if (version_str)
    free(version_str);
  if (key_obj)
    co_obj_free(key_obj);
  if (sig_obj)
    co_obj_free(sig_obj);
  return 1;
}

int
cmd_remove_service(co_obj_t *self, co_obj_t **output, co_obj_t *params)
{
  CHECK(IS_LIST(params),"Received invalid params");
  co_obj_t *ctx_obj = co_list_element(params,0);
  CHECK(IS_CTX(ctx_obj),"Received invalid ctx");
  csm_ctx *ctx = ((co_ctx_t*)ctx_obj)->ctx;
  
  co_obj_t *key_obj = co_list_element(params,1);
  CHECK(IS_STR(key_obj),"Received invalid key");
  
  char *key = NULL;
  size_t key_size = co_obj_data(&key,key_obj);
  CHECK(isValidFingerprint(key,key_size - 1),"Received invalid key");
  
  char uuid[UUID_LEN + 1] = {0};
  CHECK(get_uuid(key,key_size - 1,uuid,UUID_LEN + 1) == UUID_LEN, "Failed to get UUID");
  
  csm_service *s = csm_find_service(ctx->service_list, uuid);
  
  CHECK(s && csm_unpublish_service(s, ctx), "Failed to unpublish service");
  CHECK(csm_remove_service(ctx->service_list, s), "Failed to remove service");
  csm_service_destroy(s);
  
  CMD_OUTPUT("success",co_bool_create(true,0));
  return 1;
error:
  CMD_OUTPUT("success",co_bool_create(false,0));
  return 1;
}

int
cmd_list_services(co_obj_t *self, co_obj_t **output, co_obj_t *params)
{
  CHECK(IS_LIST(params),"Received invalid params");
  co_obj_t *ctx_obj = co_list_element(params,0);
  CHECK(IS_CTX(ctx_obj),"Received invalid ctx");
  csm_ctx *ctx = ((co_ctx_t*)ctx_obj)->ctx;
  
  CMD_OUTPUT("services",ctx->service_list->service_fields);
  CMD_OUTPUT("success",co_bool_create(true,0));  
  return 1;
error:
  CMD_OUTPUT("success",co_bool_create(false,0));
  return 1;
}

int
cmd_get_schema(co_obj_t *self, co_obj_t **output, co_obj_t *params)
{
  CHECK(IS_LIST(params),"Received invalid params");
  co_obj_t *ctx_obj = co_list_element(params,0);
  CHECK(IS_CTX(ctx_obj),"Received invalid ctx");
  csm_ctx *ctx = ((co_ctx_t*)ctx_obj)->ctx;
  
  CMD_OUTPUT("schema",ctx->schema->fields);
  CMD_OUTPUT("success",co_bool_create(true,0));
  return 1;
error:
  CMD_OUTPUT("success",co_bool_create(false,0));
  return 1;
}

int
cmd_get_schema_version(co_obj_t *self, co_obj_t **output, co_obj_t *params)
{
  CHECK(IS_LIST(params),"Received invalid params");
  co_obj_t *ctx_obj = co_list_element(params,0);
  CHECK(IS_CTX(ctx_obj),"Received invalid ctx");
  csm_ctx *ctx = ((co_ctx_t*)ctx_obj)->ctx;
  
  co_obj_t *major = co_int8_create(ctx->schema->version.major,0);
  CHECK_MEM(major);
  co_obj_t *minor = co_float64_create(ctx->schema->version.minor,0);
  CHECK_MEM(minor);
  CMD_OUTPUT("major",major);
  CMD_OUTPUT("minor",minor);
  CMD_OUTPUT("success",co_bool_create(true,0));
  return 1;
error:
  CMD_OUTPUT("success",co_bool_create(false,0));
  return 1;
}