#include <commotion/obj.h>
#include <commotion/list.h>
#include <commotion/tree.h>
#include <commotion/cmd.h>

#include "defs.h"
#include "service.h"
#include "service_list.h"
#include "publish.h"
#include "util.h"
#include "cmd.h"

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
//   co_obj_t *ctx_obj = co_list_element(params,0);
//   CHECK(IS_CTX(ctx_obj),"Received invalid ctx");
//   csm_ctx *ctx = ((co_ctx_t*)ctx_obj)->ctx;
  
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

/** Add OR update a service */
int
cmd_commit_service(co_obj_t *self, co_obj_t **output, co_obj_t *params)
{
  // TODO insert major/minor version of schema into newly created services
  CHECK(IS_LIST(params),"Received invalid params");
  co_obj_t *ctx_obj = co_list_element(params,0);
  CHECK(IS_CTX(ctx_obj),"Received invalid ctx");
  csm_ctx *ctx = ((co_ctx_t*)ctx_obj)->ctx;
  
  co_obj_t *service = co_list_element(params,1);
  CHECK(IS_TREE(service),"Received invalid service");

  co_obj_t *name_obj = co_tree_find(service,"name",sizeof("name"));
  co_obj_t *description_obj = co_tree_find(service,"description",sizeof("description"));
  co_obj_t *uri_obj = co_tree_find(service,"uri",sizeof("uri"));
  co_obj_t *icon_obj = co_tree_find(service,"icon",sizeof("icon"));
  co_obj_t *key_obj = co_tree_find(service,"key",sizeof("key"));
  
  /* Check required fields */
  CHECK(name_obj && description_obj && uri_obj && icon_obj,
	"Service missing required fields");
  
  csm_service *s = NULL;
  
  if (key_obj) {
    // find existing service
    char *key = NULL;
    size_t key_len = co_obj_data(&key, key_obj);
    CHECK(isValidFingerprint(key,strlen(key)),"Invalid key");
    char uuid[UUID_LEN + 1] = {0};
    CHECK(get_uuid(key,key_len,uuid,UUID_LEN + 1) == UUID_LEN, "Failed to get UUID");
    s = csm_find_service(ctx->service_list, uuid);
    if (!s)
      INFO("Could not find service with provided key, creating new service");
  }
  
  if (!s) {
    // create new service
    s = csm_service_new(AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, NULL, "_commotion._tcp", "mesh.local");
    CHECK_MEM(s);
    s->local = 1;
    // TODO do add_service here
  } else {
    // TODO use update_service here
  }
  
  ctx->service = s;
  
  // we can now replace/set the service's fields with the new passed fields
  // TODO THIS IS BAD, redo this (and move to above if block)
  co_obj_free(s->fields); // TODO this will only work if brand new service that hasn't been added to service_list
  hattach(service, NULL); // TODO remove from list instead of just detaching
  s->fields = service;
  hattach(s->fields, s);
  
  // delete signature so a new one is created upon submission
  // TODO this should be moved to above if block before update_service call
  if (csm_service_get_signature(s))
    csm_service_set_signature(s, NULL);
  
  CHECK(csm_service_set_version(s, CSM_PROTO_VERSION), "Failed to set version");
  
  if (csm_add_service(ctx->service_list, s)) {
    s->l.uptodate = 0; // flag used to indicate need to re-register w/ avahi server if it's an already existing service (otherwise ignored)
    
    // send back success, key, signature
    char *key = csm_service_get_key(s);
    char *signature = csm_service_get_signature(s);
    CHECK(key && signature && s->uuid, "Failed to get key and signature");
    co_obj_t *true_obj = co_bool_create(true,0);
    CHECK_MEM(true_obj);
    CMD_OUTPUT("success",true_obj);
    co_obj_t *key_obj = co_str8_create(key,strlen(key)+1,0);
    CHECK_MEM(key_obj);
    CMD_OUTPUT("key",key_obj);
    co_obj_t *sig_obj = co_str8_create(signature,strlen(signature)+1,0);
    CHECK_MEM(sig_obj);
    CMD_OUTPUT("signature",sig_obj);
    
    CHECK(csm_publish_service(s, ctx), "Failed to publish service");
  } else {
    // remove service, send back failure
    csm_service_destroy(s);
    co_obj_t *false_obj = co_bool_create(false,0);
    CHECK_MEM(false_obj);
    CMD_OUTPUT("success",false_obj);
  }
  
  return 1;
error:
  return 0;
}

int
cmd_remove_service(co_obj_t *self, co_obj_t **output, co_obj_t *params)
{
  // TODO add check to make sure we're removing a local servie and not a remote one
  CHECK(IS_LIST(params),"Received invalid params");
  co_obj_t *ctx_obj = co_list_element(params,0);
  CHECK(IS_CTX(ctx_obj),"Received invalid ctx");
  csm_ctx *ctx = ((co_ctx_t*)ctx_obj)->ctx;
  
  co_obj_t *key_obj = co_list_element(params,1);
  CHECK(IS_STR(key_obj),"Received invalid key");
  
  char *key = NULL;
  size_t key_len = co_obj_data(&key,key_obj);
  CHECK(isValidFingerprint(key,key_len),"Received invalid key");
  
  char uuid[UUID_LEN + 1] = {0};
  CHECK(get_uuid(key,key_len,uuid,UUID_LEN + 1) == UUID_LEN, "Failed to get UUID");
  
  csm_service *s = csm_find_service(ctx->service_list, uuid);
  
  if (s && csm_unpublish_service(s, ctx)) {
    csm_remove_service(ctx->service_list, s);
    csm_service_destroy(s);
    co_obj_t *true_obj = co_bool_create(true,0);
    CHECK_MEM(true_obj);
    CMD_OUTPUT("success",true_obj);
  } else {
    co_obj_t *false_obj = co_bool_create(false,0);
    CHECK_MEM(false_obj);
    CMD_OUTPUT("success",false_obj);
  }
  
  return 1;
error:
  return 0;
}

int
cmd_list_services(co_obj_t *self, co_obj_t **output, co_obj_t *params)
{
  CHECK(IS_LIST(params),"Received invalid params");
  co_obj_t *ctx_obj = co_list_element(params,0);
  CHECK(IS_CTX(ctx_obj),"Received invalid ctx");
  csm_ctx *ctx = ((co_ctx_t*)ctx_obj)->ctx;
  
  if (csm_services_length(ctx->service_list) == 0) {
    co_obj_t *false_obj = co_bool_create(false,0);
    CHECK_MEM(false_obj);
    CMD_OUTPUT("success",false_obj);
    return 1;
  }
  
  CMD_OUTPUT("services",ctx->service_list->service_fields);
  co_obj_t *true_obj = co_bool_create(true,0);
  CHECK_MEM(true_obj);
  CMD_OUTPUT("success",true_obj);
  
  return 1;
error:
  return 0;
}