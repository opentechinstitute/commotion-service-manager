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

/** 
 * Add OR update a service
 * NOTE: this can be called to create new local services, as well as from uci_read to
 * import local and non-local services from UCI
 */
int
cmd_commit_service(co_obj_t *self, co_obj_t **output, co_obj_t *params)
{
  csm_service *s = NULL;
  int found = 0, success = 0, ret = 0;
  char *version_str = NULL;
  co_obj_t *bool_obj = NULL, *key_obj = NULL, *sig_obj = NULL, *ptr_obj = NULL;
  
  CHECK(IS_LIST(params),"Received invalid params");
  co_obj_t *ctx_obj = co_list_element(params,0);
  CHECK(IS_CTX(ctx_obj),"Received invalid ctx");
  csm_ctx *ctx = ((co_ctx_t*)ctx_obj)->ctx;
  
  co_obj_t *service_fields = co_list_element(params,1);
  CHECK(IS_TREE(service_fields),"Received invalid service fields");
  
  co_obj_t *found_key = co_tree_find(service_fields, "key", sizeof("key"));
  
  if (found_key) {
    // look for existing service in service list
    char *key = NULL;
    size_t key_len = co_obj_data(&key, found_key);
    char uuid[UUID_LEN + 1] = {0};
    CHECK(get_uuid(key,key_len,uuid,UUID_LEN + 1) == UUID_LEN, "Failed to get UUID");
    s = csm_find_service(ctx->service_list, uuid);
    if (!s)
      INFO("Could not find service with provided key, creating new service");
    else
      found = 1;
  }
  
  if (!s) {
    // create new service
    s = csm_service_new(AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, NULL, "_commotion._tcp", "mesh.local");
    CHECK_MEM(s);
    s->local = 1;
  } else {
    if (co_list_contains(ctx->service_list->service_fields, s->fields)) {
      co_obj_t *old_fields = co_list_delete(ctx->service_list->service_fields, s->fields);
      CHECK(old_fields, "Failed to delete old service fields");
      co_obj_free(old_fields);
      s->fields = NULL;
    }
    
    // clear signature so a new one is created upon submission
    if (s->signature)
      s->signature = NULL;
  }
  
  // attach passed list of service fields to our newly created/updated service
  CHECK(co_list_delete(params, service_fields), "Failed to remove service fields from cmd params list");
  s->fields = service_fields;
  service_attach(s->fields, s);
  
  ptr_obj = co_tree_find(s->fields, "lifetime", strlen("lifetime") + 1);
  CHECK(ptr_obj, "Service doesn't contain lifetime field");
  s->lifetime = atol(co_obj_data_ptr(ptr_obj));
  
  ptr_obj = co_tree_find(s->fields, "version", strlen("version") + 1);
  if (ptr_obj) {
    char *version_str = co_obj_data_ptr(ptr_obj);
    char *dot = strchr(version_str, '.');
    CHECK(dot, "Invalid version string; doesn't use semantic versioning");
    *dot = '\0';
    s->version.major = atoi(version_str);
    s->version.minor = atof(dot + 1);
  } else {
    s->version = ctx->schema->version;
    CHECK(asprintf(&version_str, "%d.%f", s->version.major, s->version.minor) != -1, "Failed to generate version string");
    CHECK(csm_service_set_str(s, "version", version_str), "Failed to set version");
  }
  
  ptr_obj = co_tree_find(s->fields, "key", strlen("key") + 1);
  if (ptr_obj)
    s->key = co_obj_data_ptr(ptr_obj);
  ptr_obj = co_tree_find(s->fields, "signature", strlen("signature") + 1);
  if (ptr_obj)
    s->signature = co_obj_data_ptr(ptr_obj);
  
  if (!found)
    success = csm_add_service(ctx->service_list, s, ctx);
  else
    success = csm_update_service(ctx->service_list, s, ctx);
  
  if (success) {
//     ctx->service = s;

    s->l.uptodate = 0; // flag used to indicate need to re-register w/ avahi server if it's an already existing service (otherwise ignored)
    
    // send back success, key, signature
    CHECK(s->key && s->signature && s->uuid, "Failed to get key and signature");
    bool_obj = co_bool_create(true,0);
    CHECK_MEM(bool_obj);
    CMD_OUTPUT("success",bool_obj);
    key_obj = co_str8_create(s->key,strlen(s->key)+1,0);
    CHECK_MEM(key_obj);
    CMD_OUTPUT("key",key_obj);
    sig_obj = co_str8_create(s->signature,strlen(s->signature)+1,0);
    CHECK_MEM(sig_obj);
    CMD_OUTPUT("signature",sig_obj);
    
    CHECK(csm_publish_service(s, ctx), "Failed to publish service");
  } else {
    // remove service, send back failure
    csm_service_destroy(s);
    bool_obj = co_bool_create(false,0);
    CHECK_MEM(bool_obj);
    CMD_OUTPUT("success",bool_obj);
  }
  
  ret = 1;
error:
  if (version_str)
    free(version_str);
  if (bool_obj)
    co_obj_free(bool_obj);
  if (key_obj)
    co_obj_free(key_obj);
  if (sig_obj)
    co_obj_free(sig_obj);
  return ret;
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

int
cmd_get_schema(co_obj_t *self, co_obj_t **output, co_obj_t *params)
{
  CHECK(IS_LIST(params),"Received invalid params");
  co_obj_t *ctx_obj = co_list_element(params,0);
  CHECK(IS_CTX(ctx_obj),"Received invalid ctx");
  csm_ctx *ctx = ((co_ctx_t*)ctx_obj)->ctx;
  
  CMD_OUTPUT("schema",ctx->schema->fields);
  co_obj_t *true_obj = co_bool_create(true,0);
  CHECK_MEM(true_obj);
  CMD_OUTPUT("success",true_obj);
  
  return 1;
error:
  return 0;
}