/**
 *       @file  uci-utils.c
 *      @brief  UCI integration for the Commotion Service Manager
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

#include "uci-utils.h"

#include <assert.h>
#include <stdio.h>
#include <uci.h>

#include <commotion/debug.h>
#include <commotion/obj.h>
#include <commotion/list.h>
#include <commotion/tree.h>
#include <commotion.h>

#include "defs.h"
#include "cmd.h"
#include "config.h"
#include "schema.h"
#include "service.h"
#include "util.h"

#define UCI_CHECK(A, M, ...) \
  if(!(A)) { \
    char *err = NULL; \
    uci_get_errorstr(c,&err,NULL); \
    ERROR(M ": %s", ##__VA_ARGS__, err); \
    free(err); \
    errno=0; \
    goto error; \
  }
#define UCI_WARN(M, ...) \
  do { \
    char *err = NULL; \
    uci_get_errorstr(c,&err,NULL); \
    WARN(M ": %s", ##__VA_ARGS__, err); \
    free(err); \
  } while (0)
#define _UCI_SET(F,C,SRV,FLD,VAL) \
  do { \
    struct uci_ptr sec_ptr = {0}; \
    sec_ptr.package = "applications"; \
    sec_ptr.section = SRV->uuid; \
    sec_ptr.option = #FLD; \
    sec_ptr.value = VAL; \
    int uci_ret = F(C, &sec_ptr); \
    UCI_CHECK(uci_ret == UCI_OK,"Failed to set UCI field " #FLD); \
  } while (0)
#define UCI_SET(C,SRV,FLD,VAL) _UCI_SET(uci_set,C,SRV,FLD,VAL)

static co_obj_t *
_uci_write_service(co_obj_t *list, co_obj_t *current, void *context)
{
  if (IS_LIST(current)) return NULL;
  assert(IS_SERVICE(current));
  co_service_t *s = (co_service_t*)current;
  CHECK(uci_write(&s->service), "Failed to write service %s", s->service.uuid);
  return NULL;
error:
  return current;
}

/**
 * data and output not used
 */
int
uci_service_updater(co_obj_t *data, co_obj_t **output, co_obj_t *service_list)
{
  assert(IS_LIST(service_list));
  int ret = 0;
  struct uci_package *pkg = NULL;
  struct uci_context *c = uci_alloc_context();
  CHECK_MEM(c);
  
  uci_set_confdir(c, getenv("UCI_INSTANCE_PATH") ? : UCIPATH);
  
  // delete current services in UCI
  uci_load(c, "applications", &pkg);
  CHECK(pkg, "Failed to load applications");
  struct uci_element *e = NULL, *tmp = NULL;
  struct uci_list *section_list = &pkg->sections;
  uci_foreach_element_safe(section_list, tmp, e) {
    struct uci_section *section = uci_to_section(e);
    if (strcmp(section->type,"application") == 0) {
      struct uci_ptr ptr = {
	.p = pkg,
	.s = section,
      };
      CHECK(uci_delete(c, &ptr) == 0, "Failed to delete application");
    }
  }
  
  // uci_save
  CHECK(uci_save(c, pkg) == UCI_OK,"Failed to save");
  INFO("Save succeeded");
  
  CHECK(uci_commit(c,&pkg,false) == UCI_OK,"Failed to commit");
  INFO("Commit succeeded");
  
  // write out all services using uci_write
  CHECK(co_list_parse(service_list, _uci_write_service, NULL) == NULL,
	"Failed to write service list to UCI");
  
  ret =  1;
error:
  if (c) uci_free_context(c);
  return ret;
}

/** 
 * Lookup a UCI section or option
 * @param c uci_context pointer
 * @param[out] sec_ptr uci_ptr struct to be populated by uci_lookup_ptr()
 * @param file UCI config name
 * @param file_len length of config name
 * @param sec UCI section name
 * @param sec_len length of section name
 * @param op UCI option name
 * @param op_len length of option name
 * @return -1 = fail, > 0 success/sec_ptr flags
 */
int 
get_uci_section(struct uci_context *c,
		struct uci_ptr *sec_ptr,
		const char *file, 
		const size_t file_len,
		const char *sec, 
		const size_t sec_len,
		const char *op,
		const size_t op_len)
{
  char *lookup_str = NULL;
  int ret = -1;
  
  memset(sec_ptr, 0, sizeof(struct uci_ptr));
  
  if (op_len) {
    CHECK_MEM((lookup_str = calloc(file_len + sec_len + op_len + 3,sizeof(char))));
  } else {
    CHECK_MEM((lookup_str = calloc(file_len + sec_len + 2,sizeof(char))));
  }
  strncpy(lookup_str,file,file_len);
  lookup_str[file_len] = '.';
  strncpy(lookup_str + file_len + 1,sec,sec_len);
  if (op_len) {
    lookup_str[file_len + 1 + sec_len] = '.';
    strncpy(lookup_str + file_len + sec_len + 2,op,op_len);
    lookup_str[file_len + sec_len + op_len + 2] = '\0';
  } else
    lookup_str[file_len + sec_len + 1] = '\0';
  
  UCI_CHECK(uci_lookup_ptr(c, sec_ptr, lookup_str, false) == UCI_OK,
	    "Failed section lookup: %s",lookup_str);
  ret = (*sec_ptr).flags;

error:
  if (lookup_str) free(lookup_str);
  return ret;
}

/**
 * caller must free returned object
 */
static co_obj_t *
_csm_store_uci_field(char *key, char *val, csm_ctx *ctx)
{
  co_obj_t *val_obj = NULL;
  CHECK(strlen(val) + strlen(key) < 256, "Service option length too long");
  csm_schema_field_t *field = csm_schema_get_field(ctx->schema, key);
  if (!field)
    SENTINEL("Service option %s not in schema", key);
  int type = (field->type == CSM_FIELD_LIST) ? field->subtype : field->type;
  if (field) {
    switch (type) {
      case CSM_FIELD_STRING:
      case CSM_FIELD_HEX:
	val_obj = co_str8_create(val, strlen(val) + 1, 0);
	CHECK_MEM(val_obj);
	break;
      case CSM_FIELD_INT:
	val_obj = co_int32_create(atol(val),0);
	CHECK_MEM(val_obj);
	break;
      default:
	SENTINEL("Invalid schema type");
    }
  } else {
    char *endptr = NULL;
    long int_val = strtol(val, &endptr, 10);
    if (!endptr) { // val was a valid long int
      val_obj = co_int32_create(int_val,0);
      CHECK_MEM(val_obj);
    } else { // val treated as string or hex
      val_obj = co_str8_create(val, strlen(val) + 1, 0);
      CHECK_MEM(val_obj);
    }
  }
  return val_obj;
error:
  return NULL;
}

/**
 * Reads services from UCI to import into service list, once
 * the mDNS server is ready. Validates each service against the
 * service schema before accepting.
 */
void
uci_read(AvahiTimeout *t, void *userdata)
{
  csm_ctx *ctx = (csm_ctx*)userdata;
  co_obj_t *ctx_obj = NULL;
  struct uci_context *c = NULL;
  co_obj_t *fields = NULL,
	   *params = NULL,
	   *verdict = NULL,
	   *val_obj = NULL,
	   *list = NULL;
  struct uci_package *pkg = NULL;
  int local = 0;
  
  CHECK(ctx && ctx->service_list, "Uninitialized context");
  
  c = uci_alloc_context();
  CHECK_MEM(c);
  
  uci_set_confdir(c, getenv("UCI_INSTANCE_PATH") ? : UCIPATH);
  
  uci_load(c, "applications", &pkg);
  CHECK(pkg, "Failed to load applications");
  struct uci_element *e = NULL;
  struct uci_list *section_list = &pkg->sections;
  uci_foreach_element(section_list, e) {
    struct uci_section *section = uci_to_section(e);
    if (strcmp(section->type,"application") == 0) {
      fields = co_tree16_create();
      CHECK_MEM(fields);
      struct uci_list *option_list = &section->options;
      struct uci_element *o = NULL;
      uci_foreach_element(option_list, o) {
	struct uci_option *option = uci_to_option(o);
	char *key = o->name, *val = NULL;
	if (option->type == UCI_TYPE_STRING) {
	  val = option->v.string;
	  if (strcmp(key, "local") == 0 && strcmp(val,"1") == 0)
	    local = 1;
	  val_obj = _csm_store_uci_field(key, val, ctx);
	  if (!val_obj)
	    continue;
	  CHECK(co_tree_insert(fields, key, strlen(key) + 1, val_obj),
		"Failed to add field to imported service");
	  DEBUG("Read service field %s : %s", key, val);
	  val_obj = NULL;
	} else { // option->type == UCI_TYPE_LIST
	  struct uci_element *l = NULL;
	  list = co_tree_find(fields, key, strlen(key) + 1);
	  if (!list) {
	    list = co_list16_create();
	    CHECK_MEM(list);
	  }
	  uci_foreach_element(&option->v.list, l) {
	    val = l->name;
	    val_obj = _csm_store_uci_field(key, val, ctx);
	    if (!val_obj)
	      continue;
	    CHECK(co_list_append(list, val_obj),
		  "Failed to add list field to new service");
	    DEBUG("Read service list field %s : %s", key, val);
	    val_obj = NULL;
	  }
	  if (co_list_length(list) > 0)
	    CHECK(co_tree_insert(fields, key, strlen(key) + 1, list),
		  "Failed to add list field to new service");
	  else
	    co_obj_free(list);
	  list = NULL;
	}
      }
      verdict = NULL;
      params = co_list16_create();
      CHECK_MEM(params);
      ctx_obj = co_ctx_create(ctx);
      CHECK_MEM(ctx_obj);
      CHECK(co_list_append(params, ctx_obj), "Failed to append ctx to command params");
      CHECK(co_list_append(params, fields), "Failed to append service fields to command params");
      fields = NULL;
      co_obj_t *local_obj = co_bool_create(local,0);
      CHECK_MEM(local_obj);
      CHECK(co_list_append(params, local_obj), "Failed to append local to command params");
      CHECK(cmd_commit_service(NULL, &verdict, params), "Failed to commit service from UCI");
      bool result;
      CHECK(co_response_get_bool(verdict, &result, "success", sizeof("success")),
	    "Failed to fetch result from command");
      if (!result) { // perhaps service didn't validate against schema, don't want to hard error here
	WARN("Error committing service %s from UCI", e->name);
      } else {
	char *key = NULL;
	CHECK(co_response_get_str(verdict, &key, "key", sizeof("key")) != -1,
	      "Failed to fetch key from response");
	INFO("Successfully added local service with key %s", key);
      }
    }
  }
  
error:
  if (c)
    uci_free_context(c);
  if (fields)
    co_obj_free(fields);
  if (params)
    co_obj_free(params);
  if (verdict)
    co_obj_free(verdict);
  if (val_obj)
    co_obj_free(val_obj);
  if (list)
    co_obj_free(list);
}

struct uci_write_ctx {
  char *uuid;
  struct uci_context *c;
  int (*uci_setter)(struct uci_context *ctx, struct uci_ptr *ptr);
};

static void
_csm_write_uci_field(co_obj_t *container, co_obj_t *key, co_obj_t *val, void *context)
{
  char *val_str = NULL;
  struct uci_write_ctx *uci_ctx = (struct uci_write_ctx*)context;
  struct uci_context *c = uci_ctx->c;
  struct uci_ptr sec_ptr = {0};
  sec_ptr.package = "applications";
  sec_ptr.section = uci_ctx->uuid;
  sec_ptr.option = co_obj_data_ptr(key);
  if (IS_INT(val)) {
    CHECK_MEM(asprintf(&val_str, "%"PRId32, ((co_int32_t*)val)->data) != -1);
    sec_ptr.value = val_str;
    UCI_CHECK(uci_ctx->uci_setter(uci_ctx->c, &sec_ptr) == UCI_OK, 
	      "Failed to set UCI field %s", val_str);
  } else if (IS_STR(val)) {
    sec_ptr.value = co_obj_data_ptr(val);
    UCI_CHECK(uci_ctx->uci_setter(uci_ctx->c, &sec_ptr) == UCI_OK, 
	      "Failed to set UCI field %s", co_obj_data_ptr(val));
  } else { // IS_LIST
    uci_ctx->uci_setter = uci_add_list;
    csm_list_parse(val, key, _csm_write_uci_field, context);
    uci_ctx->uci_setter = uci_set;
  }
  
error:
  if (val_str)
    free(val_str);
}

int
uci_write(csm_service *s)
{
  struct uci_context *c = NULL;
  struct uci_ptr sec_ptr,sig_ptr;
#ifdef OPENWRT
  struct uci_ptr approved_ptr;
#endif
  int ret = 0;
  struct uci_package *pak = NULL;
  
  assert(s);
  
  c = uci_alloc_context();
  CHECK_MEM(c);
  
  uci_set_confdir(c, getenv("UCI_INSTANCE_PATH") ? : UCIPATH);

  /* Lookup application by name (concatenation of URI + port) */
  CHECK(get_uci_section(c,
			&sec_ptr,
			"applications",
			strlen("applications"),
			s->uuid,
			strlen(s->uuid),
			NULL,
			0) > 0,
	"Failed application lookup");
  if (sec_ptr.flags & UCI_LOOKUP_COMPLETE) {
    INFO("Found application: %s",s->uuid);
    // check for service == fingerprint. if sig different, update it
    CHECK(get_uci_section(c,
			  &sig_ptr,
			  "applications",
			  strlen("applications"),
			  s->uuid,
			  strlen(s->uuid),
			  "signature",
			  strlen("signature")) > 0,
	  "Failed signature lookup");
    if (sig_ptr.flags & UCI_LOOKUP_COMPLETE && s->signature && strcmp(s->signature,sig_ptr.o->v.string) == 0) {
      // signatures equal: do nothing
      INFO("Signature the same, not updating");
      ret = 1;
      goto error;
    }
    // signatures differ: delete existing app
    INFO("Signature differs, updating");
    UCI_CHECK(uci_delete(c, &sec_ptr) == UCI_OK,
	      "Failed to delete out-of-date application from UCI");
  } else {
    INFO("Application not found, creating");
  }
  
  pak = sec_ptr.p;
  memset(&sec_ptr, 0, sizeof(struct uci_ptr));
  
  // uci_add_section
  sec_ptr.package = "applications";
  sec_ptr.section = s->uuid;
  sec_ptr.value = "application";
  UCI_CHECK(uci_set(c, &sec_ptr) == UCI_OK,"Failed to set section");
  INFO("Section set succeeded");
  
  // parse elements of s->field
  struct uci_write_ctx uci_ctx = {
    .uuid = s->uuid,
    .c = c,
    .uci_setter = uci_set
  };
  CHECK(csm_tree_process(s->fields, _csm_write_uci_field, &uci_ctx),
	"Failed to write service fields into UCI");
  
  if (s->local)
    UCI_SET(c,s,local,"1");
  
#ifdef OPENWRT
  // For OpenWRT: check known_applications list, approved or blacklisted
  if (get_uci_section(c,
		      &approved_ptr,
		      "applications",
		      strlen("applications"),
		      "known_apps",
		      strlen("known_apps"),
		      s->uuid,
		      strlen(s->uuid)) == -1) {
    WARN("Failed known_apps lookup");
  } else if (approved_ptr.flags & UCI_LOOKUP_COMPLETE) {
    if (strcmp(approved_ptr.o->v.string,"approved") == 0) {
      UCI_SET(c, s, approved, "1");
    } else if (strcmp(approved_ptr.o->v.string,"blacklisted") == 0) {
      UCI_SET(c, s, approved, "0");
    }
  } else { // not in known_apps table, so check for autoapprove
    if (get_uci_section(c,
			&approved_ptr,
			"applications",
			strlen("applications"),
			"settings",
			strlen("settings"),
			"autoapprove",
			strlen("autoapprove")) == -1) {
      WARN("Failed autoapprove lookup");
    } else if (approved_ptr.flags & UCI_LOOKUP_COMPLETE) {
      if (strcmp(approved_ptr.o->v.string,"1") == 0) {
	UCI_SET(c, s, approved, "1");
	struct uci_ptr *known_apps = NULL;
	if (get_uci_section(c,
			    &known_apps,
			    "applications",
			    strlen("applications"),
			    "known_apps",
			    strlen("known_apps"),
			    NULL, 
			    0) != -1
	    && known_apps.flags ~& UCI_LOOKUP_COMPLETE) {
	  // add known_apps section
	  memset(&sec_ptr, 0, sizeof(struct uci_ptr));
	  sec_ptr.package = "applications";
	  sec_ptr.section = "known_apps";
	  sec_ptr.value = "known_apps";
	  UCI_CHECK(uci_set(c, &sec_ptr) == UCI_OK,"Failed to add known_apps section");
	  UCI_CHECK(uci_save(c, sec_ptr.p) == UCI_OK,"Failed to save");
	}
	memset(&sec_ptr, 0, sizeof(struct uci_ptr));
	sec_ptr.package = "applications";
	sec_ptr.section = "known_apps";
	sec_ptr.option = s->uuid;
	sec_ptr.value = "approved";
	int uci_ret = uci_set(c, &sec_ptr);
	UCI_CHECK(uci_ret == UCI_OK,"Failed to set known_apps entry for service %s", s->uuid);
      }
    }
  }
#else
  UCI_SET(c, s, approved, "1");
#endif
  
  // uci_save
  UCI_CHECK(uci_save(c, pak) == UCI_OK,"Failed to save");
  INFO("Save succeeded");
  
  UCI_CHECK(uci_commit(c,&pak,false) == UCI_OK,"Failed to commit");
  INFO("Commit succeeded");

  ret = 1;
  
error:
  if (c) uci_free_context(c);
  return ret;
}

/**
 * Remove a service from UCI
 * @param i ServiceInfo object of the service
 * @return 0=success, -1=fail
 */
int uci_remove(csm_service *s) {
  int ret = -1;
  struct uci_context *c = NULL;
  struct uci_ptr sec_ptr;
  struct uci_package *pak = NULL;
  
  assert(s);
  
  c = uci_alloc_context();
  CHECK_MEM(c);
  uci_set_confdir(c, getenv("UCI_INSTANCE_PATH") ? : UCIPATH);
  
  /* Lookup application by UUID */
  CHECK(get_uci_section(c,
			&sec_ptr,
			"applications",
			strlen("applications"),
			s->uuid,
			strlen(s->uuid),
			NULL,
			0) > 0,
	"(UCI_Remove) Failed application lookup");
  
  CHECK(sec_ptr.flags & UCI_LOOKUP_COMPLETE,"(UCI_Remove) Application not found: %s",s->uuid);
  INFO("(UCI_Remove) Found application: %s",s->uuid);
  
  UCI_CHECK(uci_delete(c, &sec_ptr) == UCI_OK,"(UCI_Remove) Failed to delete application");
  INFO("(UCI_Remove) Successfully deleted application");
  
  pak = sec_ptr.p;
  
  // uci_save
  UCI_CHECK(uci_save(c, pak) == UCI_OK,"(UCI_Remove) Failed to save");
  INFO("(UCI_Remove) Save succeeded");
  
  UCI_CHECK(uci_commit(c,&pak,false) == UCI_OK,"(UCI_Remove) Failed to commit");
  INFO("(UCI_Remove) Commit succeeded");
  
  ret = 0;
  
error:
  if (c) uci_free_context(c);
  return ret;
}

/** Fetch default lifetime from UCI
 * @return if applications.settings.allowpermanent==0, returns default lifetime
 */
long default_lifetime(void) {
  long lifetime = 0;
#ifdef USE_UCI
  struct uci_ptr allow, exp;
  struct uci_context *c = uci_alloc_context();
  
  CHECK(get_uci_section(c,
			&allow,
			"applications",
			strlen("applications"),
			"settings",
			strlen("settings"),
			"allowpermanent",
			strlen("allowpermanent")) > 0
	  && allow.flags & UCI_LOOKUP_COMPLETE, 
	"Failed settings lookup");
  
  if (strcmp(allow.o->v.string,"0") == 0) {  // force applications to expire
    CHECK(get_uci_section(c,
			  &exp,
			  "applications",
			  strlen("applications"),
			  "settings",
			  strlen("settings"),
			  "lifetime",
			  strlen("lifetime")) > 0
	    && exp.flags & UCI_LOOKUP_COMPLETE,
	  "Failed settings lookup");
    CHECK(isNumeric(exp.o->v.string) && atol(exp.o->v.string) >= 0,
	  "Invalid default lifetime");
    lifetime = atol(exp.o->v.string);
  }
  
error:
  if (c) uci_free_context(c);
#endif
  return lifetime;
}