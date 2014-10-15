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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef USESYSLOG
#include <syslog.h>
#endif

#include <uci.h>

#include <commotion/debug.h>
#include <commotion/obj.h>
#include <commotion/list.h>
#include <commotion/tree.h>
#include <commotion.h>

#include "defs.h"
#include "util.h"
#include "cmd.h"
#include "schema.h"
#include "uci-utils.h"

#define UCI_CHECK(A, M, ...) if(!(A)) { char *err = NULL; uci_get_errorstr(c,&err,NULL); ERROR(M ": %s", ##__VA_ARGS__, err); free(err); errno=0; goto error; }
#define UCI_WARN(M, ...) char *err = NULL; uci_get_errorstr(c,&err,NULL); WARN(M ": %s", ##__VA_ARGS__, err); free(err);
#define _UCI_SET(F,C,SRV,FLD,VAL) \
  do { \
    struct uci_ptr sec_ptr = {0}; \
    sec_ptr.package = "applications"; \
    sec_ptr.section = SRV->uuid; \
    sec_ptr.option = #FLD; \
    sec_ptr.value = VAL; \
    int uci_ret = F(C, &sec_ptr); \
    UCI_CHECK(uci_ret == 0,"Failed to set UCI field " #FLD); \
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
int get_uci_section(struct uci_context *c,
		    struct uci_ptr *sec_ptr,
		    const char *file, 
		    const size_t file_len,
		    const char *sec, 
		    const size_t sec_len,
		    const char *op,
		    const size_t op_len) {
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
  
  UCI_CHECK(uci_lookup_ptr(c, sec_ptr, lookup_str, false) == UCI_OK,"(UCI) Failed section lookup: %s",lookup_str);
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
  if (field) {
    switch (field->type) {
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
//   int ret = 0;
  CHECK(ctx && ctx->service_list, "Uninitialized context");
  struct uci_context *c = NULL;
  struct uci_package *pkg = NULL;
  co_obj_t *fields = NULL, *params = NULL, *verdict = NULL, *val_obj = NULL;
  
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
	  val_obj = _csm_store_uci_field(key, val, ctx);
	  CHECK(co_tree_insert(fields, key, strlen(key) + 1, val_obj), "Failed to add field to imported service");
	  DEBUG("Read service field %s : %s", key, val);
	  co_obj_free(val_obj);
	  val_obj = NULL;
	} else { // option->type == UCI_TYPE_LIST
	  struct uci_element *l = NULL;
	  co_obj_t *list = co_tree_find(fields, key, strlen(key) + 1);
	  if (!list) {
	    list = co_list16_create();
	    CHECK_MEM(list);
	  }
	  uci_foreach_element(&option->v.list, l) {
	    val = l->name;
	    val_obj = _csm_store_uci_field(key, val, ctx);
	    CHECK(co_list_append(list, val_obj), "Failed to add list field to new service");
	    DEBUG("Read service list field %s : %s", key, val);
	    co_obj_free(val_obj);
	    val_obj = NULL;
	  }
	  CHECK(co_tree_insert(fields, key, strlen(key) + 1, list), "Failed to add list field to new service");
	}
      }
      // if service has local=1, create co_list = [ctx, service_fields] and call cmd_commit_service() (which will do validation against schema)
      co_obj_t *local = co_tree_find(fields,"local",sizeof("local"));
      if (local && strcmp(co_obj_data_ptr(local), "1") == 0) {
	verdict = NULL;
	params = co_list16_create();
	CHECK_MEM(params);
	co_obj_t *ctx_obj = co_ctx_create(ctx);
	CHECK_MEM(ctx_obj);
	CHECK(co_list_append(params, ctx_obj), "Failed to append ctx to command params");
	CHECK(co_list_append(params, fields), "Failed to append service fields to command params");
	fields = NULL;
	CHECK(cmd_commit_service(NULL, &verdict, params), "Failed to commit service from UCI");
	bool result;
	CHECK(co_response_get_bool(verdict, &result, "success", sizeof("success")), "Failed to fetch result from command");
	if (!result) { // perhaps service didn't validate against schema, don't want to hard error here
	  WARN("Error committing service %s from UCI", e->name);
	} else {
	  char *key = NULL;
	  CHECK(co_response_get_str(verdict, &key, "key", sizeof("key")), "Failed to fetch key from response");
	  INFO("Successfully added local service with key %s", key);
	}
      }
    }
  }
  
//   ret = 1;
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
//   return ret;
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
  int uci_ret = -1;
  struct uci_write_ctx *uci_ctx = (struct uci_write_ctx*)context;
  struct uci_context *c = uci_ctx->c;
  struct uci_ptr sec_ptr = {0};
  sec_ptr.package = "applications";
  sec_ptr.section = uci_ctx->uuid;
  sec_ptr.option = co_obj_data_ptr(key);
  if (IS_INT(val)) {
    CHECK_MEM(asprintf(&val_str, "%ld", (long)*co_obj_data_ptr(val)) != -1);
    sec_ptr.value = val_str;
    uci_ret = uci_ctx->uci_setter(uci_ctx->c, &sec_ptr);
    UCI_CHECK(uci_ret == 0, "Failed to set UCI field %s", val_str);
  } else if (IS_STR(val)) {
    sec_ptr.value = co_obj_data_ptr(val);
    uci_ret = uci_ctx->uci_setter(uci_ctx->c, &sec_ptr);
    UCI_CHECK(uci_ret == 0, "Failed to set UCI field %s", co_obj_data_ptr(val));
  } else { // IS_LIST
    uci_ctx->uci_setter = uci_add_list;
    csm_list_parse(val, key, _csm_write_uci_field, context);
    uci_ctx->uci_setter = uci_set;
  }
  
error:
  if (val_str)
    free(val_str);
}

int uci_write(csm_service *s) {
  struct uci_context *c = NULL;
  struct uci_ptr sec_ptr,sig_ptr;
#ifdef OPENWRT
  struct uci_ptr approved_ptr;
#endif
  int ret = 0;
  struct uci_package *pak = NULL;
//   struct uci_element *e = NULL;
#if 0
  enum {
    NO_TYPE_SECTION,
    NO_TYPE_MATCHES,
    TYPE_MATCH_FOUND,
  };
  int type_state = NO_TYPE_SECTION;
#endif
  
  assert(s);
  
  c = uci_alloc_context();
  CHECK_MEM(c);
  
  uci_set_confdir(c, getenv("UCI_INSTANCE_PATH") ? : UCIPATH);

  /* Lookup application by name (concatenation of URI + port) */
  CHECK(get_uci_section(c,&sec_ptr,"applications",12,s->uuid,strlen(s->uuid),NULL,0) > 0, "Failed application lookup");
  if (sec_ptr.flags & UCI_LOOKUP_COMPLETE) {
    INFO("(UCI) Found application: %s",s->uuid);
    // check for service == fingerprint. if sig different, update it
    CHECK(get_uci_section(c,&sig_ptr,"applications",12,s->uuid,strlen(s->uuid),"signature",9) > 0,"Failed signature lookup");
    if (sig_ptr.flags & UCI_LOOKUP_COMPLETE && s->signature && !strcmp(s->signature,sig_ptr.o->v.string)) {
      // signatures equal: do nothing
      INFO("(UCI) Signature the same, not updating");
      ret = 1;
      goto error;
    }
    // signatures differ: delete existing app
    INFO("(UCI) Signature differs, updating");
    UCI_CHECK(uci_delete(c, &sec_ptr), "Failed to delete out-of-date application from UCI");
  } else {
    INFO("(UCI) Application not found, creating");
  }
  
  pak = sec_ptr.p;
  memset(&sec_ptr, 0, sizeof(struct uci_ptr));
  
  // uci_add_section
  sec_ptr.package = "applications";
  sec_ptr.section = s->uuid;
  sec_ptr.value = "application";
  UCI_CHECK(!uci_set(c, &sec_ptr),"(UCI) Failed to set section");
  INFO("(UCI) Section set succeeded");
  
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
  
#if 0
  // uci set options/values
  UCI_SET_STR(c,s,name);
  UCI_SET_STR(c,s,uri);
  UCI_SET_STR(c,s,description);
  UCI_SET_STR(c,s,icon);
  UCI_SET_STR(c,s,signature);
  UCI_SET(c,s,fingerprint,csm_service_get_key(s));
  UCI_SET_STR(c,s,version);
  UCI_SET(c,s,uuid,s->uuid);
  if (s->local)
    UCI_SET(c,s,local,"1");
  
  char *ttl_str = NULL, *lifetime_str = NULL;
  CHECK_MEM(asprintf(&ttl_str, "%d", csm_service_get_ttl(s)) != -1);
  CHECK_MEM(asprintf(&lifetime_str, "%ld", csm_service_get_lifetime(s)) != -1);
  UCI_SET(c,s,ttl,ttl_str);
  UCI_SET(c,s,lifetime,lifetime_str);
  
  /* set type_ptr to lookup the 'type' list */
  co_obj_t *cat_obj = csm_service_get_categories(s);
  if (cat_obj) {
  CHECK(get_uci_section(c,&type_ptr,"applications",12,s->uuid,strlen(s->uuid),"type",4) > 0,"Failed type lookup");
    for (int j = 0; j < co_list_length(cat_obj); j++) {
      // NOTE: the version of UCI packaged with LuCI doesn't have uci_del_list, so here's a workaround
      //uci_ret = uci_del_list(c, &sec_ptr);
      type_state = NO_TYPE_MATCHES;
      if (type_ptr.o && type_ptr.o->type == UCI_TYPE_LIST) {
	uci_foreach_element(&(type_ptr.o->v.list), e) {
	  if (!strcmp(e->name, _LIST_ELEMENT(cat_obj, j))) {
	    type_state = TYPE_MATCH_FOUND;
	    break;
	  }
	}
      }
      if (type_state != TYPE_MATCH_FOUND)
	UCI_SET_CAT(c, s, _LIST_ELEMENT(cat_obj, j));
    }
  }
#endif
  
#ifdef OPENWRT
  // For OpenWRT: check known_applications list, approved or blacklisted
  if (get_uci_section(c,&approved_ptr,"applications",12,"known_apps",10,s->uuid,strlen(s->uuid)) == -1) {
    WARN("(UCI) Failed known_apps lookup");
  } else if (approved_ptr.flags & UCI_LOOKUP_COMPLETE) {
    if (!strcmp(approved_ptr.o->v.string,"approved")) {
      UCI_SET(c, s, approved, "1");
    } else if (!strcmp(approved_ptr.o->v.string,"blacklisted")) {
      UCI_SET(c, s, approved, "0");
    }
  }
#else
  UCI_SET(c, s, approved, "1");
#endif
  
#if 0
  // if no type fields in new announcement, remove section from UCI (part of workaround)
  if (type_state == NO_TYPE_SECTION) {
    if (type_ptr.o && type_ptr.o->type == UCI_TYPE_LIST) {
      UCI_CHECK(uci_delete(c, &type_ptr) == UCI_OK,"(UCI) Failed to delete type section");
    }
  }
#endif
  
  // uci_save
  UCI_CHECK(uci_save(c, pak) == UCI_OK,"(UCI) Failed to save");
  INFO("(UCI) Save succeeded");
  
  UCI_CHECK(uci_commit(c,&pak,false) == UCI_OK,"(UCI) Failed to commit");
  INFO("(UCI) Commit succeeded");

  ret = 1;
  
error:
  if (c) uci_free_context(c);
#if 0
  if (ttl_str)
    free(ttl_str);
  if (lifetime_str)
    free(lifetime_str);
#endif
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
  CHECK(get_uci_section(c,&sec_ptr,"applications",12,s->uuid,strlen(s->uuid),NULL,0) > 0,
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
  
  CHECK(get_uci_section(c,&allow,"applications",12,"settings",8,"allowpermanent",14) > 0 &&
    allow.flags & UCI_LOOKUP_COMPLETE, "Failed settings lookup");
  
  if (strcmp(allow.o->v.string,"0") == 0) {  // force applications to expire
    CHECK(get_uci_section(c,&exp,"applications",12,"settings",8,"lifetime",8) > 0 &&
      exp.flags & UCI_LOOKUP_COMPLETE, "Failed settings lookup");
    CHECK(isNumeric(exp.o->v.string) && atol(exp.o->v.string) >= 0,"Invalid default lifetime");
    lifetime = atol(exp.o->v.string);
  }
  
error:
  if (c) uci_free_context(c);
#endif
  return lifetime;
}