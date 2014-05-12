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

#include "defs.h"
#include "uci-utils.h"
#include "util.h"

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
#define UCI_SET_STR(C,SRV,FLD) UCI_SET(C,SRV,FLD,csm_service_get_##FLD(SRV))
#define UCI_SET_CAT(C,SRV,CAT) _UCI_SET(uci_add_list,C,SRV,type,CAT)

static co_obj_t *
_uci_write_service(co_obj_t *list, co_obj_t *current, void *context)
{
  if (IS_LIST(current)) return NULL;
  assert(IS_SERVICE(current));
  co_service_t *s = (co_service_t*)current;
  CHECK(uci_write(s->service), "Failed to write service %s", s->service->uuid);
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

int uci_write(csm_service *s) {
  struct uci_context *c = NULL;
  struct uci_ptr sec_ptr,sig_ptr,type_ptr;
#ifdef OPENWRT
  struct uci_ptr approved_ptr;
#endif
  int ret = 0;
  struct uci_package *pak = NULL;
  struct uci_element *e = NULL;
  enum {
    NO_TYPE_SECTION,
    NO_TYPE_MATCHES,
    TYPE_MATCH_FOUND,
  };
  int type_state = NO_TYPE_SECTION;
  
  assert(s);
  
  c = uci_alloc_context();
  CHECK_MEM(c);
  
  uci_set_confdir(c, getenv("UCI_INSTANCE_PATH") ? : UCIPATH);

  /* Lookup application by name (concatenation of URI + port) */
  CHECK(get_uci_section(c,&sec_ptr,"applications",12,s->uuid,strlen(s->uuid),NULL,0) > 0, "Failed application lookup");
  if (sec_ptr.flags & UCI_LOOKUP_COMPLETE) {
    INFO("(UCI) Found application: %s",s->uuid);
    // check for service == fingerprint. if sig different, update it
    char *signature = csm_service_get_signature(s);
    CHECK(get_uci_section(c,&sig_ptr,"applications",12,s->uuid,strlen(s->uuid),"signature",9) > 0,"Failed signature lookup");
    if (sig_ptr.flags & UCI_LOOKUP_COMPLETE && signature && !strcmp(signature,sig_ptr.o->v.string)) {
      // signatures equal: do nothing
      INFO("(UCI) Signature the same, not updating");
      ret = 1;
      goto error;
    }
    // signatures differ: delete existing app
    INFO("(UCI) Signature differs, updating");
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
  
  // uci set options/values
  UCI_SET_STR(c,s,name);
  UCI_SET_STR(c,s,uri);
  UCI_SET_STR(c,s,description);
  UCI_SET_STR(c,s,icon);
  UCI_SET_STR(c,s,signature);
  UCI_SET(c,s,fingerprint,csm_service_get_key(s));
  UCI_SET_STR(c,s,version);
  UCI_SET(c,s,uuid,s->uuid);
  
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
  
  // if no type fields in new announcement, remove section from UCI (part of workaround)
  if (type_state == NO_TYPE_SECTION) {
    if (type_ptr.o && type_ptr.o->type == UCI_TYPE_LIST) {
      UCI_CHECK(uci_delete(c, &type_ptr) == UCI_OK,"(UCI) Failed to delete type section");
    }
  }
  
  // uci_save
  UCI_CHECK(uci_save(c, pak) == UCI_OK,"(UCI) Failed to save");
  INFO("(UCI) Save succeeded");
  
  UCI_CHECK(uci_commit(c,&pak,false) == UCI_OK,"(UCI) Failed to commit");
  INFO("(UCI) Commit succeeded");

  ret = 0;
  
error:
  if (c) uci_free_context(c);
  if (ttl_str)
    free(ttl_str);
  if (lifetime_str)
    free(lifetime_str);
  return ret;
}

#if 0
/**
 * Write a service to UCI
 * @param i ServiceInfo object of the service
 * @return 0=success, -1=fail
 */
int uci_write(ServiceInfo *i) {
  struct uci_context *c = NULL;
  struct uci_ptr sec_ptr,sig_ptr,type_ptr;
#ifdef OPENWRT
  struct uci_ptr approved_ptr;
#endif
  int ret = 0;
  struct uci_package *pak = NULL;
  struct uci_element *e = NULL;
  enum {
    NO_TYPE_SECTION,
    NO_TYPE_MATCHES,
    TYPE_MATCH_FOUND,
  };
  int type_state = NO_TYPE_SECTION;
  
  assert(i);
  
  c = uci_alloc_context();
  CHECK_MEM(c);
  
  uci_set_confdir(c, getenv("UCI_INSTANCE_PATH") ? : UCIPATH);

  /* Lookup application by name (concatenation of URI + port) */
  CHECK(get_uci_section(c,&sec_ptr,"applications",12,i->uuid,strlen(i->uuid),NULL,0) > 0, "Failed application lookup");
  if (sec_ptr.flags & UCI_LOOKUP_COMPLETE) {
    INFO("(UCI) Found application: %s",i->uuid);
    // check for service == fingerprint. if sig different, update it
    CHECK(get_uci_section(c,&sig_ptr,"applications",12,i->uuid,strlen(i->uuid),"signature",9) > 0,"Failed signature lookup");
    if (sig_ptr.flags & UCI_LOOKUP_COMPLETE && i->signature && !strcmp(i->signature,sig_ptr.o->v.string)) {
      // signatures equal: do nothing
      INFO("(UCI) Signature the same, not updating");
      ret = 1;
      goto error;
    }
    // signatures differ: delete existing app
    INFO("(UCI) Signature differs, updating");
  } else {
    INFO("(UCI) Application not found, creating");
  }
  
  pak = sec_ptr.p;
  memset(&sec_ptr, 0, sizeof(struct uci_ptr));
  
  // uci_add_section
  sec_ptr.package = "applications";
  sec_ptr.section = i->uuid;
  sec_ptr.value = "application";
  UCI_CHECK(!uci_set(c, &sec_ptr),"(UCI) Failed to set section");
  INFO("(UCI) Section set succeeded");
  
  // uci set options/values
  UCI_SET_STR(c,i,name);
  UCI_SET_STR(c,i,uri);
  UCI_SET_STR(c,i,description);
  UCI_SET_STR(c,i,icon);
  UCI_SET_STR(c,i,signature);
  UCI_SET_STR(c,i,fingerprint);
  UCI_SET_STR(c,i,version);
  UCI_SET_STR(c,i,uuid);
  
  char *ttl_str = NULL, *lifetime_str = NULL;
  CHECK_MEM(asprintf(&ttl_str, "%d", i->ttl) != -1);
  CHECK_MEM(asprintf(&lifetime_str, "%ld", i->lifetime) != -1);
  UCI_SET(c,i,ttl,ttl_str);
  UCI_SET(c,i,lifetime,lifetime_str);
  
  /* set type_ptr to lookup the 'type' list */
  CHECK(get_uci_section(c,&type_ptr,"applications",12,i->uuid,strlen(i->uuid),"type",4) > 0,"Failed type lookup");
  for (int j = 0; j < i->cat_len; j++) {
    // NOTE: the version of UCI packaged with LuCI doesn't have uci_del_list, so here's a workaround
    //uci_ret = uci_del_list(c, &sec_ptr);
    type_state = NO_TYPE_MATCHES;
    if (type_ptr.o && type_ptr.o->type == UCI_TYPE_LIST) {
      uci_foreach_element(&(type_ptr.o->v.list), e) {
	if (!strcmp(e->name, i->categories[j])) {
	  type_state = TYPE_MATCH_FOUND;
	  break;
	}
      }
    }
    if (type_state != TYPE_MATCH_FOUND)
      UCI_SET_CAT(c, i, i->categories[j]);
  }
  
#ifdef OPENWRT
  // For OpenWRT: check known_applications list, approved or blacklisted
  if (get_uci_section(c,&approved_ptr,"applications",12,"known_apps",10,i->uuid,strlen(i->uuid)) == -1) {
    WARN("(UCI) Failed known_apps lookup");
  } else if (approved_ptr.flags & UCI_LOOKUP_COMPLETE) {
    if (!strcmp(approved_ptr.o->v.string,"approved")) {
      UCI_SET(c, i, approved, "1");
    } else if (!strcmp(approved_ptr.o->v.string,"blacklisted")) {
      UCI_SET(c, i, approved, "0");
    }
  }
#else
  UCI_SET(c, i, approved, "1");
#endif
  
  // if no type fields in new announcement, remove section from UCI (part of workaround)
  if (type_state == NO_TYPE_SECTION) {
    if (type_ptr.o && type_ptr.o->type == UCI_TYPE_LIST) {
      UCI_CHECK(uci_delete(c, &type_ptr) == UCI_OK,"(UCI) Failed to delete type section");
    }
  }
  
  // uci_save
  UCI_CHECK(uci_save(c, pak) == UCI_OK,"(UCI) Failed to save");
  INFO("(UCI) Save succeeded");
  
  UCI_CHECK(uci_commit(c,&pak,false) == UCI_OK,"(UCI) Failed to commit");
  INFO("(UCI) Commit succeeded");

  ret = 0;
  
error:
  if (c) uci_free_context(c);
  if (ttl_str)
    free(ttl_str);
  if (lifetime_str)
    free(lifetime_str);
  return ret;
}
#endif

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

#if 0
int uci_remove(ServiceInfo *i) {
  int ret = -1;
  struct uci_context *c = NULL;
  struct uci_ptr sec_ptr;
  struct uci_package *pak = NULL;
  
  c = uci_alloc_context();
  uci_set_confdir(c, getenv("UCI_INSTANCE_PATH") ? : UCIPATH);
  assert(c);
  assert(i);
  
  /* Lookup application by UUID */
  CHECK(get_uci_section(c,&sec_ptr,"applications",12,i->uuid,strlen(i->uuid),NULL,0) > 0, "(UCI_Remove) Failed application lookup");
  
  CHECK(sec_ptr.flags & UCI_LOOKUP_COMPLETE,"(UCI_Remove) Application not found: %s",i->uuid);
  INFO("(UCI_Remove) Found application: %s",i->uuid);
  
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
#endif

/** Determine if a service is local to this node
 * @param i ServiceInfo object of the service
 * @return 1=it's local, 0=it's not local, -1=error
 */
#if 0
int is_local(ServiceInfo *i) {
  struct uci_ptr local_ptr;
  int ret = -1;
  
  struct uci_context *c = uci_alloc_context();
  
  /* Make sure application isn't local to this node */
  CHECK(get_uci_section(c,&local_ptr,"applications",12,i->uuid,strlen(i->uuid),"localapp",8) > 0, "Failed application lookup");
  if (!(local_ptr.flags & UCI_LOOKUP_COMPLETE) || strcmp(local_ptr.o->v.string,"1") != 0) {
    INFO("Application NOT local");
    ret = 0;
  } else {
    INFO("Application is local");
    ret = 1;
  } 
  
error:
  if (c) uci_free_context(c);
  return ret;
}
#endif

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