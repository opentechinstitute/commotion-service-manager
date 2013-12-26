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

#include "uci-utils.h"
#include "debug.h"
#include "util.h"
#include "commotion-service-manager.h"

#define UCI_CHECK(A, M, ...) if(!(A)) { char *err = NULL; uci_get_errorstr(c,&err,NULL); ERROR(M ": %s", ##__VA_ARGS__, err); free(err); errno=0; goto error; }
#define UCI_WARN(M, ...) char *err = NULL; uci_get_errorstr(c,&err,NULL); WARN(M ": %s", ##__VA_ARGS__, err); free(err);

/**
 * Derives the UCI-encoded name of a service, as a concatenation of URI and port
 * @param i ServiceInfo object of the service
 * @param[out] uuid_len Length of the UCI-encoded name
 * @return UCI-encoded name
 */
char *get_uuid(ServiceInfo *i, size_t *uuid_len) {
  char *uuid = NULL;
  char *uri = NULL;
  char *uri_escaped = NULL;
  char port[6] = "";
  size_t uri_escaped_len, uri_len = 0;
  AvahiStringList *uri_txt = NULL;
  
  assert(i);
  
  CHECK((uri_txt = avahi_string_list_find(i->txt_lst,"uri")),"Failed to find uri txt record");
  avahi_string_list_get_pair(uri_txt,NULL,&uri,&uri_len);
  CHECK(uri && uri_len,"Failed to fetch uri txt record");
  CHECK((uri_escaped = uci_escape(uri,uri_len,&uri_escaped_len)),"Failed to escape URI");
  if (i->port > 0)
    sprintf(port,"%d",i->port);
  CHECK_MEM((uuid = (char*)calloc(uri_escaped_len + strlen(port),sizeof(char))));
  strncpy(uuid,uri_escaped,uri_escaped_len);
  strcat(uuid,port);
  *uuid_len = uri_escaped_len + strlen(port);

error:
  free(uri_escaped);
  return uuid;
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
 * Write a service to UCI
 * @param i ServiceInfo object of the service
 * @return 0=success, -1=fail
 */
int uci_write(ServiceInfo *i) {
  struct uci_context *c = NULL;
  struct uci_ptr sec_ptr,sig_ptr,type_ptr,approved_ptr;
  int uci_ret, ret = -1;
  char *sig = NULL, *uuid = NULL;
  struct uci_package *pak = NULL;
  struct uci_section *sec = NULL;
  struct uci_element *e = NULL;
  AvahiStringList *txt = NULL;
  size_t sig_len = 0, uuid_len = 0;
  enum {
    NO_TYPE_SECTION,
    NO_TYPE_MATCHES,
    TYPE_MATCH_FOUND,
  };
  int type_state = NO_TYPE_SECTION;
  
  c = uci_alloc_context();
  uci_set_confdir(c, getenv("UCI_INSTANCE_PATH") ? : UCIPATH);
  assert(c);
  assert(i);

  avahi_string_list_get_pair(avahi_string_list_find(i->txt_lst,"signature"),NULL,&sig,&sig_len);
  
  CHECK((uuid = get_uuid(i,&uuid_len)),"Failed to get UUID");

  CHECK(sig_len == SIG_LENGTH &&
      isHex(sig,sig_len),
      "(UCI) Invalid signature txt field");
  
  /* Lookup application by name (concatenation of URI + port) */
  CHECK(get_uci_section(c,&sec_ptr,"applications",12,uuid,uuid_len,NULL,0) > 0, "Failed application lookup");
  if (sec_ptr.flags & UCI_LOOKUP_COMPLETE) {
    INFO("(UCI) Found application: %s",uuid);
    // check for service == fingerprint. if sig different, update it
    CHECK(get_uci_section(c,&sig_ptr,"applications",12,uuid,uuid_len,"signature",9) > 0,"Failed signature lookup");
    if (sig_ptr.flags & UCI_LOOKUP_COMPLETE && sig && !strcmp(sig,sig_ptr.o->v.string)) {
      // signatures equal: do nothing
      INFO("(UCI) Signature the same, not updating");
      ret = 0;
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
  sec_ptr.section = uuid;
  sec_ptr.value = "application";
  UCI_CHECK(!uci_set(c, &sec_ptr),"(UCI) Failed to set section");
  INFO("(UCI) Section set succeeded");
  
  /* set type_opstr to lookup the 'type' fields */
  CHECK(get_uci_section(c,&type_ptr,"applications",12,uuid,uuid_len,"type",4) > 0,"Failed type lookup");
  
  // uci set options/values
  txt = i->txt_lst;
  do {
    if (avahi_string_list_get_pair(txt,(char **)&(sec_ptr.option),(char **)&(sec_ptr.value),NULL))
      continue;
    if (!strcmp(sec_ptr.option,"type")) {
      // NOTE: the version of UCI packaged with LuCI doesn't have uci_del_list, so here's a stupid workaround
      //uci_ret = uci_del_list(c, &sec_ptr);
      type_state = NO_TYPE_MATCHES;
      if (type_ptr.o && type_ptr.o->type == UCI_TYPE_LIST) {
	uci_foreach_element(&(type_ptr.o->v.list), e) {
	  if (!strcmp(e->name, sec_ptr.value)) {
	    type_state = TYPE_MATCH_FOUND;
	    break;
	  }
	}
      }
      if (type_state != TYPE_MATCH_FOUND)
	uci_ret = uci_add_list(c, &sec_ptr);
    } else {
      uci_ret = uci_set(c, &sec_ptr);
    }
    UCI_CHECK(!uci_ret,"(UCI) Failed to set");
    INFO("(UCI) Set succeeded: %s=%s",sec_ptr.option,sec_ptr.value);
  } while (txt = avahi_string_list_get_next(txt));
  
  // set uuid and approved fields
  sec_ptr.option = "uuid";
  sec_ptr.value = uuid;
  uci_ret = uci_set(c, &sec_ptr);
  UCI_CHECK(!uci_ret,"(UCI) Failed to set");
  INFO("(UCI) Set succeeded: %s=%s",sec_ptr.option,sec_ptr.value);

#ifdef OPENWRT
  // For OpenWRT: check known_applications list, approved or blacklisted
  if (get_uci_section(c,&approved_ptr,"applications",12,"known_apps",10,uuid,uuid_len) == -1) {
    WARN("(UCI) Failed known_apps lookup");
  } else if (approved_ptr.flags & UCI_LOOKUP_COMPLETE) {
    sec_ptr.option = "approved";
    if (!strcmp(approved_ptr.o->v.string,"approved")) {
      sec_ptr.value = "1";
    } else if (!strcmp(approved_ptr.o->v.string,"blacklisted")) {
      sec_ptr.value = "0";
    }
    uci_ret = uci_set(c, &sec_ptr);
    UCI_CHECK(!uci_ret,"(UCI) Failed to set");
    INFO("(UCI) Set succeeded: %s=%s",sec_ptr.option,sec_ptr.value);
  }
#else
  sec_ptr.option = "approved";
  sec_ptr.value = "1";
  uci_ret = uci_set(c, &sec_ptr);
  UCI_CHECK(!uci_ret,"(UCI) Failed to set");
  INFO("(UCI) Set succeeded: %s=%s",sec_ptr.option,sec_ptr.value);
#endif
  
  // if no type fields in new announcement, remove section from UCI (part of stupid workaround)
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
  if (uuid) free(uuid);
  return ret;
}

/**
 * Remove a service from UCI
 * @param i ServiceInfo object of the service
 * @return 0=success, -1=fail
 */
int uci_remove(ServiceInfo *i) {
  int ret = -1;
  struct uci_context *c = NULL;
  struct uci_ptr sec_ptr;
  struct uci_package *pak = NULL;
  char *uuid = NULL;
  size_t uuid_len = 0;
  
  c = uci_alloc_context();
  uci_set_confdir(c, getenv("UCI_INSTANCE_PATH") ? : UCIPATH);
  assert(c);
  assert(i);
  
  CHECK((uuid = get_uuid(i,&uuid_len)),"Failed to get UUID");
  
  /* Lookup application by name (concatination of URI + port) */
  CHECK(get_uci_section(c,&sec_ptr,"applications",12,uuid,uuid_len,NULL,0) > 0, "(UCI_Remove) Failed application lookup");
  
  CHECK(sec_ptr.flags & UCI_LOOKUP_COMPLETE,"(UCI_Remove) Application not found: %s",uuid);
  INFO("(UCI_Remove) Found application: %s",uuid);
  
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
  if (uuid) free(uuid);
  return ret;
}

/** Determine if a service is local to this node
 * @param i ServiceInfo object of the service
 * @return 1=it's local, 0=it's not local, -1=error
 */
int is_local(ServiceInfo *i) {
  struct uci_ptr local_ptr;
  char *uuid = NULL;
  size_t uuid_len = 0;
  int ret = -1;
  
  struct uci_context *c = uci_alloc_context();
  
  CHECK((uuid = get_uuid(i,&uuid_len)),"Failed to get UUID");
  
  /* Make sure application isn't local to this node */
  CHECK(get_uci_section(c,&local_ptr,"applications",12,uuid,uuid_len,"localapp",8) > 0, "Failed application lookup");
  if (!(local_ptr.flags & UCI_LOOKUP_COMPLETE) || strcmp(local_ptr.o->v.string,"1") != 0) {
    INFO("Application NOT local");
    ret = 0;
  } else {
    INFO("Application is local");
    ret = 1;
  } 
  
error:
  if (c) uci_free_context(c);
  if (uuid) free(uuid);
  return ret;
}