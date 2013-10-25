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

/**
 * Derives the UCI-encoded name of a service, as a concatenation of IP address/URL and port
 * @param i ServiceInfo object of the service
 * @param[out] name_len Length of the UCI-encoded name
 * @return UCI-encoded name
 */
char *get_name(ServiceInfo *i, size_t *name_len) {
  char *uci_name = NULL;
  char *ip = NULL;
  char *ip_escaped = NULL;
  char port[6] = "";
  size_t ip_escaped_len, ip_len = 0;
  
  assert(i);
  
  avahi_string_list_get_pair(avahi_string_list_find(i->txt_lst,"ipaddr"),NULL,&ip,&ip_len);
  ip_escaped = uci_escape(ip,ip_len,&ip_escaped_len);
  if (i->port > 0)
    sprintf(port,"%d",i->port);
  uci_name = (char*)calloc(ip_escaped_len + strlen(port),sizeof(char));
  strncpy(uci_name,ip_escaped,ip_escaped_len);
  strcat(uci_name,port);
  *name_len = ip_escaped_len + strlen(port);
  
  free(ip_escaped);
  return uci_name;
}

/**
 * Write a service to UCI
 * @param i ServiceInfo object of the service
 * @return 0=success, 1=fail
 */
int uci_write(ServiceInfo *i) {
  struct uci_context *c = NULL;
  struct uci_ptr sec_ptr,sig_ptr,type_ptr;
  int uci_ret, ret = 1;
  char *sec_name = NULL;
  char *sig_opstr = NULL;
  char *type_opstr = NULL;
  char *sig = NULL;
  struct uci_package *pak = NULL;
  struct uci_section *sec = NULL;
  AvahiStringList *txt;
  size_t sig_len;
  char *uci_name = NULL;
  size_t uci_name_len = 0;
  struct uci_element *e;
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
  
  uci_name = get_name(i,&uci_name_len);

  CHECK(sig_len == SIG_LENGTH &&
      isHex(sig,sig_len),
      "(UCI) Invalid signature txt field");
  
  /* Lookup application by name (concatenation of ip + port) */
  sec_name = (char*)calloc(13 + uci_name_len + 1,sizeof(char));
  strcpy(sec_name,"applications.");
  strncat(sec_name,uci_name, uci_name_len);
  sec_name[13 + uci_name_len] = '\0';
  
  UCI_CHECK(uci_lookup_ptr(c, &sec_ptr, sec_name, false) == UCI_OK,"(UCI) Failed application lookup: %s",uci_name);
  
  if (sec_ptr.flags & UCI_LOOKUP_COMPLETE) {
    INFO("(UCI) Found application: %s",uci_name);
    // check for service == fingerprint. if sig different, update it
    // NOTE: sec_name is modified by uci_lookup_ptr above, so cannot cpy it into sig_opstr
    sig_opstr = (char*)calloc(13 + uci_name_len + 10 + 1,sizeof(char));
    strcpy(sig_opstr,"applications.");
    strncat(sig_opstr,uci_name,uci_name_len);
    strcat(sig_opstr,".signature");
    UCI_CHECK(uci_lookup_ptr(c, &sig_ptr, sig_opstr, false) == UCI_OK,"(UCI) Failed signature lookup");
    if (sig_ptr.flags & UCI_LOOKUP_COMPLETE && sig && !strcmp(sig,sig_ptr.o->v.string)) {
      // signatures equal: do nothing
      INFO("(UCI) Signature the same, not updating");
      uci_free_context(c);
      return 0;
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
  sec_ptr.section = uci_name;
  sec_ptr.value = "application";
  UCI_CHECK(!uci_set(c, &sec_ptr),"(UCI) Failed to set section");
  INFO("(UCI) Section set succeeded");
  
  /* set type_opstr to lookup the 'type' fields */
  type_opstr = (char*)calloc(13 + uci_name_len + 5 + 1,sizeof(char));
  strcpy(type_opstr,"applications.");
  strncpy(type_opstr + 13, uci_name, uci_name_len);
  strcpy(type_opstr + 13 + uci_name_len,".type");
  UCI_CHECK(uci_lookup_ptr(c, &type_ptr, type_opstr, false) == UCI_OK,"(UCI) Failed type lookup");
  
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
      if (!strcmp(sec_ptr.option,"application"))
	sec_ptr.option = "name";
      uci_ret = uci_set(c, &sec_ptr);
    }
    UCI_CHECK(!uci_ret,"(UCI) Failed to set");
    INFO("(UCI) Set succeeded: %s=%s",sec_ptr.option,sec_ptr.value);
  } while (txt = avahi_string_list_get_next(txt));
  
  // set uuid and approved fields
  sec_ptr.option = "uuid";
  sec_ptr.value = uci_name;
  uci_ret = uci_set(c, &sec_ptr);
  UCI_CHECK(!uci_ret,"(UCI) Failed to set");
  INFO("(UCI) Set succeeded: %s=%s",sec_ptr.option,sec_ptr.value);
  sec_ptr.option = "approved";
  sec_ptr.value = "1";
  uci_ret = uci_set(c, &sec_ptr);
  UCI_CHECK(!uci_ret,"(UCI) Failed to set");
  INFO("(UCI) Set succeeded: %s=%s",sec_ptr.option,sec_ptr.value);
  
  // if no type fields in new announcement, remove section from UCI (part of stupid workaround)
  if (type_state == NO_TYPE_SECTION)
    UCI_CHECK(uci_delete(c, &type_ptr) == UCI_OK,"(UCI) Failed to delete type section");
  
  // uci_save
  UCI_CHECK(uci_save(c, pak) == UCI_OK,"(UCI) Failed to save");
  INFO("(UCI) Save succeeded");
  
  UCI_CHECK(uci_commit(c,&pak,false) == UCI_OK,"(UCI) Failed to commit");
  INFO("(UCI) Commit succeeded");

  ret = 0;
  
error:
  if (c) uci_free_context(c);
  if (type_opstr) free(type_opstr);
  if (sig_opstr) free(sig_opstr);
  if (sec_name) free(sec_name);
  if (uci_name) free(uci_name);
  return ret;
}

/**
 * Remove a service from UCI
 * @param i ServiceInfo object of the service
 * @return 0=success, 1=fail
 */
int uci_remove(ServiceInfo *i) {
  int ret = 1;
  struct uci_context *c = NULL;
  struct uci_ptr sec_ptr;
  struct uci_package *pak = NULL;
  char *sec_name = NULL;
  char *uci_name = NULL;
  size_t uci_name_len = 0;
  
  c = uci_alloc_context();
  uci_set_confdir(c, getenv("UCI_INSTANCE_PATH") ? : UCIPATH);
  assert(c);
  assert(i);
  
  uci_name = get_name(i,&uci_name_len);
  
  /* Lookup application by name (concatination of ip + port) */
  sec_name = (char*)calloc(13 + uci_name_len + 1,sizeof(char));
  strcpy(sec_name,"applications.");
  strncat(sec_name,uci_name, uci_name_len);
  sec_name[13 + uci_name_len] = '\0';
  
  UCI_CHECK(uci_lookup_ptr(c, &sec_ptr, sec_name, false) == UCI_OK,"(UCI_Remove) Failed application lookup: %s", sec_name);
  
  CHECK(sec_ptr.flags & UCI_LOOKUP_COMPLETE,"(UCI_Remove) Application not found: %s",uci_name);
  INFO("(UCI_Remove) Found application: %s",uci_name);
  
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
  if (uci_name) free(uci_name);
  if (sec_name) free(sec_name);
  return ret;
}