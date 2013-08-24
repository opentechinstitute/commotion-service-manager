#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef USESYSLOG
#include <syslog.h>
#endif

#include <uci.h>

#include "debug.h"
#include "commotion-service-manager.h"

int uci_remove(ServiceInfo *i) {
  int ret = 1;
  struct uci_context *c = NULL;
  struct uci_ptr sec_ptr;
  struct uci_package *pak = NULL;
  char *sid = NULL;
  char sec_name[78];
  char *key = NULL;
  size_t sid_len;
  
  avahi_string_list_get_pair(avahi_string_list_find(i->txt_lst,"fingerprint"),&key,&sid,&sid_len);
  CHECK(sid_len == FINGERPRINT_LEN && isHex(sid,sid_len),"Invalid fingerprint txt field");
  
  c = uci_alloc_context();
  assert(c);
  
  strcpy(sec_name,"applications.");
  strncat(sec_name,sid,FINGERPRINT_LEN);
  sec_name[77] = '\0';
  
  CHECK(uci_lookup_ptr(c, &sec_ptr, sec_name, false) == UCI_OK,"(UCI_Remove) Failed application lookup");
  
  CHECK(sec_ptr.flags & UCI_LOOKUP_COMPLETE,"(UCI_Remove) Application not found");
  INFO("(UCI_Remove) Found application");
  
  CHECK(uci_delete(c, &sec_ptr) != UCI_OK,"(UCI_Remove) Failed to delete application");
  INFO("(UCI_Remove) Successfully deleted application");
  
  pak = sec_ptr.p;
  
  // uci_save
  CHECK(!uci_save(c, pak),"(UCI_Remove) Failed to save");
  INFO("(UCI_Remove) Save succeeded");
  
  CHECK(!uci_commit(c,&pak,false),"(UCI_Remove) Failed to commit");
  INFO("(UCI_Remove) Commit succeeded");
  
  ret = 0;
  
error:
  if (c)
    uci_free_context(c);
  return ret;
}

int uci_write(ServiceInfo *i) {
  struct uci_context *c = NULL;
  struct uci_ptr sec_ptr,sig_ptr;
  int uci_ret, ret = 1;
  char sec_name[78], sig_opstr[88];
  char *key, *sig = NULL;
  char *sid = NULL;
  struct uci_package *pak = NULL;
  struct uci_section *sec = NULL;
  AvahiStringList *txt;
  size_t sid_len, sig_len;
  
  c = uci_alloc_context();
  assert(c);

  avahi_string_list_get_pair(avahi_string_list_find(i->txt_lst,"fingerprint"),&key,&sid,&sid_len);
  avahi_string_list_get_pair(avahi_string_list_find(i->txt_lst,"signature"),&key,&sig,&sig_len);

  CHECK(sid_len == FINGERPRINT_LEN &&
      sig_len == SIG_LENGTH &&
      isHex(sid,sid_len) &&
      isHex(sig,sig_len),
      "(UCI) Invalid signature or fingerprint txt fields");
  
  strcpy(sec_name,"applications.");
  strncat(sec_name,sid,FINGERPRINT_LEN);
  sec_name[77] = '\0';
  
  CHECK(uci_lookup_ptr(c, &sec_ptr, sec_name, false) == UCI_OK,"(UCI) Failed application lookup");
  
  if (sec_ptr.flags & UCI_LOOKUP_COMPLETE) {
    INFO("(UCI) Found application");
    // check for service == fingerprint. if sig different, update it
    strcpy(sig_opstr,"applications.");
    strncat(sig_opstr,sid,FINGERPRINT_LEN);
    strcat(sig_opstr,".signature");
    CHECK(uci_lookup_ptr(c, &sig_ptr, sig_opstr, false) == UCI_OK,"(UCI) Failed signature lookup");
    if (sig_ptr.flags & UCI_LOOKUP_COMPLETE && sig && !strcmp(sig,sig_ptr.o->v.string)) {
      // signatures equal: do nothing
      INFO("(UCI) Signature the same, not updating");
      uci_free_context(c);
      return 0;
    }
    // signatures differ: delete existing app
    INFO("(UCI) Signature differs, updating");
    CHECK(uci_delete(c, &sec_ptr) == UCI_OK,"(UCI) Failed to delete application");
  } else {
    INFO("(UCI) Application not found, creating");
  }

  pak = sec_ptr.p;
  memset(&sec_ptr, 0, sizeof(struct uci_ptr));
    
  // uci_add_section
  sec_ptr.package = "applications";
  sec_ptr.section = sid;
  sec_ptr.value = "application";
  CHECK(!uci_set(c, &sec_ptr),"(UCI) Failed to set section");
  INFO("(UCI) Section set succeeded");
    
  // uci set options/values
  txt = i->txt_lst;
  do {
    if (avahi_string_list_get_pair(txt,(char **)&(sec_ptr.option),(char **)&(sec_ptr.value),NULL))
      continue;
    if (!strcmp(sec_ptr.option,"type")) {
      uci_ret = uci_add_list(c, &sec_ptr);
    } else {
      uci_ret = uci_set(c, &sec_ptr);
    }
    CHECK(!uci_ret,"(UCI) Failed to set");
    INFO("(UCI) Set succeeded");
  } while (txt = avahi_string_list_get_next(txt));
  
  // uci_save
  CHECK(!uci_save(c, pak),"(UCI) Failed to save");
  INFO("(UCI) Save succeeded");
  
  CHECK(!uci_commit(c,&pak,false),"(UCI) Failed to commit");
  INFO("(UCI) Commit succeeded");

  ret = 0;
  
error:
  if (c)
    uci_free_context(c);
  return ret;
}