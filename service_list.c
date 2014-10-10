/**
 *       @file  service_list.c
 *      @brief  service list-related functionality of the Commotion Service Manager
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <net/if.h>

#include <avahi-common/error.h>
#include <avahi-common/simple-watch.h>

#include <commotion/debug.h>
#include <commotion/obj.h>
#include <commotion/profile.h>
#include <commotion/list.h>

#ifdef USE_UCI
#include "uci-utils.h"
#endif

#include "defs.h"
#include "browse.h"
#include "util.h"
#include "service.h"
#include "service_list.h"

extern AvahiSimplePoll *simple_poll;
extern struct csm_config csm_config;

/* Private */

static co_obj_t *
_csm_services_commit_i(co_obj_t *list, co_obj_t *current, void *context)
{
  if (IS_LIST(current)) return NULL;
  
  co_obj_t *service_list = (co_obj_t*)context;
  assert(IS_LIST(service_list));
  
  co_cbptr_t *handler = (co_cbptr_t*)current;
  handler->cb(service_list, NULL, service_list);
  return NULL;
}

static co_obj_t *
_csm_find_service_i(co_obj_t *list, co_obj_t *current, void *context)
{
  if (IS_LIST(current)) return NULL;
  
  assert(IS_SERVICE(current));
  
  co_service_t *service = (co_service_t*)current;
  char *uuid = (char*)context;
  if (strcmp(uuid, service->service->uuid) == 0)
    return current;
  return NULL;
}

static void
_csm_expire_service(AvahiTimeout *t, void *userdata)
{
  assert(userdata);
  csm_service *s = (csm_service*)userdata;
  csm_service_list *services = s->parent;
  
  s->timeout = NULL;
  if (!csm_remove_service(services, s))
    ERROR("Error expiring service %s", s->uuid);
  csm_service_destroy(s);
}

#if 0
static co_obj_t *
_csm_service_list_find_service(co_obj_t *list, co_obj_t *current, void *context)
{
  if (IS_LIST(current)) return NULL;
  assert(IS_SERVICE(current));
  csm_service *srv_ptr = (csm_service*)context;
  if (((co_service_t*)current)->service == srv_ptr)
    return current;
  return NULL;
}
#endif

/* Public */

csm_service_list *
csm_services_init(void)
{
  csm_service_list *services = h_calloc(1, sizeof(csm_service_list));
  CHECK_MEM(services);
  
  co_obj_t *csm_services = co_list16_create();
  CHECK_MEM(csm_services);
  services->services = csm_services;
  hattach(services->services, services);
  
  co_obj_t *service_fields = co_list16_create();
  CHECK_MEM(service_fields);
  services->service_fields = service_fields;
  hattach(services->service_fields, services);
  
  co_obj_t *update_handlers = co_list16_create();
  CHECK_MEM(update_handlers);
  services->update_handlers = update_handlers;
  hattach(services->update_handlers, services);
  
  return services;
error:
  return NULL;
}

void
csm_services_destroy(csm_service_list *services)
{
  assert(services);
  h_free(services);
}

size_t
csm_services_length(csm_service_list *services)
{
  size_t fields_len = co_list_length(services->service_fields);
  size_t services_len = co_list_length(services->services);
  if (fields_len != services_len) {
    ERROR("Inconsistent service list length");
    return 0;
  }
  return fields_len;
}

int
csm_services_commit(csm_service_list *services)
{
  CHECK(co_list_parse(services->update_handlers, _csm_services_commit_i, services->services) == NULL,
	"Error committing service");
  return 1;
error:
  return 0;
}

/** 
 * update handlers must be idempotent and side effect free, as
 * handlers are called in the order they were registered with
 * service list
 */
int
csm_services_register_commit_hook(csm_service_list *services, co_cb_t handler)
{
  co_cbptr_t *callback = h_calloc(1, sizeof(co_cbptr_t));
  CHECK_MEM(callback);
  callback->_header._type = _ext8;
  callback->_header._ref = 0;
  callback->_header._flags = 0;
  callback->_exttype = _cbptr;
  callback->_len = sizeof(co_cb_t *);
  callback->cb = handler;
  CHECK(co_list_append(services->update_handlers, (co_obj_t *)callback),
	"Failed to register commit hook");
  return 1;
error:
  return 0;
}

int
csm_add_service(csm_service_list *services, csm_service *s, csm_ctx *ctx)
{
  // validate service fields against schema
  CHECK(csm_validate_fields(ctx, s), "Service doesn't validate");
  
  // attach service to service list
  s->parent = services;
//   co_obj_t *service_obj = co_service_create(s);
//   CHECK_MEM(service_obj);
  co_service_t *service_obj = container_of(s, co_service_t, service);
  CHECK(co_list_append(services->services, service_obj),
	"Failed to add service to service list");
  
  co_obj_t *fields = s->fields;
  // detach s->fields from s before adding s->fields to services->service_fields
  hattach(fields, NULL);
  
  // add service fields to service list
  CHECK(co_list_append(services->service_fields, fields),
        "Failed to add service fields to service list");
  
  CHECK(csm_update_service(services, s),
        "Failed to finalize service");
  
  return 1;
error:
// TODO better memory cleanup on errors
  csm_remove_service(services, s);
//   csm_service_destroy(s);
  return 0;
}

int
csm_update_service(csm_service_list *services, csm_service *s, csm_ctx *ctx)
{
  CHECK(csm_validate_fields(ctx, s), "Service doesn't validate");
  assert(s->lifetime);
  long lifetime = *s->lifetime;
  
  // check if service is attached to service_list
  CHECK(co_list_contains(services->services, (co_obj_t*)container_of(s, co_service_t, service)),
	"Cannot update service not in service list");
  
  // detach s->fields from s and attach to services->service_fields
  if (!co_list_contains(services->service_fields, s->fields)) {
    co_obj_t *fields = s->fields;
    hattach(fields, NULL);
    CHECK(co_list_append(services->service_fields, fields),
	  "Failed to add service fields to service list");
  }
  
  /* Create or verify signature */
  // TODO extract signature
  if (signature)
    CHECK(_csm_verify_signature(s),"Invalid signature");
  else
    CHECK(_csm_create_signature(s),"Failed to create signature");
  
  /* Set expiration timer on the service */
#ifdef USE_UCI
  long def_lifetime = default_lifetime();
  if (lifetime == 0 || (def_lifetime < lifetime && def_lifetime > 0))
    lifetime = def_lifetime;
#endif
  if (lifetime > 0) {
    struct timeval tv;
    avahi_elapse_time(&tv, 1000*lifetime, 0);
    time_t current_time = time(NULL);
    // create expiration event for service
    s->timeout = avahi_simple_poll_get(simple_poll)->timeout_new(avahi_simple_poll_get(simple_poll),
								       &tv,
								       _csm_expire_service,
								       s);
    /* Convert lifetime period into timestamp */
    if (current_time != ((time_t)-1)) {
      struct tm *timestr = localtime(&current_time);
      timestr->tm_sec += lifetime;
      current_time = mktime(timestr);
      char *c_time_string = ctime(&current_time);
      if (c_time_string) {
	c_time_string[strlen(c_time_string)-1] = '\0'; /* ctime adds \n to end of time string; remove it */
	s->expiration = h_strdup(c_time_string);
	CHECK_MEM(s->expiration);
	hattach(s->expiration, s);
      }
    }
  }
  
  // finalize service by running update handlers
  csm_services_commit(services);
  
  return 1;
error:
  return 0;
}

csm_service *
csm_find_service(csm_service_list *services, const char *uuid)
{
  co_obj_t *match = co_list_parse(services->services, _csm_find_service_i, (char*)uuid);
  if (match)
    return ((co_service_t*)match)->service;
  return NULL;
}

csm_service *
csm_remove_service(csm_service_list *services, csm_service *s)
{
  INFO("Removing service announcement: %s",s->uuid);
  
  /* Cancel expiration event */
  if (s->timeout)
    avahi_simple_poll_get(simple_poll)->timeout_update(s->timeout,NULL);
  
  // find associated fields obj, dettach it from service_list's tree, and
  // reattach it to the original csm_service
  co_obj_t *fields = s->fields;
  if (fields && services && co_list_contains(services->service_fields, fields)) {
    co_list_delete(services->service_fields, fields);
    hattach(s->fields, s);
  }
  
  // remove service from service list
  if (services) {
//     co_obj_t *service_obj = co_list_parse(services->services, _csm_service_list_find_service, s);
    co_obj_t *service_obj = (co_obj_t*)container_of(s, co_service_t, service);
    if (co_list_contains(services->services, service_obj))
      co_list_delete(services->services, service_obj);
  }
  
  // finalize removal by running update handlers
  if (services)
    csm_services_commit(services);
  
  return s;
}

void
csm_print_services(csm_service_list *services)
{
  // TODO iterate call of csm_print_service()
}

struct _csm_fields_array {
  ssize_t num_fields;
  ssize_t current_field;
  char **fields;
};

typedef void (*_csm_iter_t)(co_obj_t *data, co_obj_t *key, co_obj_t *val, void *context);

static void
_csm_list_parse(co_obj_t *list, co_obj_t *key, _csm_iter_t iter, void *context)
{
  CHECK(IS_LIST(list), "Not a list object.");
  _listnode_t *next = _co_list_get_first_node(list);
  while(next != NULL)
  {
    iter(list, key, next->value, context);
    next = _LIST_NEXT(next);
  }
  return;
error:
  return;
}

static inline void
_csm_tree_process_r(co_obj_t *tree, _treenode_t *current, const _csm_iter_t iter, void *context)
{
  CHECK(IS_TREE(tree), "Recursion target is not a tree.");
  if(current != NULL)
  {
    if(current->value != NULL) iter(tree, current->key current->value, context);
    _csm_tree_process_r(tree, current->low, iter, context); 
    _csm_tree_process_r(tree, current->equal, iter, context); 
    _csm_tree_process_r(tree, current->high, iter, context); 
  }
  return;
error:
  return;
}

static void
_csm_sort_service_fields(co_obj_t *data, co_obj_t *key, co_obj_t *field, void *context)
{
  struct _csm_fields_array *fields = (struct _csm_fields_array*)context;
  /* max length of TXT record is 256 char, so the max length of our
     template string is 256 + sizeof('<txt-record></txt-record>\0') = 282 */
  fields->fields[fields->current] = h_calloc(282, sizeof(char));
  if (IS_STR(field)) {
    snprintf(fields->fields[fields->current], 
	     282, 
	     "<txt-record>%s=%s</txt-record>",
	     co_obj_data_ptr(key),
	     co_obj_data_ptr(field));
  } else if (IS_INT(field)) {
    snprintf(fields->fields[fields->current], 
	     282, 
	     "<txt-record>%s=%ld</txt-record>",
	     co_obj_data_ptr(key),
	     (int32_t)*co_obj_data_ptr(field));
  } else if (IS_LIST(field)) {
    _csm_list_parse(field, key, _csm_sort_service_fields, context);
  } else {
    ERROR("Invalid service field");
    h_free(fields->fields[fields->current]);
    return;
  }
  hattach(fields->fields[fields->current], fields->fields);
  fields->current++;
}

/*
 * sort fields alphabetcally, or should the schema keep them in alpha order?
 * probably should base signing template on schema, not the fields the
 * service happens to have
 * ^^ actually, since this will be called for remote services that might have
 * 	a different schema, should probably base on fields
 * conclusion: keep signing template separate from schema. sort fields and
 * 	elements of list fields alphabetically
 */
static size_t
_csm_create_signing_template(csm_service *s, char **template)
{
  int ret = 0;
  char *txt_fields = NULL;
  
  /* Sort fields into alphabetical order */
  ssize_t num_fields = co_tree_length(s->fields);
  struct _csm_fields_array fields = {
    .num_fields = num_fields,
    .current_field = 0,
    .fields = h_calloc(num_fields, sizeof(char*))
  };
  CHECK_MEM(fields.fields);
  _csm_tree_process_r(s->fields, ((co_tree16_t *)s->fields)->root, _csm_sort_service_fields, &fields);
  assert(fields.num_fields == fields.current_field);
  
  // Alphabetically sort the array of template strings we've built
  qsort(fields->fields,num_fields,sizeof(char*),cmpstringp);
  
  // build the full txt field template
  for (int i = 0; i < num_fields, i++) {
    txt_fields = h_realloc(txt_fields, strlen(txt_fields) + strlen(fields->fields[i]) + 1);
    strcat(txt_fields, fields->fields[i]);
  }
  txt_fields[strlen(txt_fields) - 1] = '\0'; // remove last \n
  
  // finally create the signing template
  int bytes = asprintf(template,
		       "<type>%s</type>\n<domain-name>%s</domain-name>\n<port>%d</port>\n%s",
		       s->type,
		       s->domain,
		       s->port,
		       txt_fields);
  CHECK(bytes > 0, "Failed to create signing template");
  
  ret = strlen(*template);
error:
  if (fields.fields)
    h_free(fields.fields);
  if (txt_fields)
    h_free(txt_fields);
  return ret;
}

static int
_csm_verify_signature(csm_service *s)
{
  int verdict = 0;
  co_obj_t *co_conn = NULL, *co_req = NULL, *co_resp = NULL;
  char *to_verify = NULL;
  CHECK(_csm_create_signing_template(s,&to_verify) > 0, "Failed to create signing template");
  CHECK_MEM(to_verify);
  
  char sas_buf[2*SAS_SIZE+1] = {0};
  
  char *key = csm_service_get_key(s);
  CHECK(keyring_send_sas_request_client(key,strlen(key),sas_buf,2*SAS_SIZE+1),"Failed to fetch signing key");
  
  bool output;
  CHECK((co_conn = co_connect(csm_config.co_sock,strlen(csm_config.co_sock)+1)),
	"Failed to connect to Commotion socket");
  CHECK_MEM((co_req = co_request_create()));
  CO_APPEND_STR(co_req,"verify");
  CO_APPEND_STR(co_req,sas_buf);
  CO_APPEND_STR(co_req,csm_service_get_signature(s));
  CO_APPEND_STR(co_req,to_verify);
  CHECK(co_call(co_conn,&co_resp,"serval-crypto",sizeof("serval-crypto"),co_req)
	&& co_response_get_bool(co_resp,&output,"result",sizeof("result")),
	"Failed to verify signature");
  
  /* Is the signature valid? 1=yes, 0=no */
  if (output == true)
    verdict = 1;
  
error:
  if (co_req)
    co_free(co_req);
  if (co_resp)
    co_free(co_resp);
  if (co_conn)
    co_disconnect(co_conn);
  if (to_verify)
    free(to_verify); // alloc'd using asprint from _csm_create_signing_template()
  return verdict;
}

static int
_csm_create_signature(csm_service *s)
{
  int ret = 0;
  char *to_sign = NULL;
  CHECK(_csm_create_signing_template(s,&to_sign) > 0, "Failed to create signing template");
  CHECK_MEM(to_sign);
  
  co_obj_t *co_conn = NULL, *co_req = NULL, *co_resp = NULL;
  CHECK((co_conn = co_connect(csm_config.co_sock,strlen(csm_config.co_sock)+1)),
	"Failed to connect to Commotion socket");
  CHECK_MEM((co_req = co_request_create()));
  CO_APPEND_STR(co_req,"sign");
  char *key = csm_service_get_key(s);
  if (key) {
    CO_APPEND_STR(co_req,key);
  }
  CO_APPEND_STR(co_req,to_sign);
  
  CHECK(co_call(co_conn,&co_resp,"serval-crypto",sizeof("serval-crypto"),co_req),
	"Failed to sign service announcement");
  
  char *signature = NULL, *sid = NULL;
  CHECK(co_response_get_str(co_resp,&signature,"signature",sizeof("signature")),
	"Failed to fetch signature from response");
  CHECK(co_response_get_str(co_resp,&sid,"SID",sizeof("SID")),
	"Failed to fetch SID from response");
  CHECK(csm_service_set_signature(s, signature), "Failed to set signature");
  if (!key) {
    csm_service_set_key(s, sid);
    // set UUID
    char uuid[UUID_LEN + 1] = {0};
    CHECK(get_uuid(sid,strlen(sid),uuid,UUID_LEN + 1) == UUID_LEN, "Failed to get UUID");
    s->uuid = h_strdup(uuid);
    CHECK_MEM(s->uuid);
    hattach(s->uuid, s);
  }
  
  ret = 1;
error:
  if (co_req)
    co_free(co_req);
  if (co_resp)
    co_free(co_resp);
  if (co_conn)
    co_disconnect(co_conn);
  if (to_sign)
    free(to_sign); // alloc'd using asprint from _csm_create_signing_template()
  return ret;
}