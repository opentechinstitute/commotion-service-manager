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
  // TODO use correct version of schema, or reject
  // validate service fields against schema
  CHECK(csm_validate_fields(ctx->schema, s->fields), "Service doesn't validate");
  
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
  // TODO use correct version of schema, or reject
  CHECK(csm_validate_fields(ctx->schema, s->fields), "Service doesn't validate");
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

static co_obj_t *
_csm_sort_service_fields(co_obj_t *data, co_obj_t *current, void *context)
{
  
}

/*
 * sort fields alphabetcally, or should the schema keep them in alpha order?
 * probably should base signing template on schema, not the fields the
 * service happens to have
 * ^^ actually, since this will be called for remote services that might have
 * 	a different schema, should probably base on fields
 */
static size_t
_csm_create_signing_template(csm_service *s, char **template)
{
  int ret = 0;
  
  /* Sort fields into alphabetical order */
  //qsort(*cat_array,cat_len,sizeof(char*),cmpstringp);
  
  
  
  
  
  const char *type_template = "<txt-record>type=%s</txt-record>";
  const char *str_template = "<type>%s</type>\n"
  "<domain-name>%s</domain-name>\n"
  "<port>%d</port>\n"
  "<txt-record>name=%s</txt-record>\n"
  "<txt-record>ttl=%d</txt-record>\n"
  "<txt-record>uri=%s</txt-record>\n"
  "%s\n"
  "<txt-record>icon=%s</txt-record>\n"
  "<txt-record>description=%s</txt-record>\n"
  "<txt-record>lifetime=%ld</txt-record>";
  
  char **categories = NULL, *type_str = NULL, *app_type = NULL;
  size_t cat_len = csm_service_categories_to_array(s, &categories);
  if (cat_len) {
    /* Concat the types into a single string to add to template */
    int prev_len = 0;
    for (int j = 0; j < cat_len; j++) {
      if (app_type) {
	free(app_type);
	app_type = NULL;
      }
      prev_len = type_str ? strlen(type_str) : 0;
      CHECK_MEM(asprintf(&app_type, type_template, categories[j]) != -1);
      type_str = h_realloc(type_str, prev_len + strlen(app_type) + 1);
      CHECK_MEM(type_str);
      type_str[prev_len] = '\0';
      strcat(type_str, app_type);
    }
  }
  
  /* Add the fields into the template */
  CHECK_MEM(asprintf(template,
		     str_template,
		     s->type,
		     s->domain,
		     s->port,
		     csm_service_get_name(s),
		     csm_service_get_ttl(s),
		     csm_service_get_uri(s),
		     cat_len ? type_str : "",
		     csm_service_get_icon(s),
		     csm_service_get_description(s),
		     csm_service_get_lifetime(s)) != -1);
  
  ret = strlen(*template);
  error:
  if (categories)
    h_free(categories);
  if (app_type)
    free(app_type); // alloc'd using asprintf
    if (type_str)
      h_free(type_str);
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