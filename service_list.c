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
#include <uci.h>
#include "uci-utils.h"
#endif

#include "defs.h"
#include "browse.h"
#include "util.h"
#include "service.h"
#include "service_list.h"

#if 0
extern AvahiSimplePoll *simple_poll;
#ifndef CLIENT
extern AvahiServer *server;
#endif

extern struct csm_config csm_config;
#endif


extern AvahiSimplePoll *simple_poll;

/* Private */

static co_obj_t *
_csm_services_commit_i(co_obj_t *list, co_obj_t *current, void *context)
{
  if (IS_LIST(current)) return NULL;
  
  co_obj_t *service_list = (co_obj_t*)context;
  assert(IS_LIST(service_list));
  
  co_cb_t handler = (co_cb_t)current;
  handler(service_list, NULL, service_list);
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

static co_obj_t *
_csm_service_list_find_service(co_obj_t *list, co_obj_t *current, void *context)
{
  if (IS_LIST(current)) return NULL;
  csm_service *srv_ptr = (csm_service*)context;
  if (((co_service_t*)current)->service == srv_ptr)
    return current;
  return NULL;
}

/* Public */

csm_service_list *
csm_services_init(void)
{
  csm_service_list *services = h_calloc(1, sizeof(csm_service_list));
  CHECK_MEM(services);
  
  co_obj_t *csm_services = co_list16_create();
  CHECK_MEM(csm_services);
  services->services = csm_services;
  hattach(services->services, csm_services);
  
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
  CHECK(co_list_parse(services->services, _csm_services_commit_i, services->services) == NULL,
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
csm_add_service(csm_service_list *services, csm_service *s)
{
  // attach service and service list
  s->parent = services;
  co_obj_t *service_obj = co_service_create(s);
  CHECK_MEM(service_obj);
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
  csm_service_destroy(s);
  return 0;
}

int
csm_update_service(csm_service_list *services, csm_service *service)
{
  /* Input validation */
  CHECK(isValidTtl(csm_service_get_ttl(service)),"Invalid TTL value: %s -> %d",service->uuid,csm_service_get_ttl(service));
  long lifetime = csm_service_get_lifetime(service);
  CHECK(isValidLifetime(lifetime),"Invalid lifetime value: %s -> %ld",service->uuid,lifetime);
  char *key = csm_service_get_key(service);
  if (key)
    CHECK(isValidFingerprint(key,strlen(key)),"Invalid fingerprint: %s -> %s",service->uuid,key);
  char *signature = csm_service_get_signature(service);
  if (signature)
    CHECK(isValidSignature(signature,strlen(signature)),"Invalid signature: %s -> %s",service->uuid,signature);
  
  /* Create or verify signature */
  if (signature)
    CHECK(verify_signature(service),"Invalid signature");
  else
    CHECK(create_signature(service),"Failed to create signature");
  
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
    service->timeout = avahi_simple_poll_get(simple_poll)->timeout_new(avahi_simple_poll_get(simple_poll),
								       &tv,
								       _csm_expire_service,
								       service);
    /* Convert lifetime period into timestamp */
    if (current_time != ((time_t)-1)) {
      struct tm *timestr = localtime(&current_time);
      timestr->tm_sec += lifetime;
      current_time = mktime(timestr);
      char *c_time_string = ctime(&current_time);
      if (c_time_string) {
	c_time_string[strlen(c_time_string)-1] = '\0'; /* ctime adds \n to end of time string; remove it */
	service->expiration = h_strdup(c_time_string);
	CHECK_MEM(service->expiration);
	hattach(service->expiration, service);
      }
    }
  }
  
  // TODO move this to service_list_commit()
  // TODO or better yet, register a uci_write function with commit_hook_register()
#ifdef USE_UCI
  /* Write out service to UCI */
  if (csm_config.uci && uci_write(i) == 0)
    ERROR("(Resolver) Could not write to UCI");
#endif
  
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
    co_obj_t *service_obj = co_list_parse(services->services, _csm_service_list_find_service, s);
    if (service_obj)
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

/**
 * Check if a service uuid is in the current list of local services
 */
#if 0
ServiceInfo *
find_service(const char *uuid)
{
  for (ServiceInfo *i = services; i; i = i->info_next) {
    if (strcasecmp(i->uuid, uuid) == 0)
      return i;
  }
    
  return NULL;
}
#endif

#if 0
/**
 * Add a remote service to the list of services
 * @param interface
 * @param protocol
 * @param name service name
 * @param type service type (e.g. _commotion._tcp)
 * @param domain domain service is advertised on (e.g. mesh.local)
 * @return ServiceInfo struct representing the service that was added
 */
ServiceInfo *
add_service(BROWSER *b,
	    AvahiIfIndex interface,
	    AvahiProtocol protocol,
	    const char *uuid,
	    const char *type,
	    const char *domain)
{
  ServiceInfo *i;
  
  i = h_calloc(1, sizeof(ServiceInfo));
  
  i->interface = interface;
  i->protocol = protocol;
  if (uuid)
    CSM_SET(i, uuid, uuid);
  CSM_SET(i, type, type);
  CSM_SET(i, domain, domain);
  
  if (b) {
#ifdef CLIENT
    AvahiClient *client = avahi_service_browser_get_client(b);
#endif
    if (!(i->resolver = RESOLVER_NEW(interface, protocol, uuid, type, domain, AVAHI_PROTO_UNSPEC, 0, resolve_callback, i))) {
      h_free(i);
      INFO("Failed to create resolver for service '%s' of type '%s' in domain '%s': %s", uuid, type, domain, AVAHI_ERROR);
      return NULL;
    }
    i->resolved = 0;
  }

  AVAHI_LLIST_PREPEND(ServiceInfo, info, services, i);

  return i;
error:
  remove_service(NULL, i);
  return NULL;
}

int
process_service(ServiceInfo *i)
{
  /* Input validation */
  CHECK(isValidTtl(i->ttl),"Invalid TTL value: %s -> %d",i->uuid,i->ttl);
  CHECK(isValidLifetime(i->lifetime),"Invalid lifetime value: %s -> %ld",i->uuid,i->lifetime);
  if (i->key)
    CHECK(isValidFingerprint(i->key,strlen(i->key)),"Invalid fingerprint: %s -> %s",i->uuid,i->key);
  if (i->signature)
    CHECK(isValidSignature(i->signature,strlen(i->signature)),"Invalid signature: %s -> %s",i->uuid,i->signature);
  
  /* Create or verify signature */
  if (i->signature)
    CHECK(verify_signature(i),"Invalid signature");
  else
    CHECK(create_signature(i),"Failed to create signature");
  
  /* Set expiration timer on the service */
#ifdef USE_UCI
  long def_lifetime = default_lifetime();
  if (i->lifetime == 0 || (def_lifetime < i->lifetime && def_lifetime > 0))
    i->lifetime = def_lifetime;
#endif
  if (i->lifetime > 0) {
    struct timeval tv;
    avahi_elapse_time(&tv, 1000*i->lifetime, 0);
    time_t current_time = time(NULL);
    // create expiration event for service
    i->timeout = avahi_simple_poll_get(simple_poll)->timeout_new(avahi_simple_poll_get(simple_poll),
								 &tv,
								 remove_service,
								 i);
    /* Convert lifetime period into timestamp */
    if (current_time != ((time_t)-1)) {
      struct tm *timestr = localtime(&current_time);
      timestr->tm_sec += i->lifetime;
      current_time = mktime(timestr);
      char *c_time_string = ctime(&current_time);
      if (c_time_string) {
	c_time_string[strlen(c_time_string)-1] = '\0'; /* ctime adds \n to end of time string; remove it */
	CSM_SET(i, expiration, c_time_string);
      }
    }
  }
  
#ifdef USE_UCI
  /* Write out service to UCI */
  if (csm_config.uci && uci_write(i) == 0)
    ERROR("(Resolver) Could not write to UCI");
#endif
  
  i->resolved = 1;
  return 1;
error:
  return 0;
}

/**
 * Remove service from list of local services
 * @param t timer set to service's expiration data. This param is only passed 
 *          when the service is being expired, otherwise it is NULL.
 * @param userdata should be cast as the ServiceInfo object of the service to remove
 * @note If compiled for OpenWRT, the Avahi service file for the local service is removed
 * @note If compiled with UCI support, service is also removed from UCI list
 */
void
remove_service(AvahiTimeout *t, void *userdata)
{
  assert(userdata);
  ServiceInfo *i = (ServiceInfo*)userdata;

  INFO("Removing service announcement: %s",i->uuid);
  
  /* Cancel expiration event */
  if (!t && i->timeout)
    avahi_simple_poll_get(simple_poll)->timeout_update(i->timeout,NULL);
  
#ifdef USE_UCI
  if (i->resolved) {
    // Delete UCI entry
    if (csm_config.uci && uci_remove(i) < 0)
      ERROR("(Remove_Service) Could not remove from UCI");
  }
#endif
  
  AVAHI_LLIST_REMOVE(ServiceInfo, info, services, i);

  if (i->resolver)
    RESOLVER_FREE(i->resolver);

  if (i->txt_lst)
    avahi_string_list_free(i->txt_lst);
  h_free(i);
}

/**
 * Upon resceiving the USR1 signal, print local services
 */
// TODO add global csm_service_list to daemon.c, and move this function to daemon.c, which should call csm_print_services()
void print_services(int signal) {
  ServiceInfo *i;
  FILE *f = NULL;

  if (!(f = fopen(csm_config.output_file, "w+"))) {
    WARN("Could not open %s. Using stdout instead.", csm_config.output_file);
    f = stdout;
  }

  for (i = services; i; i = i->info_next) {
    if (i->resolved)
      print_service(f, i);
  }

  if (f != stdout)
    fclose(f);
}
#endif