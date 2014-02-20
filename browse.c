/**
 *       @file  browse.c
 *      @brief  functionality for receiving and processing service announcements
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
#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <net/if.h>
#include <string.h>
#include <ctype.h>
#ifdef USESYSLOG
#include <syslog.h>
#endif

#include <avahi-core/core.h>
#include <avahi-core/lookup.h>
#include <avahi-client/client.h>
#include <avahi-client/lookup.h>
#include <avahi-common/llist.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>
#include <avahi-common/simple-watch.h>

#include "defs.h"
#include "service.h"
#include "browse.h"
#include "util.h"
#include "debug.h"

#ifdef USE_UCI
#include <uci.h>
#include "uci-utils.h"
#endif

extern csm_config config;
extern AvahiSimplePoll *simple_poll;
#ifndef CLIENT
extern AvahiServer *server;
#endif

#define CSM_EXTRACT_TXT(I,M,T) \
  do { \
    char *val = NULL; \
    CHECK(avahi_string_list_get_pair(T,NULL,&val,NULL) == 0, "Failed to extract " #T " from TXT list"); \
    CSM_SET(I, M, val); \
    avahi_free(val); \
  } while (0)

static int
extract_from_txt_list(ServiceInfo *i, AvahiStringList *txt)
{
  int ret = 0;
  char *key = NULL, *val = NULL;
  
  AvahiStringList *name = avahi_string_list_find(txt,"name");
  AvahiStringList *uri = avahi_string_list_find(txt,"uri");
  AvahiStringList *icon = avahi_string_list_find(txt,"icon");
  AvahiStringList *description = avahi_string_list_find(txt,"description");
  AvahiStringList *ttl = avahi_string_list_find(txt,"ttl");
  AvahiStringList *lifetime = avahi_string_list_find(txt,"lifetime");
  AvahiStringList *signature = avahi_string_list_find(txt,"signature");
  AvahiStringList *fingerprint = avahi_string_list_find(txt,"fingerprint");
  
  /* Make sure all the required fields are there */
  CHECK(name && uri && icon && description && ttl && lifetime && signature && fingerprint,
	"Missing TXT field(s): %s", i->uuid);
  
  CSM_EXTRACT_TXT(i, name, name);
  CSM_EXTRACT_TXT(i, uri, uri);
  CSM_EXTRACT_TXT(i, description, description);
  CSM_EXTRACT_TXT(i, icon, icon);
  CSM_EXTRACT_TXT(i, signature, signature);
  CSM_EXTRACT_TXT(i, key, fingerprint);
  char *ttl_str = NULL, *lifetime_str = NULL;
  CHECK(avahi_string_list_get_pair(ttl,NULL,&ttl_str,NULL) == 0, "Failed to extract TTL from TXT list");
  CHECK(avahi_string_list_get_pair(lifetime,NULL,&lifetime_str,NULL) == 0, "Failed to extract lifetime from TXT list");
  i->ttl = atoi(ttl_str);
  i->lifetime = atol(lifetime_str);
  
  /** Add service categories */
  do {
    avahi_string_list_get_pair(txt,&key,&val,NULL);
    if (!strcmp(key,"type")) {
      /* Add 'type' fields to a list to be sorted alphabetically later */
      i->categories = h_realloc(i->categories,(i->cat_len + 1)*sizeof(char*));
      CHECK_MEM(i->categories);
      hattach(i->categories, i);
      CSM_SET(i, categories[i->cat_len], val);
      i->cat_len++;
    }
    avahi_free(val);
    avahi_free(key);
    val = key = NULL;
  } while ((txt = avahi_string_list_get_next(txt)));
  
  ret = 1;
error:
  if (val)
    avahi_free(val);
  if (key)
    avahi_free(key);
  if (ttl_str)
    avahi_free(ttl_str);
  if (lifetime_str)
    avahi_free(lifetime_str);
  return ret;
}

void resolve_callback(
    RESOLVER *r,
    AVAHI_GCC_UNUSED AvahiIfIndex interface,
    AVAHI_GCC_UNUSED AvahiProtocol protocol,
    AvahiResolverEvent event,
    const char *name,
    const char *type,
    const char *domain,
    const char *host_name,
    const AvahiAddress *address,
    uint16_t port,
    AvahiStringList *txt,
    AvahiLookupResultFlags flags,
    void* userdata) {
    
    ServiceInfo *i = (ServiceInfo*)userdata;
    
    assert(r);
    
#ifdef CLIENT
    AvahiClient *client = avahi_service_resolver_get_client(r);
#endif

    switch (event) {
        case AVAHI_RESOLVER_FAILURE:
            ERROR("(Resolver) Failed to resolve service '%s' of type '%s' in domain '%s': %s", name, type, domain, AVAHI_ERROR);
            break;

        case AVAHI_RESOLVER_FOUND: {
            avahi_address_snprint(i->address, 
                sizeof(i->address),
                address);
	    CSM_SET(i, host_name, host_name);
	    if (port < 0 || port > 65535) {
	      WARN("(Resolver) Invalid port: %s",name);
	      break;
	    }
	    i->port = port;
	    i->txt_lst = avahi_string_list_copy(txt);
	    
	    if (!extract_from_txt_list(i,txt)) {
	      ERROR("Failed to extract TXT fields");
	      break;
	    }
	    
	    if (process_service(i) == 0) {
	      ERROR("Error processing service");
	      break;
	    }
	    
	    break;
        }
    }
error:
    RESOLVER_FREE(i->resolver);
    i->resolver = NULL;
    if (event == AVAHI_RESOLVER_FOUND && !i->resolved) {
      remove_service(NULL, i);
    }
}

void browse_service_callback(
    BROWSER *b,
    AvahiIfIndex interface,
    AvahiProtocol protocol,
    AvahiBrowserEvent event,
    const char *name,
    const char *type,
    const char *domain,
    AVAHI_GCC_UNUSED AvahiLookupResultFlags flags,
    void* userdata) {

    assert(b);

    switch (event) {

        case AVAHI_BROWSER_FAILURE:

            ERROR("(Browser) %s", AVAHI_BROWSER_ERROR);
            avahi_simple_poll_quit(simple_poll);
            return;

        case AVAHI_BROWSER_NEW:
        case AVAHI_BROWSER_REMOVE: {
            ServiceInfo *found_service = NULL;
            INFO("Browser: %s: service '%s' of type '%s' in domain '%s'",event == AVAHI_BROWSER_NEW ? "NEW" : "REMOVE", name, type, domain);
	    
	    /* Lookup the service to see if it's already in our list */
	    found_service=find_service(name); // name is fingerprint, so should be unique
            if (event == AVAHI_BROWSER_NEW && !found_service) {
                /* add the service.*/
                add_service(b, interface, protocol, name, type, domain);
            }
            if (event == AVAHI_BROWSER_REMOVE && found_service) {
                /* remove the service.*/
                remove_service(NULL, found_service);
            }
            break;
        }
        case AVAHI_BROWSER_CACHE_EXHAUSTED:
            INFO("(Browser) %s", "CACHE_EXHAUSTED");
            break;
	default:
	    break;
    }
}

void browse_type_callback(
    TYPE_BROWSER *b,
    AvahiIfIndex interface,
    AvahiProtocol protocol,
    AvahiBrowserEvent event,
    const char *type,
    const char *domain,
    AVAHI_GCC_UNUSED AvahiLookupResultFlags flags,
    void* userdata) {

#ifdef CLIENT
    AvahiClient *client = (AvahiClient*)userdata;
#else
    AvahiServer *server = (AvahiServer*)userdata;
#endif
    assert(b);

    INFO("Type browser got an event: %d", event);
    switch (event) {
        case AVAHI_BROWSER_FAILURE:
            ERROR("(Browser) %s", AVAHI_ERROR);
            avahi_simple_poll_quit(simple_poll);
            return;
        case AVAHI_BROWSER_NEW:
            if (!BROWSER_NEW(AVAHI_IF_UNSPEC, 
                                           AVAHI_PROTO_UNSPEC, 
                                           type, 
                                           domain, 
                                           0, 
                                           browse_service_callback)) {
                ERROR("Service Browser: Failed to create a service " 
                                "browser for type (%s) in domain (%s)", 
                                                                type, 
                                                                domain);
                avahi_simple_poll_quit(simple_poll);
            } else {
                DEBUG("Service Browser: Successfully created a service " 
                                "browser for type (%s) in domain (%s)", 
                                                                type, 
                                                                domain);
            }
            break;
        case AVAHI_BROWSER_CACHE_EXHAUSTED:
            INFO("Cache exhausted");
            break;
	default:
	    break;
    }
}