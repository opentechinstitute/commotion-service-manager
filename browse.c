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

#include <stdlib.h>
#include <assert.h>
#include <time.h>

#include <avahi-core/core.h>
#include <avahi-core/lookup.h>
#include <avahi-client/client.h>
#include <avahi-client/lookup.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>
#include <avahi-common/simple-watch.h>

#include <commotion/debug.h>
#include <commotion/obj.h>
#include <commotion/list.h>

#include "defs.h"
#include "service.h"
#include "service_list.h"
#include "browse.h"

extern AvahiSimplePoll *simple_poll;

/* Private */

static int
_csm_extract_from_txt_list(csm_service *s, AvahiStringList *txt)
{
  // TODO insert major/minor version from txt field into service (and keep it as a field too)
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
  AvahiStringList *version = avahi_string_list_find(txt,"version");
  
  /* Make sure all the required fields are there */
  CHECK(name && uri && icon && description && ttl && lifetime && signature && fingerprint && version,
	"Missing TXT field(s): %s", s->uuid);
  
#define CSM_EXTRACT_TXT(S,M,T) \
  do { \
    char *val = NULL; \
    CHECK(avahi_string_list_get_pair(T,NULL,&val,NULL) == 0, "Failed to extract " #T " from TXT list"); \
    CHECK(csm_service_set_##M(S, val), "Failed to set service field %s", "M"); \
    avahi_free(val); \
  } while (0)
  CSM_EXTRACT_TXT(s, name, name);
  CSM_EXTRACT_TXT(s, uri, uri);
  CSM_EXTRACT_TXT(s, description, description);
  CSM_EXTRACT_TXT(s, icon, icon);
  CSM_EXTRACT_TXT(s, signature, signature);
  CSM_EXTRACT_TXT(s, key, fingerprint);
  CSM_EXTRACT_TXT(s, version, version);
#undef CSM_EXTRACT_TXT
  
  char *ttl_str = NULL, *lifetime_str = NULL;
  CHECK(avahi_string_list_get_pair(ttl,NULL,&ttl_str,NULL) == 0, "Failed to extract TTL from TXT list");
  CHECK(avahi_string_list_get_pair(lifetime,NULL,&lifetime_str,NULL) == 0, "Failed to extract lifetime from TXT list");
  CHECK(csm_service_set_ttl(s, atoi(ttl_str)), "Failed to set service field TTL");
  CHECK(csm_service_set_lifetime(s, atol(lifetime_str)), "Failed to set service field lifetime");
  
  /** Add service categories */
  co_obj_t *categories = NULL;
  do {
    avahi_string_list_get_pair(txt,&key,&val,NULL);
    if (!strcmp(key,"categories")) {
      /* Add 'type' fields to a list to be sorted alphabetically later */
      co_obj_t *type = co_str8_create(val, strlen(val) + 1, 0);
      CHECK_MEM(type);
      if (!categories) {
	categories = co_list16_create();
	CHECK_MEM(categories);
      }
      if (!co_list_append(categories, type)) {
	ERROR("Failed to add type to category list");
	co_obj_free(type);
	goto error;
      }
    }
    avahi_free(val);
    avahi_free(key);
    val = key = NULL;
  } while ((txt = avahi_string_list_get_next(txt)));
  if (categories)
    CHECK(csm_service_set_categories(s, categories), "Failed to set service fields categories");
  
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
    const char *uuid,
    const char *type,
    const char *domain,
    const char *host_name,
    const AvahiAddress *address,
    uint16_t port,
    AvahiStringList *txt,
    AvahiLookupResultFlags flags,
    void* userdata) {
    
    assert(userdata);
    csm_ctx *ctx = (csm_ctx*)userdata;
    csm_service *s = ctx->service;
#ifdef CLIENT
    AvahiClient *client = ctx->client;
#else
    AvahiServer *server = ctx->server;
#endif
    assert(r);

    switch (event) {
        case AVAHI_RESOLVER_FAILURE:
            ERROR("Failed to resolve service '%s' of type '%s' in domain '%s': %s", uuid, type, domain, AVAHI_ERROR);
            break;

        case AVAHI_RESOLVER_FOUND: {
            avahi_address_snprint(s->r.address, 
                sizeof(s->r.address),
                address);
	    s->r.host_name = h_strdup(host_name);
	    
	    CHECK_MEM(s->r.host_name);
	    hattach(s->r.host_name, s);

	    CHECK(port >= 0 && port <= 65535, "Invalid port: %s",uuid);
	    s->port = port;

	    s->r.txt_lst = avahi_string_list_copy(txt);
	    CHECK_MEM(s->r.txt_lst);
	    
	    CHECK(_csm_extract_from_txt_list(s,txt), "Failed to extract TXT fields");
	    
	    CHECK(csm_add_service(ctx->service_list, s), "Error processing service");
	    
	    break;
        }
    }
error:
    RESOLVER_FREE(s->r.resolver);
    s->r.resolver = NULL;
    // if no signature is present, indicates service resolution failed
    if (event == AVAHI_RESOLVER_FOUND && !csm_service_get_signature(s)) {
      csm_remove_service(ctx->service_list, s);
      csm_service_destroy(s);
    }
}

void browse_service_callback(
    BROWSER *b,
    AvahiIfIndex interface,
    AvahiProtocol protocol,
    AvahiBrowserEvent event,
    const char *uuid,
    const char *type,
    const char *domain,
    AVAHI_GCC_UNUSED AvahiLookupResultFlags flags,
    void* userdata) {

    assert(userdata);
    csm_ctx *ctx = (csm_ctx*)userdata;
#ifdef CLIENT
    AvahiClient *client = ctx->client;
#else
    AvahiServer *server = ctx->server;
#endif
    assert(b);

    switch (event) {

        case AVAHI_BROWSER_FAILURE:

            ERROR("Service browser failure: %s", AVAHI_ERROR);
            avahi_simple_poll_quit(simple_poll);
            return;

        case AVAHI_BROWSER_NEW:
        case AVAHI_BROWSER_REMOVE: {
            INFO("Browser: %s: service '%s' of type '%s' in domain '%s'",event == AVAHI_BROWSER_NEW ? "NEW" : "REMOVE", uuid, type, domain);
	    
	    /* Lookup the service to see if it's already in our list */
	    csm_service *found_service = csm_find_service(ctx->service_list, uuid);
            if (event == AVAHI_BROWSER_NEW && !found_service) {
                /* add the service.*/
		csm_service *s = csm_service_new(interface, protocol, uuid, type, domain);
		if (!s) {
		  ERROR("Failed to allocate new service");
		  return;
		}
		
		ctx->service = s;
		s->r.resolver = RESOLVER_NEW(interface, protocol, uuid, type, domain, AVAHI_PROTO_UNSPEC, 0, resolve_callback, ctx);
		if (!s->r.resolver) {
		  csm_service_destroy(s);
		  INFO("Failed to create resolver for service '%s' of type '%s' in domain '%s': %s", uuid, type, domain, AVAHI_ERROR);
		  return;
		}
            }
            if (event == AVAHI_BROWSER_REMOVE && found_service) {
                /* remove the service.*/
                csm_remove_service(NULL, found_service);
            }
            break;
        }
        case AVAHI_BROWSER_CACHE_EXHAUSTED:
            INFO("Service browser cache exhausted");
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

    assert(userdata);
    csm_ctx *ctx = (csm_ctx*)userdata;
#ifdef CLIENT
    AvahiClient *client = ctx->client;
#else
    AvahiServer *server = ctx->server;
#endif
    assert(b);

    INFO("Type browser got an event: %d", event);
    switch (event) {
        case AVAHI_BROWSER_FAILURE:
            ERROR("Service type browser failure: %s", AVAHI_ERROR);
            avahi_simple_poll_quit(simple_poll);
            return;
        case AVAHI_BROWSER_NEW:
            if (!BROWSER_NEW(AVAHI_IF_UNSPEC, 
                             AVAHI_PROTO_UNSPEC, 
                             type, 
                             domain, 
                             0,
                             browse_service_callback,
			     ctx)) {
                ERROR("Failed to create a service " 
                      "browser for type (%s) in domain (%s)", 
                      type, 
                      domain);
                avahi_simple_poll_quit(simple_poll);
            } else {
                DEBUG("Successfully created a service " 
                      "browser for type (%s) in domain (%s)", 
                      type, 
                      domain);
            }
            break;
        case AVAHI_BROWSER_CACHE_EXHAUSTED:
            INFO("Service type browser cache exhausted");
            break;
	default:
	    break;
    }
}