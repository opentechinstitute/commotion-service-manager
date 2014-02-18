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

#include "commotion.h"

#include "defs.h"
#include "service.h"
#include "browse.h"
#include "util.h"
#include "debug.h"

#ifdef USE_UCI
#include <uci.h>
#include "uci-utils.h"
#endif

// from libcommotion_serval-sas
#define SAS_SIZE 32
extern int keyring_send_sas_request_client(const char *sid_str, 
					   const size_t sid_len,
					   char *sas_buf,
					   const size_t sas_buf_len);

extern csm_config config;
extern AvahiSimplePoll *simple_poll;
#ifndef CLIENT
extern AvahiServer *server;
#endif

int verify_announcement(ServiceInfo *i) {
// 	AvahiStringList *txt;
  co_obj_t *co_conn = NULL, *co_req = NULL, *co_resp = NULL;
  char *to_verify = NULL;
//   char **types_list = NULL;
//   int types_list_len = 0;
// 	char *key, *val, *app, *uri, *icon, *desc, *sid, *sig;
//   unsigned int ttl = 0;
//   long lifetime = 0;
  int verdict = 1, to_verify_len = 0;
//   size_t val_len;
	
#if 0
	assert(i->txt_lst);
	
	txt = i->txt_lst;
	/* Loop through txt fields, to be added to the template for verification */
	do {
		if (avahi_string_list_get_pair(txt,&key,&val,&val_len)) {
			if (key)
				avahi_free(key);
			if (val)
				avahi_free(val);
			continue;
		}
		if (!strcmp(key,"type")) {
			/* Add 'type' fields to a list to be sorted alphabetically later */
			CHECK_MEM((types_list = (char**)realloc(types_list,(types_list_len + 1)*sizeof(char*))));
			types_list[types_list_len] = avahi_strdup(val);
			types_list_len++;
		} else if (!strcmp(key,"name"))
			app = avahi_strdup(val);
		else if (!strcmp(key,"ttl")) {
			ttl = atoi(val);
		} else if (!strcmp(key,"uri"))
			uri = avahi_strdup(val);
		else if (!strcmp(key,"icon"))
			icon = avahi_strdup(val);
		else if (!strcmp(key,"description"))
			desc = avahi_strdup(val);
		else if (!strcmp(key,"lifetime")) {
			lifetime = atol(val);
		} else if (!strcmp(key,"fingerprint"))
			sid = avahi_strdup(val);
		else if (!strcmp(key,"signature"))
			sig = avahi_strdup(val);
		avahi_free(val);
		avahi_free(key);
		val = key = NULL;
	} while ((txt = avahi_string_list_get_next(txt)));
#endif
	
  to_verify = createSigningTemplate(i->type,
				    i->domain,
				    i->port,
				    i->name,
				    i->ttl,
				    i->uri,
				    (const char **)i->categories,
				    i->cat_len,
				    i->icon,
				    i->description,
				    i->lifetime,
				    &to_verify_len);
	
  /* Is the signature valid? 0=yes, 1=no */
  if (to_verify) {
    char sas_buf[2*SAS_SIZE+1] = {0};

    CHECK(keyring_send_sas_request_client(i->key,strlen(i->key),sas_buf,2*SAS_SIZE+1),"Failed to fetch signing key");

    bool output;
    CHECK((co_conn = co_connect(config.co_sock,strlen(config.co_sock)+1)),"Failed to connect to Commotion socket");
    CHECK_MEM((co_req = co_request_create()));
    CO_APPEND_STR(co_req,"verify");
    CO_APPEND_STR(co_req,sas_buf);
    CO_APPEND_STR(co_req,i->signature);
    CO_APPEND_STR(co_req,to_verify);
    CHECK(co_call(co_conn,&co_resp,"serval-crypto",sizeof("serval-crypto"),co_req) && 
    co_response_get_bool(co_resp,&output,"result",sizeof("result")),"Failed to verify signature");
    if (output == true)
      verdict = 0;
  }
	
error:
  if (co_req) co_free(co_req);
  if (co_resp) co_free(co_resp);
  if (co_conn) co_disconnect(co_conn);
  if (to_verify)
    free(to_verify);
#if 0
  if (types_list) {
    for (int j = 0; j <types_list_len; ++j)
      avahi_free(types_list[j]);
    free(types_list);
  }
  if (app)
    avahi_free(app);
  if (uri)
    avahi_free(uri);
  if (icon)
    avahi_free(icon);
  if (desc)
    avahi_free(desc);
  if (sid)
    avahi_free(sid);
  if (sig)
    avahi_free(sig);
#endif
  return verdict;
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
    struct timeval tv;
    time_t current_time;
    char* c_time_string;
    struct tm *timestr;
    
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
	    i->host_name = strdup(host_name);
	    if (port < 0 || port > 65535) {
	      WARN("(Resolver) Invalid port: %s",name);
	      break;
	    }
	    i->port = port;
	    i->txt_lst = avahi_string_list_copy(txt);
	    
	    /* Make sure all the required fields are there */
	    if (!avahi_string_list_find(txt,"name") ||
	      !avahi_string_list_find(txt,"uri") ||
	      !avahi_string_list_find(txt,"icon") ||
	      !avahi_string_list_find(txt,"description") ||
	      !avahi_string_list_find(txt,"ttl") ||
	      !avahi_string_list_find(txt,"lifetime") ||
	      !avahi_string_list_find(txt,"signature") ||
	      !avahi_string_list_find(txt,"fingerprint")) {
	      WARN("(Resolver) Missing TXT field(s): %s", name);
	      break;
	    }
	    
	    /************************
	     * INPUT VALIDATION
	     ***********************/
	    char *val = NULL;
	    size_t val_size = 0;
	    
	    /* Validate TTL field */
	    avahi_string_list_get_pair(avahi_string_list_find(txt,"ttl"),NULL,&val,NULL);
	    if (!isValidTtl(val)) {
	      WARN("(Resolver) Invalid TTL value: %s -> %s",name,val);
	      avahi_free(val);
	      break;
	    }
	    i->ttl = atoi(val);
	    avahi_free(val);
	    
	    /* Validate lifetime field */
	    avahi_string_list_get_pair(avahi_string_list_find(txt,"lifetime"),NULL,&val,NULL);
	    i->lifetime = atol(val);
	    if (!isValidLifetime(val)) {
	      WARN("(Resolver) Invalid lifetime value: %s -> %s",name,val);
	      avahi_free(val);
	      break;
	    }
	    avahi_free(val);
	    
	    /* Validate fingerprint field */
	    avahi_string_list_get_pair(avahi_string_list_find(txt,"fingerprint"),NULL,&val,&val_size);
	    if (!isValidFingerprint(val,val_size)) {
	      WARN("(Resolver) Invalid fingerprint: %s -> %s",name,val);
	      avahi_free(val);
	      break;
	    }
	    i->key = avahi_strdup(val);
	    avahi_free(val);
	    
	    /* Validate (but not verify) signature field */
	    avahi_string_list_get_pair(avahi_string_list_find(txt,"signature"),NULL,&val,&val_size);
	    if (!isValidSignature(val,val_size)) {
	      WARN("(Resolver) Invalid signature: %s -> %s",name,val);
	      avahi_free(val);
	      break;
	    }
	    i->signature = avahi_strdup(val);
	    avahi_free(val);
	    
	    avahi_string_list_get_pair(avahi_string_list_find(txt,"name"),NULL,&i->name,NULL);
	    avahi_string_list_get_pair(avahi_string_list_find(txt,"description"),NULL,&i->description,NULL);
	    avahi_string_list_get_pair(avahi_string_list_find(txt,"uri"),NULL,&i->uri,NULL);
	    avahi_string_list_get_pair(avahi_string_list_find(txt,"icon"),NULL,&i->icon,NULL);
	    
	    /** Add service categories */
	    char *key = NULL;
	    do {
	      avahi_string_list_get_pair(txt,&key,&val,&val_size);
	      if (!strcmp(key,"type")) {
		/* Add 'type' fields to a list to be sorted alphabetically later */
		if (!(i->categories = (char**)realloc(i->categories,(i->cat_len + 1)*sizeof(char*)))) {
		  ERROR("Error reallocating category list");
		  break;
		}
		i->categories[i->cat_len] = avahi_strdup(val);
		i->cat_len++;
	      }
	      avahi_free(val);
	      avahi_free(key);
	      val = key = NULL;
	    } while ((txt = avahi_string_list_get_next(txt)));
	    
	    // TODO: check connectivity, using commotiond socket library
	    
	    /* Verify signature */
	    if (verify_announcement(i)) {
	      INFO("Announcement signature verification failed");
	      break;
	    } else
	      INFO("Announcement signature verification succeeded");
	    
	    /* Set expiration timer on the service */
#ifdef USE_UCI
	    long def_lifetime = default_lifetime();
	    if (i->lifetime <= 0 || (def_lifetime < i->lifetime && def_lifetime > 0)) i->lifetime = def_lifetime;
#endif
	    
	    if (i->lifetime > 0) {
	      avahi_elapse_time(&tv, 1000*i->lifetime, 0);
	      current_time = time(NULL);
	      i->timeout = avahi_simple_poll_get(simple_poll)->timeout_new(avahi_simple_poll_get(simple_poll), &tv, remove_service, i); // create expiration event for service
	    
	      /* Convert lifetime period into timestamp */
	      if (current_time != ((time_t)-1)) {
	        timestr = localtime(&current_time);
		timestr->tm_sec += i->lifetime;
	        current_time = mktime(timestr);
	        if ((c_time_string = ctime(&current_time))) {
		  c_time_string[strlen(c_time_string)-1] = '\0'; /* ctime adds \n to end of time string; remove it */
	          i->txt_lst = avahi_string_list_add_printf(i->txt_lst,"expiration=%s",c_time_string);
	        }
	      }
	    }
	    
	    // TODO add various TXT fields to appropriate ServiceInfo->CSMService members, and use txt_list_to_string in _print_service instead
	    if (!(i->txt = txt_list_to_string(i->txt_lst))) {
	      ERROR("(Resolver) Could not convert txt fields to string");
	      break;
	    }
	    
#ifdef USE_UCI
	    if (config.uci && uci_write(i) < 0)
	      ERROR("(Resolver) Could not write to UCI");
#endif
            
            i->resolved = 1;
        }
    }
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
                add_remote_service(b, interface, protocol, name, type, domain);
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