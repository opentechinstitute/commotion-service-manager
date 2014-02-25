/**
 *       @file  commotion-service-manager.c
 *      @brief  main functionality of the Commotion Service Manager
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

#include <avahi-common/malloc.h>
#include <avahi-common/error.h>
#include <avahi-common/simple-watch.h>

#include "commotion.h"

#include "commotion-service-manager.h"
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

/** Linked list of all the local services */
ServiceInfo *services = NULL;

AvahiSimplePoll *simple_poll = NULL;
AvahiServer *server = NULL;

#define CO_APPEND_STR(R,S) CHECK(co_request_append_str(co_req,S,strlen(S)+1),"Failed to append to request")

struct arguments arguments;

/**
 * Check if a service name is in the current list of local services
 */
ServiceInfo *find_service(const char *name) {
  ServiceInfo *i;
  
  for (i = services; i; i = i->info_next)
    if (strcasecmp(i->name, name) == 0)
      return i;
    
    return NULL;
}

/**
 * Add a service to the list of local services
 * @param interface
 * @param protocol
 * @param name service name
 * @param type service type (e.g. _commotion._tcp)
 * @param domain domain service is advertised on (e.g. mesh.local)
 * @return ServiceInfo struct representing the service that was added
 */
ServiceInfo *add_service(AvahiIfIndex interface, AvahiProtocol protocol, const char *name, const char *type, const char *domain) {
    ServiceInfo *i;

    i = avahi_new0(ServiceInfo, 1);

    if (!(i->resolver = avahi_s_service_resolver_new(server, interface, protocol, name, type, domain, AVAHI_PROTO_UNSPEC, 0, resolve_callback, i))) {
        avahi_free(i);
        INFO("Failed to create resolver for service '%s' of type '%s' in domain '%s': %s", name, type, domain, avahi_strerror(avahi_server_errno(server)));
        return NULL;
    }
    i->interface = interface;
    i->protocol = protocol;
    i->name = avahi_strdup(name);
    i->type = avahi_strdup(type);
    i->domain = avahi_strdup(domain);
    i->resolved = 0;

    AVAHI_LLIST_PREPEND(ServiceInfo, info, services, i);

    return i;
}

/**
 * Remove service from list of local services
 * @param t timer set to service's expiration data. This param is only passed 
 *          when the service is being expired, otherwise it is NULL.
 * @param userdata should be cast as the ServiceInfo object of the service to remove
 * @note If compiled for OpenWRT, the Avahi service file for the local service is removed
 * @note If compiled with UCI support, service is also removed from UCI list
 */
void remove_service(AvahiTimeout *t, void *userdata) {
    assert(userdata);
    ServiceInfo *i = (ServiceInfo*)userdata;

    INFO("Removing service announcement: %s",i->name);
    
    /* Cancel expiration event */
    if (!t && i->timeout)
      avahi_simple_poll_get(simple_poll)->timeout_update(i->timeout,NULL);
    
#ifdef OPENWRT
    if (t && is_local(i) == 1) {
      // Delete Avahi service file
      DEBUG("Removing Avahi service file");
      size_t uuid_len = 0;
      char *uuid = NULL, *serviceFile = NULL;
      uuid = get_uuid(i,&uuid_len);
      if (uuid && (serviceFile = (char*)calloc(strlen(avahiDir) + uuid_len + strlen(".service") + 1,sizeof(char)))) {
        strcpy(serviceFile,avahiDir);
        strcat(serviceFile,uuid);
        strcat(serviceFile,".service");
        if (remove(serviceFile))
          ERROR("(Remove_Service) Could not delete service file: %s", serviceFile);
        else
          INFO("(Remove_Service) Successfully deleted service file: %s", serviceFile);
        free(serviceFile);
      }
      if (uuid) free(uuid);
    }
#endif
    
#ifdef USE_UCI
    if (t || !is_local(i)) {
      // Delete UCI entry
      if (arguments.uci && uci_remove(i) < 0)
        ERROR("(Remove_Service) Could not remove from UCI");
    }
#endif
    
    AVAHI_LLIST_REMOVE(ServiceInfo, info, services, i);

    if (i->resolver)
        avahi_s_service_resolver_free(i->resolver);

    avahi_free(i->name);
    avahi_free(i->type);
    avahi_free(i->domain);
    if (i->host_name)
      avahi_free(i->host_name);
    if (i->txt)
      avahi_free(i->txt);
    if (i->txt_lst)
      avahi_string_list_free(i->txt_lst);
    avahi_free(i);
}

/**
 * Output service fields to a file
 * @param f File to output to
 * @param service the service to print
 */
static void _print_service(FILE *f, ServiceInfo *service) {
    char interface_string[IF_NAMESIZE];
    const char *protocol_string;

    if (!if_indextoname(service->interface, interface_string))
        WARN("Could not resolve the interface name!");

    if (!(protocol_string = avahi_proto_to_string(service->protocol)))
        WARN("Could not resolve the protocol name!");

    fprintf(f, "%s;%s;%s;%s;%s;%s;%s;%u;%s\n", interface_string,
                               protocol_string,
                               service->name,
                               service->type,
                               service->domain,
                               service->host_name,
                               service->address,
                               service->port,
                               service->txt ? service->txt : "");
}

/**
 * Upon resceiving the USR1 signal, print local services
 */
void print_services(int signal) {
    ServiceInfo *i;
    FILE *f = NULL;

    if (!(f = fopen(arguments.output_file, "w+"))) {
        WARN("Could not open %s. Using stdout instead.", arguments.output_file);
        f = stdout;
    }

    for (i = services; i; i = i->info_next) {
        if (i->resolved)
            _print_service(f, i);
    }

    if (f != stdout) {
        fclose(f);
    }
}

/**
 * Verify the Serval signature in a service announcement
 * @param i the service to verify (includes signature and fingerprint txt fields)
 * @returns 0 if the signature is valid, 1 if it is invalid
 */
int verify_announcement(ServiceInfo *i) {
  AvahiStringList *txt;
  co_obj_t *co_conn = NULL, *co_req = NULL, *co_resp = NULL;
  char *to_verify = NULL;
  char **types_list = NULL;
  int types_list_len = 0;
  char *key, *val, *app, *uri, *icon, *desc, *sid, *sig;
  unsigned int ttl = 0;
  unsigned long lifetime = 0;
  int j, verdict = 1, to_verify_len = 0;
  size_t val_len;
  
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
  
  to_verify = createSigningTemplate(
    i->type,
    i->domain,
    i->port,
    app,
    ttl,
    uri,
    (const char**)types_list,
    types_list_len,
    icon,
    desc,
    lifetime,
    &to_verify_len);
  
  /* Is the signature valid? 0=yes, 1=no */
  if (to_verify) {
    char sas_buf[2*SAS_SIZE+1] = {0};
    
    CHECK(keyring_send_sas_request_client(sid,strlen(sid),sas_buf,2*SAS_SIZE+1),"Failed to fetch signing key");
    
    bool output;
    CHECK((co_conn = co_connect(arguments.co_sock,strlen(arguments.co_sock)+1)),"Failed to connect to Commotion socket");
    CHECK_MEM((co_req = co_request_create()));
    CO_APPEND_STR(co_req,"verify");
    CO_APPEND_STR(co_req,sas_buf);
    CO_APPEND_STR(co_req,sig);
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
  if (types_list) {
    for (j = 0; j <types_list_len; ++j)
      avahi_free(types_list[j]);
    free(types_list);
  }
  if (to_verify)
    free(to_verify);
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
  return verdict;
}

/**
 * Handler called whenever a service is (potentially) resolved
 * @param userdata the ServiceFile object of the service in question
 * @note if compiled with UCI support, write the service to UCI if
 *       it successfully resolves
 * @note if txt fields fail verification, the service is removed from
 *       the local list
 */
void resolve_callback(
    AvahiSServiceResolver *r,
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
    char *lifetime_str = NULL;
    char *val = NULL;
    size_t val_size = 0;
    struct timeval tv;
    time_t current_time;
    char* c_time_string;
    struct tm *timestr;
    long lifetime = 0, expiration;
    
    assert(r);

    switch (event) {
        case AVAHI_RESOLVER_FAILURE:
            ERROR("(Resolver) Failed to resolve service '%s' of type '%s' in domain '%s': %s", name, type, domain, avahi_strerror(avahi_server_errno(server)));
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
	    
	    /* Validate TTL field */
	    avahi_string_list_get_pair(avahi_string_list_find(txt,"ttl"),NULL,&val,NULL);
	    if (!isValidTtl(val)) {
	      WARN("(Resolver) Invalid TTL value: %s -> %s",name,val);
	      avahi_free(val);
	      break;
	    }
	    avahi_free(val);
	    
	    /* Validate lifetime field */
	    avahi_string_list_get_pair(avahi_string_list_find(txt,"lifetime"),NULL,&lifetime_str,NULL);
	    lifetime = atol(lifetime_str);
	    if (!isValidLifetime(lifetime_str)) {
	      WARN("(Resolver) Invalid lifetime value: %s -> %s",name,lifetime_str);
	      avahi_free(lifetime_str);
	      break;
	    }
	    avahi_free(lifetime_str);
	    
	    /* Validate fingerprint field */
	    avahi_string_list_get_pair(avahi_string_list_find(txt,"fingerprint"),NULL,&val,&val_size);
	    if (!isValidFingerprint(val,val_size)) {
	      WARN("(Resolver) Invalid fingerprint: %s -> %s",name,val);
	      avahi_free(val);
	      break;
	    }
	    avahi_free(val);
	    
	    /* Validate (but not verify) signature field */
	    avahi_string_list_get_pair(avahi_string_list_find(txt,"signature"),NULL,&val,&val_size);
	    if (!isValidSignature(val,val_size)) {
	      WARN("(Resolver) Invalid signature: %s -> %s",name,val);
	      avahi_free(val);
	      break;
	    }
	    avahi_free(val);
	    
	    // TODO: check connectivity, using commotiond socket library
	    
	    /* Verify signature */
	    if (verify_announcement(i)) {
	      INFO("Announcement signature verification failed");
	      break;
	    } else
	      INFO("Announcement signature verification succeeded");
	    
	    /* Set expiration timer on the service */
	    expiration = default_lifetime();
	    if (lifetime > 0 && (expiration > lifetime || expiration == 0)) expiration = lifetime;
	    if (expiration > 0) {
	      avahi_elapse_time(&tv, 1000*expiration, 0);
	      current_time = time(NULL);
	      i->timeout = avahi_simple_poll_get(simple_poll)->timeout_new(avahi_simple_poll_get(simple_poll), &tv, remove_service, i); // create expiration event for service
	    
	      /* Convert expiration period into timestamp */
	      if (current_time != ((time_t)-1)) {
	        timestr = localtime(&current_time);
		timestr->tm_sec += expiration;
	        current_time = mktime(timestr);
	        if ((c_time_string = ctime(&current_time))) {
		  c_time_string[strlen(c_time_string)-1] = '\0'; /* ctime adds \n to end of time string; remove it */
	          i->txt_lst = avahi_string_list_add_printf(i->txt_lst,"expiration=%s",c_time_string);
	        }
	      }
	    }
	    
	    if (!(i->txt = txt_list_to_string(i->txt_lst))) {
	      ERROR("(Resolver) Could not convert txt fields to string");
	      break;
	    }
	    
#ifdef USE_UCI
	    if (arguments.uci && uci_write(i) < 0)
	      ERROR("(Resolver) Could not write to UCI");
#endif
            
            i->resolved = 1;
        }
    }
    avahi_s_service_resolver_free(i->resolver);
    i->resolver = NULL;
    if (event == AVAHI_RESOLVER_FOUND && !i->resolved) {
      remove_service(NULL, i);
    }
}

/**
 * Handler for Avahi service browser events. Called whenever a new 
 * services becomes available on the LAN or is removed from the LAN
 */
void browse_service_callback(
    AvahiSServiceBrowser *b,
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

            ERROR("(Browser) %s", avahi_strerror(avahi_server_errno(server)));
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
                add_service(interface, protocol, name, type, domain);
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
    }
}

/**
 * Handler for creating Avahi service browser
 */
void browse_type_callback(
    AvahiSServiceTypeBrowser *b,
    AvahiIfIndex interface,
    AvahiProtocol protocol,
    AvahiBrowserEvent event,
    const char *type,
    const char *domain,
    AVAHI_GCC_UNUSED AvahiLookupResultFlags flags,
    void* userdata) {

    AvahiServer *s = (AvahiServer*)userdata;
    assert(b);

    INFO("Type browser got an event: %d", event);
    switch (event) {
        case AVAHI_BROWSER_FAILURE:
            ERROR("(Browser) %s", 
                avahi_strerror(avahi_server_errno(s)));
            avahi_simple_poll_quit(simple_poll);
            return;
        case AVAHI_BROWSER_NEW:
            if (!avahi_s_service_browser_new(s, 
                                           AVAHI_IF_UNSPEC, 
                                           AVAHI_PROTO_UNSPEC, 
                                           type, 
                                           domain, 
                                           0, 
                                           browse_service_callback, 
                                           s)) {
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
    }
}