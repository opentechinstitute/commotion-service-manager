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
#include <avahi-core/core.h>
#include <avahi-core/lookup.h>
#ifdef CLIENT
#include <avahi-client/client.h>
#include <avahi-client/lookup.h>
#endif

#include "commotion.h"

#include "commotion-service-manager.h"
#include "browse.h"
#include "debug.h"

#ifdef USE_UCI
#include <uci.h>
#include "uci-utils.h"
#endif

/** Linked list of all the local services */
ServiceInfo *services = NULL;

extern AvahiSimplePoll *simple_poll;
#ifndef CLIENT
extern AvahiServer *server;
#endif

extern struct arguments arguments;

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
ServiceInfo *add_service(BROWSER *b, AvahiIfIndex interface, AvahiProtocol protocol, const char *name, const char *type, const char *domain) {
    ServiceInfo *i;
    
#ifdef CLIENT
    AvahiClient *client = avahi_service_browser_get_client(b);
#endif

    i = avahi_new0(ServiceInfo, 1);

    if (!(i->resolver = RESOLVER_NEW(interface, protocol, name, type, domain, AVAHI_PROTO_UNSPEC, 0, resolve_callback, i))) {
        avahi_free(i);
        INFO("Failed to create resolver for service '%s' of type '%s' in domain '%s': %s", name, type, domain, AVAHI_ERROR);
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
    if (t && is_local(i)) {
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
        RESOLVER_FREE(i->resolver);

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
