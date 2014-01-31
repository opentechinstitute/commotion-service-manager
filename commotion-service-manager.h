/**
 *       @file  commotion-service-manager.h
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

#ifndef COMMOTION_SERVICE_MANAGER_H
#define COMMOTION_SERVICE_MANAGER_H

#include <stdlib.h>

#include <avahi-common/simple-watch.h>
#include <avahi-common/llist.h>
#include <avahi-core/core.h>
#include <avahi-core/lookup.h>
#ifdef CLIENT
#include <avahi-client/client.h>
#include <avahi-client/lookup.h>
#endif

/** Length (in hex chars) of Serval IDs */
#define FINGERPRINT_LEN 64
/** Length (in hex chars) of Serval-created signatures */
#define SIG_LENGTH 128

/** Name of file to output list of services when daemon receives USR1 signal */
#define DEFAULT_FILENAME "/tmp/local-services.out"
#define PIDFILE "/var/run/commotion/commotion-service-manager.pid"
/** Directory where Avahi service files are stored */
#define avahiDir "/etc/avahi/services/"

#ifndef SERVAL_PATH
#define SERVAL_PATH "/var/serval-node/serval.keyring"
#endif

#define DEFAULT_CO_SOCK "/var/run/commotiond.sock"

#ifdef CLIENT
#define TYPE_BROWSER AvahiServiceTypeBrowser
#define TYPE_BROWSER_NEW(A,B,C,D,E) avahi_service_type_browser_new(client,A,B,C,D,E,client)
#define TYPE_BROWSER_FREE(J) avahi_service_type_browser_free(J)
#define BROWSER AvahiServiceBrowser
#define BROWSER_NEW(A,B,C,D,E,F) avahi_service_browser_new(client,A,B,C,D,E,F,client)
#define RESOLVER AvahiServiceResolver
#define RESOLVER_NEW(A,B,C,D,E,F,G,H,I) avahi_service_resolver_new(client,A,B,C,D,E,F,G,H,I)
#define RESOLVER_FREE(J) avahi_service_resolver_free(J)
#define AVAHI_ERROR avahi_strerror(avahi_client_errno(client))
#define AVAHI_BROWSER_ERROR avahi_strerror(avahi_client_errno(avahi_service_browser_get_client(b)))
#define FREE_AVAHI() if (client) avahi_client_free(client);
#else
#define TYPE_BROWSER AvahiSServiceTypeBrowser
#define TYPE_BROWSER_NEW(A,B,C,D,E) avahi_s_service_type_browser_new(server,A,B,C,D,E,server)
#define TYPE_BROWSER_FREE(J) avahi_s_service_type_browser_free(J)
#define BROWSER AvahiSServiceBrowser
#define BROWSER_NEW(A,B,C,D,E,F) avahi_s_service_browser_new(server,A,B,C,D,E,F,server)
#define RESOLVER AvahiSServiceResolver
#define RESOLVER_NEW(A,B,C,D,E,F,G,H,I) avahi_s_service_resolver_new(server,A,B,C,D,E,F,G,H,I)
#define RESOLVER_FREE(J) avahi_s_service_resolver_free(J)
#define AVAHI_ERROR avahi_strerror(avahi_server_errno(server))
#define AVAHI_BROWSER_ERROR AVAHI_ERROR
#define FREE_AVAHI() if (server) avahi_server_free(server);
#endif

struct arguments {
  char *co_sock;
  #ifdef USE_UCI
  int uci;
  #endif
  int nodaemon;
  char *output_file;
  char *pid_file;
};

typedef struct ServiceInfo ServiceInfo;
/** Struct used to hold info about a service */
struct ServiceInfo {
    AvahiIfIndex interface;
    AvahiProtocol protocol;
    char *name, 
         *type, 
         *domain, 
	 *host_name, 
	 *txt; /**< string representing all the txt fields */
    char address[AVAHI_ADDRESS_STR_MAX];
    uint16_t port;
    AvahiStringList *txt_lst; /**< Collection of all the user-defined txt fields */
    AvahiTimeout *timeout; /** Timer set for the service's expiration date */

    RESOLVER *resolver;
    int resolved; /**< Flag indicating whether all the fields have been resolved */

    AVAHI_LLIST_FIELDS(ServiceInfo, info);
};

// TODO document these

ServiceInfo *find_service(const char *name);
ServiceInfo *add_service(BROWSER *b, AvahiIfIndex interface, AvahiProtocol protocol, const char *name, const char *type, const char *domain);
void remove_service(AvahiTimeout *t, void *userdata);
void print_services(int signal);
void sig_handler(int signal);

#endif
