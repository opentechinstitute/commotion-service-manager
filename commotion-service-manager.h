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

#include <avahi-core/lookup.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/llist.h>

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

struct arguments {
  #ifdef USE_UCI
  int uci;
  #endif
  int nodaemon;
  char *output_file;
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

    AvahiSServiceResolver *resolver;
    int resolved; /**< Flag indicating whether all the fields have been resolved */

    AVAHI_LLIST_FIELDS(ServiceInfo, info);
};

/** Linked list of all the local services */
extern ServiceInfo *services;
extern AvahiSimplePoll *simple_poll;
extern AvahiServer *server;

// TODO document these
void browse_type_callback(
    AvahiSServiceTypeBrowser *b,
    AvahiIfIndex interface,
    AvahiProtocol protocol,
    AvahiBrowserEvent event,
    const char *type,
    const char *domain,
    AVAHI_GCC_UNUSED AvahiLookupResultFlags flags,
    void* userdata);
void browse_service_callback(
    AvahiSServiceBrowser *b,
    AvahiIfIndex interface,
    AvahiProtocol protocol,
    AvahiBrowserEvent event,
    const char *name,
    const char *type,
    const char *domain,
    AVAHI_GCC_UNUSED AvahiLookupResultFlags flags,
    void* userdata);
ServiceInfo *find_service(const char *name);
ServiceInfo *add_service(AvahiIfIndex interface, AvahiProtocol protocol, const char *name, const char *type, const char *domain);
void remove_service(AvahiTimeout *t, void *userdata);
int verify_announcement(ServiceInfo *i);
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
  void* userdata);
void print_service(FILE *f, ServiceInfo *service);
void sig_handler(int signal);

#endif