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

static AvahiSimplePoll *simple_poll = NULL;
static AvahiServer *server = NULL;

/** Struct used to hold info about a service */
typedef struct ServiceInfo ServiceInfo;
/** Linked list of all the local services */
static struct ServiceInfo {
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
} *services;

#endif