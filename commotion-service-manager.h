#ifndef COMMOTION_SERVICE_MANAGER_H
#define COMMOTION_SERVICE_MANAGER_H

#include <stdlib.h>

#include <avahi-core/lookup.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/llist.h>

#define FINGERPRINT_LEN 64
#define SIG_LENGTH 128

#define DEFAULT_FILENAME "/tmp/local-services.out"
#define PIDFILE "/var/run/commotion/commotion-service-manager.pid"
#define avahiDir "/etc/avahi/services/"

static AvahiSimplePoll *simple_poll = NULL;
static AvahiServer *server = NULL;

/*
 * This is a compiler trick for the LLIST
 * macros to work.
 */
typedef struct ServiceInfo ServiceInfo;
static struct ServiceInfo {
    AvahiIfIndex interface;
    AvahiProtocol protocol;
    char *name, *type, *domain, *host_name, *txt;
    char address[AVAHI_ADDRESS_STR_MAX];
    uint16_t port;
    AvahiStringList *txt_lst;
    AvahiTimeout *timeout;

    AvahiSServiceResolver *resolver;
    int resolved;

    AVAHI_LLIST_FIELDS(ServiceInfo, info);
} *services;

#endif