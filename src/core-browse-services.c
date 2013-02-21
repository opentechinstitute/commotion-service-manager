#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <net/if.h>
#include <string.h>
#include <signal.h>

#include <avahi-core/core.h>
#include <avahi-core/lookup.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>
#include <avahi-common/llist.h>

#include "escape.h"
#include "concat.h"

static AvahiSimplePoll *simple_poll = NULL;
static AvahiServer *server = NULL;
static char *g_filename = NULL;
#define DEFAULT_FILENAME "/tmp/avahi-client.out"

/*
 * This is a compiler trick for the LLIST
 * macros to work.
 */
typedef struct ServiceInfo ServiceInfo;
typedef struct ServiceInfo {
    AvahiIfIndex interface;
    AvahiProtocol protocol;
    char *name, *type, *domain, *host_name, *txt;
    char address[AVAHI_ADDRESS_STR_MAX];
    uint16_t port;

    AvahiSServiceResolver *resolver;
    int resolved;

    AVAHI_LLIST_FIELDS(ServiceInfo, info);
};
static ServiceInfo *services;

static void resolve_callback(
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

static ServiceInfo *find_service(AvahiIfIndex interface, AvahiProtocol protocol, const char *name, const char *type, const char *domain) {
    ServiceInfo *i;

    for (i = services; i; i = i->info_next)
        if (i->interface == interface &&
            i->protocol == protocol &&
            strcasecmp(i->name, name) == 0 &&
            avahi_domain_equal(i->type, type) &&
            avahi_domain_equal(i->domain, domain))

            return i;

    return NULL;
}

static ServiceInfo *add_service(AvahiIfIndex interface, AvahiProtocol protocol, const char *name, const char *type, const char *domain) {
    ServiceInfo *i;

    i = avahi_new0(ServiceInfo, 1);

    if (!(i->resolver = avahi_s_service_resolver_new(server, interface, protocol, name, type, domain, AVAHI_PROTO_UNSPEC, 0, resolve_callback, i))) {
        avahi_free(i);
        fprintf(stderr, "Failed to resolve service '%s' of type '%s' in domain '%s': %s\n", name, type, domain, avahi_strerror(avahi_server_errno(server)));
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

static void remove_service(ServiceInfo *i) {
    assert(i);

    AVAHI_LLIST_REMOVE(ServiceInfo, info, services, i);

    if (i->resolver)
        avahi_s_service_resolver_free(i->resolver);

    avahi_free(i->name);
    avahi_free(i->type);
    avahi_free(i->domain);
    avahi_free(i->host_name);
    avahi_free(i->txt);
    avahi_free(i);
}


static void print_service(FILE *f, ServiceInfo *service) {
    char a[AVAHI_ADDRESS_STR_MAX];
    char interface_string[IF_NAMESIZE];
    const char *protocol_string;

    if (!if_indextoname(service->interface, interface_string)) {
        fprintf(stderr, "Could not resolve the interface name!\n");
    }
    if (!(protocol_string = avahi_proto_to_string(service->protocol))) {
        fprintf(stderr, "Could not resolve the protocol name!\n");
    }
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

void sig_handler(int signal) {
    ServiceInfo *i;
    FILE *f = NULL;

    if (!(f = fopen(g_filename, "w+"))) {
        fprintf(stderr, "Could not open %s. Using stdout instead.\n", g_filename);
        f = stdout;
    }

    for (i = services; i; i = i->info_next) {
        if (i->resolved)
            print_service(f, i);
    }

    if (f != stdout) {
        fclose(f);
    }
}
static void resolve_callback(
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
    assert(r);

    switch (event) {
        case AVAHI_RESOLVER_FAILURE:
            fprintf(stderr, "(Resolver) Failed to resolve service '%s' of type '%s' in domain '%s': %s\n", name, type, domain, avahi_strerror(avahi_server_errno(server)));
            break;

        case AVAHI_RESOLVER_FOUND: {
            if (!(i->txt = txt_list_to_string(txt))) {
                fprintf(stderr, "Could not resolve the text field!\n");
            }
                
            avahi_address_snprint(i->address, 
                sizeof(i->address),
                address);
            i->port = port;
            i->host_name = strdup(host_name);
            i->resolved = 1;
        }
    }
    avahi_s_service_resolver_free(i->resolver);
    i->resolver = NULL;
}
static void browse_service_callback(
    AvahiSServiceBrowser *b,
    AvahiIfIndex interface,
    AvahiProtocol protocol,
    AvahiBrowserEvent event,
    const char *name,
    const char *type,
    const char *domain,
    AVAHI_GCC_UNUSED AvahiLookupResultFlags flags,
    void* userdata) {

    AvahiServer *s = userdata;
    assert(b);

    /* Called whenever a new services becomes available on the LAN or is removed from the LAN */

    switch (event) {

        case AVAHI_BROWSER_FAILURE:

            fprintf(stderr, "(Browser) %s\n", avahi_strerror(avahi_server_errno(server)));
            avahi_simple_poll_quit(simple_poll);
            return;

        case AVAHI_BROWSER_NEW:
        case AVAHI_BROWSER_REMOVE: {
            ServiceInfo *found_service = NULL;
            fprintf(stderr, "(Browser) %s: service '%s' of type '%s' in domain '%s'\n",event == AVAHI_BROWSER_NEW ? "NEW" : "REMOVE", name, type, domain);

            found_service=find_service(interface, protocol, name, type, domain);
            if (event == AVAHI_BROWSER_NEW && !found_service) {
                /* add the service.
                 */
                add_service(interface, protocol, name, type, domain);
            }
            if (event == AVAHI_BROWSER_REMOVE && found_service) {
                /* remove the service.
                 */
                remove_service(found_service);
            }
            break;
        }
        case AVAHI_BROWSER_CACHE_EXHAUSTED:
            fprintf(stderr, "(Browser) %s\n", "CACHE_EXHAUSTED");
            break;
    }
}

static void browse_type_callback(
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

    fprintf(stderr, "Type browser got an event: %d\n", event);
    switch (event) {
        case AVAHI_BROWSER_FAILURE:
            fprintf(stderr, "(Browser) %s\n", 
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
                fprintf(stderr, "Service Browser: Failed to create a service " 
                                "browser for type (%s) in domain (%s)\n", 
                                                                type, 
                                                                domain);
                avahi_simple_poll_quit(simple_poll);
            }
            break;
        case AVAHI_BROWSER_CACHE_EXHAUSTED:
            fprintf(stderr, "Cache exhausted\n");
            break;
    }
}


int main(int argc, char*argv[]) {
    AvahiServerConfig config;
    AvahiSServiceTypeBrowser *stb = NULL;
    int error;
    int ret = 1;

    if (argc == 2) {
        /* 
         * we are going to use this for our filename.
         */
        g_filename = strdup(argv[1]);
    }
    else {
        g_filename = DEFAULT_FILENAME;
    }
    fprintf(stderr, "g_filename: %s\n", g_filename);

    signal(SIGUSR1, sig_handler);

    /* Initialize the psuedo-RNG */
    srand(time(NULL));

    /* Allocate main loop object */
    if (!(simple_poll = avahi_simple_poll_new())) {
        fprintf(stderr, "Failed to create simple poll object.\n");
        goto fail;
    }

    /* Do not publish any local records */
    avahi_server_config_init(&config);
    config.publish_hinfo = 0;
    config.publish_addresses = 0;
    config.publish_workstation = 0;
    config.publish_domain = 0;

    /* Set a unicast DNS server for wide area DNS-SD */
    avahi_address_parse("192.168.50.1", AVAHI_PROTO_UNSPEC, &config.wide_area_servers[0]);
    config.n_wide_area_servers = 1;
    config.enable_wide_area = 1;

    /* Allocate a new server */
    server = avahi_server_new(avahi_simple_poll_get(simple_poll), &config, NULL, NULL, &error);

    /* Free the configuration data */
    avahi_server_config_free(&config);

    /* Check wether creating the server object succeeded */
    if (!server) {
        fprintf(stderr, "Failed to create server: %s\n", avahi_strerror(error));
        goto fail;
    }

    /* Create the service browser */
    if (!(stb = avahi_s_service_type_browser_new(server, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, "mesh.local", 0, browse_type_callback, server))) {
        fprintf(stderr, "Failed to create service browser: %s\n", avahi_strerror(avahi_server_errno(server)));
        goto fail;
    }

    /* Run the main loop */
    avahi_simple_poll_loop(simple_poll);

    ret = 0;

fail:

    /* Cleanup things */
    if (stb)
        avahi_s_service_type_browser_free(stb);

    if (server)
        avahi_server_free(server);

    if (simple_poll)
        avahi_simple_poll_free(simple_poll);

    return ret;
}
