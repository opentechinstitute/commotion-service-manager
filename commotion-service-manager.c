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
#include <ctype.h>
#include <argp.h>

#include <serval-crypto.h>

#include <avahi-common/malloc.h>
#include <avahi-common/error.h>

#include "commotion-service-manager.h"
#include "util.h"
#include "uci-utils.h"
#include "debug.h"

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

static ServiceInfo *find_service(const char *name) {
  ServiceInfo *i;
  
  for (i = services; i; i = i->info_next)
    if (strcasecmp(i->name, name) == 0)
      return i;
    
    return NULL;
}

static ServiceInfo *add_service(AvahiIfIndex interface, AvahiProtocol protocol, const char *name, const char *type, const char *domain) {
    ServiceInfo *i;

    i = avahi_new0(ServiceInfo, 1);

    if (!(i->resolver = avahi_s_service_resolver_new(server, interface, protocol, name, type, domain, AVAHI_PROTO_UNSPEC, 0, resolve_callback, i))) {
        avahi_free(i);
        LOG("ADD_SERVICE", "Failed to resolve service '%s' of type '%s' in domain '%s': %s\n", name, type, domain, avahi_strerror(avahi_server_errno(server)));
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

static void remove_service(AvahiTimeout *t, void *userdata) {
    assert(userdata);
    ServiceInfo *i = (ServiceInfo*)userdata;

    LOG("Remove_Service","Removing service announcement: %s\n",i->name);
    
    /* Cancel expiration event */
    if (!t && i->timeout)
      avahi_simple_poll_get(simple_poll)->timeout_update(i->timeout,NULL);
    
    if (arguments.uci && uci_remove(i))
      ERROR("(Remove_Service) Could not remove from UCI\n");
    
    AVAHI_LLIST_REMOVE(ServiceInfo, info, services, i);

    if (i->resolver)
        avahi_s_service_resolver_free(i->resolver);

    avahi_free(i->name);
    avahi_free(i->type);
    avahi_free(i->domain);
    avahi_free(i->host_name);
    avahi_free(i->txt);
    avahi_free(i->txt_lst);
    avahi_free(i);
}

static void print_service(FILE *f, ServiceInfo *service) {
    char a[AVAHI_ADDRESS_STR_MAX];
    char interface_string[IF_NAMESIZE];
    const char *protocol_string;

    if (!if_indextoname(service->interface, interface_string))
        WARN("Could not resolve the interface name!\n");

    if (!(protocol_string = avahi_proto_to_string(service->protocol)))
        WARN("Could not resolve the protocol name!\n");

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

static void sig_handler(int signal) {
    ServiceInfo *i;
    FILE *f = NULL;

    if (!(f = fopen(arguments.output_file, "w+"))) {
        WARN("Could not open %s. Using stdout instead.\n", arguments.output_file);
        f = stdout;
    }

    for (i = services; i; i = i->info_next) {
        if (i->resolved)
            print_service(f, i);
    }

    // TODO: For OpenWRT: check known_applications list, approved or blacklisted
    
    if (f != stdout) {
        fclose(f);
    }
}

static int verify_announcement(ServiceInfo *i) {
  char type_template[] = "<txt-record>type=%s</txt-record>";
  char template[] = "<type>%s</type>\n\
  <domain-name>%s</domain-name>\n\
  <port>%d</port>\n\
  <txt-record>application=%s</txt-record>\n\
  <txt-record>ttl=%s</txt-record>\n\
  <txt-record>ipaddr=%s</txt-record>\n\
  %s\n\
  <txt-record>icon=%s</txt-record>\n\
  <txt-record>description=%s</txt-record>\n\
  <txt-record>expiration=%s</txt-record>";
  AvahiStringList *txt;
  char *msg = NULL;
  char *type_str = NULL;
  char *type = NULL;
  char **types_list = NULL;
  int types_list_len = 0;
  char *key, *val, *app, *ttl, *ipaddr, *icon, *desc, *expr, *sid, *sig;
  int j, verdict = 1;
  size_t val_len;
  
  assert(i->txt_lst);
  
  txt = i->txt_lst;
  do {
    if (avahi_string_list_get_pair(txt,&key,&val,&val_len))
      continue;
    if (!strcmp(key,"type")) {
      CHECK_MEM((types_list = (char**)realloc(types_list,(types_list_len + 1)*sizeof(char*))));
      types_list[types_list_len] = val;
      types_list_len++;
    } else if (!strcmp(key,"application")) {
      app = val;
    } else if (!strcmp(key,"ttl")) {
      ttl = val;
    } else if (!strcmp(key,"ipaddr")) {
      ipaddr = val;
    } else if (!strcmp(key,"icon")) {
      icon = val;
    } else if (!strcmp(key,"description")) {
      desc = val;
    } else if (!strcmp(key,"expiration")) {
      expr = val;
    } else if (!strcmp(key,"fingerprint")) {
      sid = val;
    } else if (!strcmp(key,"signature")) {
      sig = val;
    }
  } while (txt = avahi_string_list_get_next(txt));
  
  qsort(&types_list[0],types_list_len,sizeof(char*),cmpstringp); /* Sort types into alphabetical order */
  
  for (j = 0; j < types_list_len; ++j) {
    if (type)
      free(type);
    int prev_len = type_str ? strlen(type_str) : 0;
    CHECK_MEM(asprintf(&type,type_template,types_list[j]) != -1 &&
      (type_str = (char*)realloc(type_str,prev_len + strlen(type) + 1)));
    if (prev_len)
      strcat(type_str,type);
    else
      strcpy(type_str,type);
  }
  
  CHECK_MEM(asprintf(&msg,template,i->type,i->domain,i->port,app,ttl,ipaddr,type_str,icon,desc,expr) != -1);
  
  verdict = verify(sid,strlen(sid),msg,strlen(msg),sig,strlen(sig));
  //DEBUG("%s\n",msg);
  
error:
  if (type)
    free(type);
  if (type_str)
    free(type_str);
  if (types_list)
    free(types_list);
  return verdict;
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
    char *expiration_str = NULL;
    char *val = NULL;
    size_t val_size = 0;
    struct timeval tv;
    time_t current_time;
    char* c_time_string;
    struct tm *timestr;
    
    assert(r);

    switch (event) {
        case AVAHI_RESOLVER_FAILURE:
            ERROR("(Resolver) Failed to resolve service '%s' of type '%s' in domain '%s': %s\n", name, type, domain, avahi_strerror(avahi_server_errno(server)));
            break;

        case AVAHI_RESOLVER_FOUND: {
            avahi_address_snprint(i->address, 
                sizeof(i->address),
                address);
	    i->host_name = strdup(host_name);
	    if (port < 0 || port > 65535) {
	      WARN("(Resolver) Invalid port: %s\n",name);
	      break;
	    }
	    i->port = port;
	    i->txt_lst = avahi_string_list_copy(txt);
	    
	    if (!avahi_string_list_find(txt,"application") ||
	      !avahi_string_list_find(txt,"icon") ||
	      !avahi_string_list_find(txt,"description") ||
	      !avahi_string_list_find(txt,"ttl") ||
	      !avahi_string_list_find(txt,"expiration") ||
	      !avahi_string_list_find(txt,"signature") ||
	      !avahi_string_list_find(txt,"fingerprint")) {
	      WARN("(Resolver) Missing TXT field(s): %s\n", name);
	      break;
	    }
	    
	    avahi_string_list_get_pair(avahi_string_list_find(txt,"ttl"),NULL,&val,NULL);
	    if (!isNumeric(val) || atoi(val) < 0) {
	      WARN("(Resolver) Invalid TTL value: %s -> %s\n",name,val);
	      break;
	    }
	    
	    avahi_string_list_get_pair(avahi_string_list_find(txt,"expiration"),NULL,&expiration_str,NULL);
	    if (!isNumeric(expiration_str) || atoi(expiration_str) < 0) {
	      WARN("(Resolver) Invalid expiration value: %s -> %s\n",name,expiration_str);
	      break;
	    }
	    
	    avahi_string_list_get_pair(avahi_string_list_find(txt,"fingerprint"),NULL,&val,&val_size);
	    if (val_size != FINGERPRINT_LEN && !isHex(val,val_size)) {
	      WARN("(Resolver) Invalid fingerprint: %s -> %s\n",name,val);
	      break;
	    }
	    
	    avahi_string_list_get_pair(avahi_string_list_find(txt,"signature"),NULL,&val,&val_size);
	    if (val_size != SIG_LENGTH && !isHex(val,val_size)) {
	      WARN("(Resolver) Invalid signature: %s -> %s\n",name,val);
	      break;
	    }

	    // TODO: check connectivity, using commotiond socket library
	    
	    // TODO: verify signature, using commotiond serval key mgmt API

	    if (verify_announcement(i)) {
	      LOG("Resolver","Announcement signature verification failed\n");
	      break;
	    } else
	      LOG("Resolver","Announcement signature verification succeeded\n");

	    avahi_elapse_time(&tv, 1000*atoi(expiration_str), 0);
	    current_time = time(NULL);
	    i->timeout = avahi_simple_poll_get(simple_poll)->timeout_new(avahi_simple_poll_get(simple_poll), &tv, remove_service, i); // create expiration event for service
	    
	    /* Convert expiration period into timestamp */
	    if (current_time != ((time_t)-1)) {
	      timestr = localtime(&current_time);
	      timestr->tm_sec += atoi(expiration_str);
	      current_time = mktime(timestr);
	      if (c_time_string = ctime(&current_time))
		c_time_string[strlen(c_time_string)-1] = '\0'; /* ctime adds \n to end of time string; remove it */
	        i->txt_lst = avahi_string_list_add_printf(i->txt_lst,"expiration_time=%s",c_time_string);
	    }
	    
	    if (!(i->txt = txt_list_to_string(i->txt_lst))) {
	      ERROR("(Resolver) Could not convert txt fields to string\n");
	      break;
	    }
	    
	    if (arguments.uci && uci_write(i)) {
	      ERROR("(Resolver) Could not write to UCI\n");
	    }
            
            i->resolved = 1;
        }
    }
    avahi_s_service_resolver_free(i->resolver);
    i->resolver = NULL;
    if (event == AVAHI_RESOLVER_FOUND && !i->resolved) {
      remove_service(NULL, i);
    }
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

            ERROR("(Browser) %s\n", avahi_strerror(avahi_server_errno(server)));
            avahi_simple_poll_quit(simple_poll);
            return;

        case AVAHI_BROWSER_NEW:
        case AVAHI_BROWSER_REMOVE: {
            ServiceInfo *found_service = NULL;
            LOG("Browser","%s: service '%s' of type '%s' in domain '%s'\n",event == AVAHI_BROWSER_NEW ? "NEW" : "REMOVE", name, type, domain);

            //found_service=find_service(interface, protocol, name, type, domain);
	    found_service=find_service(name); // name is fingerprint, so should be unique
            if (event == AVAHI_BROWSER_NEW && !found_service) {
                /* add the service.
                 */
                add_service(interface, protocol, name, type, domain);
            }
            if (event == AVAHI_BROWSER_REMOVE && found_service) {
                /* remove the service.
                 */
                remove_service(NULL, found_service);
            }
            break;
        }
        case AVAHI_BROWSER_CACHE_EXHAUSTED:
            INFO("(Browser) %s\n", "CACHE_EXHAUSTED");
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

    INFO("Type browser got an event: %d\n", event);
    switch (event) {
        case AVAHI_BROWSER_FAILURE:
            ERROR("(Browser) %s\n", 
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
                                "browser for type (%s) in domain (%s)\n", 
                                                                type, 
                                                                domain);
                avahi_simple_poll_quit(simple_poll);
            }
            break;
        case AVAHI_BROWSER_CACHE_EXHAUSTED:
            INFO("Cache exhausted\n");
            break;
    }
}

static error_t parse_opt (int key, char *arg, struct argp_state *state) {
  struct arguments *arguments = state->input;

  switch (key) {
    case 'u':
      arguments->uci = 1;
      break;
    case 'o':
      arguments->output_file = arg;
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

int main(int argc, char*argv[]) {
    AvahiServerConfig config;
    AvahiSServiceTypeBrowser *stb = NULL;
    struct timeval tv;
    int error;
    int ret = 1;

    const char *argp_program_version = "1.0";
    static char doc[] = "Commotion Service Manager";
    static struct argp_option options[] = {
      {"uci", 'u', 0, 0, "Store service cache in UCI" },
      {"out", 'o', "FILE", 0, "Output file to write services to when USR1 signal is received" },
      { 0 }
    };
    
    /* Set defaults */
    arguments.uci = 0;
    arguments.output_file = DEFAULT_FILENAME;
    
    static struct argp argp = { options, parse_opt, NULL, doc };
    
    argp_parse (&argp, argc, argv, 0, 0, &arguments);
    //fprintf(stdout,"uci: %d, out: %s\n",arguments.uci,arguments.output_file);
    
    signal(SIGUSR1, sig_handler);

    /* Initialize the psuedo-RNG */
    srand(time(NULL));

    /* Allocate main loop object */
    CHECK((simple_poll = avahi_simple_poll_new()),"Failed to create simple poll object.\n");

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
    CHECK(server,"Failed to create server: %s\n", avahi_strerror(error));

    /* Create the service browser */
    CHECK((stb = avahi_s_service_type_browser_new(server, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, "mesh.local", 0, browse_type_callback, server)),
        "Failed to create service browser: %s\n", avahi_strerror(avahi_server_errno(server)));
    
    /* Run the main loop */
    avahi_simple_poll_loop(simple_poll);
    
    ret = 0;

error:

    /* Cleanup things */
    if (stb)
        avahi_s_service_type_browser_free(stb);

    if (server)
        avahi_server_free(server);

    if (simple_poll)
        avahi_simple_poll_free(simple_poll);

    return ret;
}
