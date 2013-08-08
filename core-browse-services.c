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

#include <uci.h>

#include <serval-crypto.h>

#include <avahi-core/core.h>
#include <avahi-core/lookup.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>
#include <avahi-common/llist.h>
#include <avahi-common/timeval.h>
#include <avahi-common/watch.h>

#include "escape.h"
#include "concat.h"

#define FINGERPRINT_LEN 64
#define SIG_LENGTH 128

static AvahiSimplePoll *simple_poll = NULL;
static AvahiServer *server = NULL;
struct arguments {
  int uci;
  char *output_file;
} arguments;
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
    AvahiStringList *txt_lst;
    AvahiTimeout *timeout;

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

static int isHex(const char *str, size_t len) {
  int i;
  for (i = 0; i < len; ++i) {
    if (!isxdigit(str[i]))
      return 0;
  }
  return 1;
}

static int isNumeric (const char *s)
{
  if (s == NULL || *s == '\0' || isspace(*s))
    return 0;
  char * p;
  strtod (s, &p);
  return *p == '\0';
}

static int isUCIEncoded(const char *s, size_t s_len) {
  int i, ret = 0;
  for(i = 0; i < s_len; ++i) {
    if (!isalnum(s[i]) && s[i] != '_') {
      ret = 1;
      break;
    }
  }
  return ret;
}

static int cmpstringp(const void *p1, const void *p2) {
  /* The actual arguments to this function are "pointers to
   *      pointers to char", but strcmp(3) arguments are "pointers
   *      to char", hence the following cast plus dereference */
  
  return strcmp(* (char * const *) p1, * (char * const *) p2);
}

int uci_remove(ServiceInfo *i) {
  int ret = 0;
  struct uci_context *c;
  struct uci_ptr sec_ptr;
  struct uci_package *pak = NULL;
  char *sid = NULL;
  char sec_name[78];
  char *key = NULL;
  size_t sid_len;
  
  avahi_string_list_get_pair(avahi_string_list_find(i->txt_lst,"fingerprint"),&key,&sid,&sid_len);
  if (sid_len != FINGERPRINT_LEN && !isHex(sid,sid_len)) {
    fprintf(stderr,"(UCI_Remove) Invalid fingerprint txt field\n");
    return 1;
  }
  
  c = uci_alloc_context();
  assert(c);
  
  strcpy(sec_name,"applications.");
  strncat(sec_name,sid,FINGERPRINT_LEN);
  sec_name[77] = '\0';
  
  if (uci_lookup_ptr(c, &sec_ptr, sec_name, false) != UCI_OK) {
    uci_perror (c, "(UCI_Remove) Failed application lookup");
  } else {
    if (sec_ptr.flags & UCI_LOOKUP_COMPLETE) {
      fprintf(stdout,"(UCI_Remove) Found application\n");
      if (uci_delete(c, &sec_ptr) != UCI_OK) {
	uci_perror (c, "(UCI_Remove) Failed to delete application");
	ret = 1;
      } else {
	fprintf(stdout,"(UCI_Remove) Successfully deleted application\n");
	pak = sec_ptr.p;
	// uci_save
	if (uci_save(c, pak)) {
	  uci_perror (c,"(UCI_Remove) Failed to save");
	  ret = 1;
	} else {
	  fprintf(stdout,"(UCI_Remove) Save succeeded\n");
	  if (uci_commit(c,&pak,false)) {
	    uci_perror(c,"(UCI_Remove) Failed to commit");
	    ret = 1;
	  } else {
	    fprintf(stdout,"(UCI_Remove) Commit succeeded\n");
	  }
	}
      }
    } else {
      fprintf(stdout,"(UCI_Remove) Application not found\n");
      ret = 1;
    }
  }
  
  uci_free_context(c);
  return ret;
}

int uci_write(ServiceInfo *i) {
  struct uci_context *c;
  struct uci_ptr sec_ptr,sig_ptr;
  int uci_ret, ret = 0;
  char sec_name[78], sig_opstr[88];
  char *key, *sig = NULL;
  char *sid = NULL;
  struct uci_package *pak = NULL;
  struct uci_section *sec = NULL;
  AvahiStringList *txt;
  size_t sid_len, sig_len;
  
  c = uci_alloc_context();
  assert(c);

  avahi_string_list_get_pair(avahi_string_list_find(i->txt_lst,"fingerprint"),&key,&sid,&sid_len);
  avahi_string_list_get_pair(avahi_string_list_find(i->txt_lst,"signature"),&key,&sig,&sig_len);

  if (sid_len != FINGERPRINT_LEN ||
      sig_len != SIG_LENGTH ||
      !isHex(sid,sid_len) ||
      !isHex(sig,sig_len)) {
    fprintf(stderr,"(UCI) Invalid signature or fingerprint txt fields\n");
    ret = 1;
    goto abort;
  }
  
  strcpy(sec_name,"applications.");
  strncat(sec_name,sid,FINGERPRINT_LEN);
  sec_name[77] = '\0';
  
  if (uci_lookup_ptr(c, &sec_ptr, sec_name, false) != UCI_OK) {
    uci_perror (c, "(UCI) Failed application lookup");
  } else {
    if (sec_ptr.flags & UCI_LOOKUP_COMPLETE) {
      fprintf(stdout,"(UCI) Found application\n");
      // check for service == fingerprint. if sig different, update it
      strcpy(sig_opstr,"applications.");
      strncat(sig_opstr,sid,FINGERPRINT_LEN);
      strcat(sig_opstr,".signature");
      if (uci_lookup_ptr(c, &sig_ptr, sig_opstr, false) != UCI_OK) {
        uci_perror (c, "(UCI) Failed signature lookup");
      } else {
        if (sig_ptr.flags & UCI_LOOKUP_COMPLETE && sig && !strcmp(sig,sig_ptr.o->v.string)) {
	  // signatures equal: do nothing
	  fprintf(stdout,"(UCI) Signature the same, not updating\n");
	  goto abort;
	} else {
	  // signatures differ: delete existing app
	  fprintf(stdout,"(UCI) Signature differs, updating\n");
	  if (uci_delete(c, &sec_ptr) != UCI_OK) {
	    uci_perror (c, "(UCI) Failed to delete application");
	  }
	}
      }
    } else {
      fprintf(stdout,"(UCI) Application not found, creating\n");
    }

    pak = sec_ptr.p;
    memset(&sec_ptr, 0, sizeof(struct uci_ptr));
    
    // uci_add_section
    sec_ptr.package = "applications";
    sec_ptr.section = sid;
    sec_ptr.value = "application";
    if (uci_set(c, &sec_ptr)) {
      uci_perror(c,"(UCI) Failed to set section");
      ret = 1;
      goto abort;
    } else {
      fprintf(stdout,"(UCI) Section set succeeded\n");
    }
    
    // uci set options/values
    txt = i->txt_lst;
    do {
      if (avahi_string_list_get_pair(txt,(char **)&(sec_ptr.option),(char **)&(sec_ptr.value),NULL))
	continue;
      if (!strcmp(sec_ptr.option,"type")) {
	uci_ret = uci_add_list(c, &sec_ptr);
      } else {
	uci_ret = uci_set(c, &sec_ptr);
      }
      if (uci_ret) {
	uci_perror(c,"(UCI) Failed to set");
	ret = 1;
	goto abort;
      } else {
	fprintf(stdout,"(UCI) Set succeeded\n");
      }
    } while (txt = avahi_string_list_get_next(txt));
    
    // uci_save
    if (uci_save(c, pak)) {
      uci_perror (c,"(UCI) Failed to save");
      ret = 1;
    } else {
      fprintf(stdout,"(UCI) Save succeeded\n");
      if (uci_commit(c,&pak,false)) {
	uci_perror(c,"(UCI) Failed to commit");
	ret = 1;
      } else {
	fprintf(stdout,"(UCI) Commit succeeded\n");
      }
    }
  }

abort:
  uci_free_context(c);
  return ret;
}

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

static void remove_service(AvahiTimeout *t, void *userdata) {
    assert(userdata);
    ServiceInfo *i = (ServiceInfo*)userdata;

    fprintf(stdout, "(Remove_Service) Removing service announcement: %s\n",i->name);
    
    /* Cancel expiration event */
    if (!t && i->timeout)
      avahi_simple_poll_get(simple_poll)->timeout_update(i->timeout,NULL);
    
    if (arguments.uci && uci_remove(i)) {
      fprintf(stderr, "(Remove_Service) Could not remove from UCI\n");
    }
    
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

    if (!(f = fopen(arguments.output_file, "w+"))) {
        fprintf(stderr, "Could not open %s. Using stdout instead.\n", arguments.output_file);
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
      if (!(types_list = (char**)realloc(types_list,(types_list_len + 1)*sizeof(char*)))) {
	fprintf(stderr,"(Verify) Failed to allocate space for types_list\n");
	return -1;
      }
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
    if ((asprintf(&type,type_template,types_list[j]) < 0) ||
      !(type_str = (char*)realloc(type_str,prev_len + strlen(type) + 1))) {
      fprintf(stderr,"(Verify) Failed to allocate space for buffer\n");
      if (type_str)
        free(type_str);
      if (type)
        free(type);
      free(types_list);
      return -1;
    }
    if (prev_len)
      strcat(type_str,type);
    else
      strcpy(type_str,type);
  }
  
  if (asprintf(&msg,template,i->type,i->domain,i->port,app,ttl,ipaddr,type_str,icon,desc,expr) < 0) {
    fprintf(stderr,"(Verify) Failed to allocate space for msg\n");
    verdict = -1;
  } else {
    verdict = verify(sid,strlen(sid),msg,strlen(msg),sig,strlen(sig));
    // printf("%s\n",msg);
  }
  
  free(type);
  free(type_str);
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
            fprintf(stderr, "(Resolver) Failed to resolve service '%s' of type '%s' in domain '%s': %s\n", name, type, domain, avahi_strerror(avahi_server_errno(server)));
            break;

        case AVAHI_RESOLVER_FOUND: {
            avahi_address_snprint(i->address, 
                sizeof(i->address),
                address);
	    i->host_name = strdup(host_name);
	    if (port < 0 || port > 65535) {
	      fprintf(stderr,"(Resolver) Invalid port: %s\n",name);
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
	      fprintf(stderr,"(Resolver) Missing TXT field(s): %s\n", name);
	      break;
	    }
	    
	    avahi_string_list_get_pair(avahi_string_list_find(txt,"ttl"),NULL,&val,NULL);
	    if (!isNumeric(val) || atoi(val) < 0) {
	      fprintf(stderr,"(Resolver) Invalid TTL value: %s -> %s\n",name,val);
	      break;
	    }
	    
	    avahi_string_list_get_pair(avahi_string_list_find(txt,"expiration"),NULL,&expiration_str,NULL);
	    if (!isNumeric(expiration_str) || atoi(expiration_str) < 0) {
	      fprintf(stderr,"(Resolver) Invalid expiration value: %s -> %s\n",name,expiration_str);
	      break;
	    }
	    
	    avahi_string_list_get_pair(avahi_string_list_find(txt,"fingerprint"),NULL,&val,&val_size);
	    if (val_size != FINGERPRINT_LEN && !isHex(val,val_size)) {
	      fprintf(stderr,"(Resolver) Invalid fingerprint: %s -> %s\n",name,val);
	      break;
	    }
	    
	    avahi_string_list_get_pair(avahi_string_list_find(txt,"signature"),NULL,&val,&val_size);
	    if (val_size != SIG_LENGTH && !isHex(val,val_size)) {
	      fprintf(stderr,"(Resolver) Invalid signature: %s -> %s\n",name,val);
	      break;
	    }

	    // TODO: check connectivity, using commotiond socket library
	    
	    // TODO: verify signature, using commotiond serval key mgmt API

	    if (verify_announcement(i)) {
	      fprintf(stderr,"(Resolver) Announcement signature verification failed\n");
	      break;
	    } else
	      fprintf(stdout,"(Resolver) Announcement signature verification succeeded\n");

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
	      fprintf(stderr, "(Resolver) Could not convert txt fields to string\n");
	      break;
	    }
	    
	    if (arguments.uci && uci_write(i)) {
	      fprintf(stderr, "(Resolver) Could not write to UCI\n");
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

            fprintf(stderr, "(Browser) %s\n", avahi_strerror(avahi_server_errno(server)));
            avahi_simple_poll_quit(simple_poll);
            return;

        case AVAHI_BROWSER_NEW:
        case AVAHI_BROWSER_REMOVE: {
            ServiceInfo *found_service = NULL;
            fprintf(stderr, "(Browser) %s: service '%s' of type '%s' in domain '%s'\n",event == AVAHI_BROWSER_NEW ? "NEW" : "REMOVE", name, type, domain);

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
    fprintf(stdout,"uci: %d, out: %s\n",arguments.uci,arguments.output_file);
    
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
