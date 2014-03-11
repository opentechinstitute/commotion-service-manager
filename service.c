/**
 *       @file  service.c
 *      @brief  service-related functionality of the Commotion Service Manager
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
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>
#include <avahi-common/simple-watch.h>

#include "commotion.h"

#include "defs.h"
#include "service.h"
#include "browse.h"
#include "debug.h"
#include "util.h"

#ifdef USE_UCI
#include <uci.h>
#include "uci-utils.h"
#endif

#define OPEN_DELIMITER "\""
#define OPEN_DELIMITER_LEN 1
#define CLOSE_DELIMITER "\""
#define CLOSE_DELIMITER_LEN 1
#define FIELD_DELIMITER ","
#define FIELD_DELIMITER_LEN 1

// from libcommotion_serval-sas
#define SAS_SIZE 32
extern int keyring_send_sas_request_client(const char *sid_str, 
					   const size_t sid_len,
					   char *sas_buf,
					   const size_t sas_buf_len);

/** Linked list of all the local services */
ServiceInfo *services = NULL;

extern AvahiSimplePoll *simple_poll;
#ifndef CLIENT
extern AvahiServer *server;
#endif

extern csm_config config;

/* Private */

static size_t
create_signing_template(ServiceInfo *i, char **template)
{
  int ret = 0;
  const char *type_template = "<txt-record>type=%s</txt-record>";
  const char *str_template = "<type>%s</type>\n"
			     "<domain-name>%s</domain-name>\n"
			     "<port>%d</port>\n"
			     "<txt-record>name=%s</txt-record>\n"
			     "<txt-record>ttl=%d</txt-record>\n"
			     "<txt-record>uri=%s</txt-record>\n"
			     "%s\n"
			     "<txt-record>icon=%s</txt-record>\n"
			     "<txt-record>description=%s</txt-record>\n"
			     "<txt-record>lifetime=%ld</txt-record>";

  /* Sort types into alphabetical order */
  qsort(i->categories,i->cat_len,sizeof(char*),cmpstringp);
  
  /* Concat the types into a single string to add to template */
  char *app_type = NULL, *type_str = NULL;
  int prev_len = 0;
  for (int j = 0; j < i->cat_len; j++) {
    if (app_type) {
      free(app_type);
      app_type = NULL;
    }
    prev_len = type_str ? strlen(type_str) : 0;
    CHECK_MEM(asprintf(&app_type,type_template,i->categories[j]) != -1
	      && (type_str = realloc(type_str,prev_len + strlen(app_type) + 1)));
    type_str[prev_len] = '\0';
    strcat(type_str,app_type);
  }
  
  /* Add the fields into the template */
  CHECK_MEM(asprintf(template,
		     str_template,
		     i->type,
		     i->domain,
		     i->port,
		     i->name,
		     i->ttl,
		     i->uri,
		     i->cat_len ? type_str : "",
		     i->icon,
		     i->description,
		     i->lifetime) != -1);
  
  ret = strlen(*template);
error:
  if (app_type)
    free(app_type);
  if (type_str)
    free(type_str);
  return ret;
}

/**
 * Convert an AvahiStringList to a string
 */
static char *
_csm_txt_list_to_string(char *cur, size_t *cur_len, char *append, size_t append_len)
{
  char *open_delimiter = OPEN_DELIMITER;
  char *close_delimiter = CLOSE_DELIMITER;
  char *field_delimiter = FIELD_DELIMITER;
  char *escaped = escape(append, &append_len);
  CHECK_MEM(escaped);
  cur = realloc(cur, *cur_len
		     + OPEN_DELIMITER_LEN
		     + append_len
		     + CLOSE_DELIMITER_LEN
		     + FIELD_DELIMITER_LEN
		     + 1);
  CHECK_MEM(cur);
  cur[*cur_len] = '\0';
  
  strcat(cur, open_delimiter);
  strcat(cur, escaped);
  strcat(cur, close_delimiter);
  strcat(cur, field_delimiter);
  
  *cur_len += OPEN_DELIMITER_LEN + append_len + CLOSE_DELIMITER_LEN + FIELD_DELIMITER_LEN;
  cur[*cur_len] = '\0';

error:
  if (escaped)
    free(escaped);
  return cur;
}

/**
 * Output service fields to a file
 * @param f File to output to
 * @param service the service to print
 */
static void
_print_service(FILE *f, ServiceInfo *service)
{
  char interface_string[IF_NAMESIZE];
  const char *protocol_string;
  
  if (!if_indextoname(service->interface, interface_string))
    WARN("Could not resolve the interface name!");
  
  if (!(protocol_string = avahi_proto_to_string(service->protocol)))
    WARN("Could not resolve the protocol name!");
  
  char *txt = NULL;
  size_t txt_len = 0;
  txt = _csm_txt_list_to_string(txt, &txt_len, service->name, strlen(service->name));
  txt = _csm_txt_list_to_string(txt, &txt_len, service->description, strlen(service->description));
  txt = _csm_txt_list_to_string(txt, &txt_len, service->uri, strlen(service->uri));
  txt = _csm_txt_list_to_string(txt, &txt_len, service->icon, strlen(service->icon));
  for (int i = 0; i < service->cat_len; i++) {
    txt = _csm_txt_list_to_string(txt, &txt_len, service->categories[i], strlen(service->categories[i]));
  }
  txt_len = asprintf(&txt, "%sttl=%d;lifetime=%ld;", txt, service->ttl, service->lifetime);
  CHECK_MEM(txt_len != -1);
  txt = _csm_txt_list_to_string(txt, &txt_len, service->key, strlen(service->key));
  txt = _csm_txt_list_to_string(txt, &txt_len, service->signature, strlen(service->signature));
  
  fprintf(f, "%s;%s;%s;%s;%s;%s;%u;%s\n",
	  interface_string,
	  protocol_string,
	  service->uuid,
	  service->type,
	  service->domain,
	  service->host_name,
	  service->port,
	  txt);
  
error:
  if (txt)
    free(txt);
}

/* Public */

/**
 * Check if a service uuid is in the current list of local services
 */
ServiceInfo *
find_service(const char *uuid)
{
  for (ServiceInfo *i = services; i; i = i->info_next) {
    if (strcasecmp(i->uuid, uuid) == 0)
      return i;
  }
    
  return NULL;
}

/**
 * Add a remote service to the list of services
 * @param interface
 * @param protocol
 * @param name service name
 * @param type service type (e.g. _commotion._tcp)
 * @param domain domain service is advertised on (e.g. mesh.local)
 * @return ServiceInfo struct representing the service that was added
 */
ServiceInfo *
add_service(BROWSER *b,
	    AvahiIfIndex interface,
	    AvahiProtocol protocol,
	    const char *uuid,
	    const char *type,
	    const char *domain)
{
  ServiceInfo *i;
  
  i = h_calloc(1, sizeof(ServiceInfo));

  i->interface = interface;
  i->protocol = protocol;
  if (uuid)
    CSM_SET(i, uuid, uuid);
  CSM_SET(i, type, type);
  CSM_SET(i, domain, domain);
  
  if (b) {
#ifdef CLIENT
    AvahiClient *client = avahi_service_browser_get_client(b);
#endif
    if (!(i->resolver = RESOLVER_NEW(interface, protocol, uuid, type, domain, AVAHI_PROTO_UNSPEC, 0, resolve_callback, i))) {
      h_free(i);
      INFO("Failed to create resolver for service '%s' of type '%s' in domain '%s': %s", uuid, type, domain, AVAHI_ERROR);
      return NULL;
    }
    i->resolved = 0;
  }

  AVAHI_LLIST_PREPEND(ServiceInfo, info, services, i);

  return i;
error:
  remove_service(NULL, i);
  return NULL;
}

int
process_service(ServiceInfo *i)
{
  /* Input validation */
  CHECK(isValidTtl(i->ttl),"Invalid TTL value: %s -> %d",i->uuid,i->ttl);
  CHECK(isValidLifetime(i->lifetime),"Invalid lifetime value: %s -> %ld",i->uuid,i->lifetime);
  if (i->key)
    CHECK(isValidFingerprint(i->key,strlen(i->key)),"Invalid fingerprint: %s -> %s",i->uuid,i->key);
  if (i->signature)
    CHECK(isValidSignature(i->signature,strlen(i->signature)),"Invalid signature: %s -> %s",i->uuid,i->signature);
  
  /* Create or verify signature */
  if (i->signature)
    CHECK(verify_signature(i),"Invalid signature");
  else
    CHECK(create_signature(i),"Failed to create signature");
  
  /* Set expiration timer on the service */
#ifdef USE_UCI
  long def_lifetime = default_lifetime();
  if (i->lifetime == 0 || (def_lifetime < i->lifetime && def_lifetime > 0))
    i->lifetime = def_lifetime;
#endif
  if (i->lifetime > 0) {
    struct timeval tv;
    avahi_elapse_time(&tv, 1000*i->lifetime, 0);
    time_t current_time = time(NULL);
    // create expiration event for service
    i->timeout = avahi_simple_poll_get(simple_poll)->timeout_new(avahi_simple_poll_get(simple_poll),
								 &tv,
								 remove_service,
								 i);
    /* Convert lifetime period into timestamp */
    if (current_time != ((time_t)-1)) {
      struct tm *timestr = localtime(&current_time);
      timestr->tm_sec += i->lifetime;
      current_time = mktime(timestr);
      char *c_time_string = ctime(&current_time);
      if (c_time_string) {
	c_time_string[strlen(c_time_string)-1] = '\0'; /* ctime adds \n to end of time string; remove it */
	CSM_SET(i, expiration, c_time_string);
      }
    }
  }
  
#ifdef USE_UCI
  /* Write out service to UCI */
  if (config.uci && uci_write(i) == 0)
    ERROR("(Resolver) Could not write to UCI");
#endif
  
  i->resolved = 1;
  return 1;
error:
  return 0;
}

/**
 * Remove service from list of local services
 * @param t timer set to service's expiration data. This param is only passed 
 *          when the service is being expired, otherwise it is NULL.
 * @param userdata should be cast as the ServiceInfo object of the service to remove
 * @note If compiled for OpenWRT, the Avahi service file for the local service is removed
 * @note If compiled with UCI support, service is also removed from UCI list
 */
void
remove_service(AvahiTimeout *t, void *userdata)
{
  assert(userdata);
  ServiceInfo *i = (ServiceInfo*)userdata;

  INFO("Removing service announcement: %s",i->uuid);
  
  /* Cancel expiration event */
  if (!t && i->timeout)
    avahi_simple_poll_get(simple_poll)->timeout_update(i->timeout,NULL);
  
#ifdef USE_UCI
  if (i->resolved) {
    // Delete UCI entry
    if (config.uci && uci_remove(i) < 0)
      ERROR("(Remove_Service) Could not remove from UCI");
  }
#endif
  
  AVAHI_LLIST_REMOVE(ServiceInfo, info, services, i);

  if (i->resolver)
    RESOLVER_FREE(i->resolver);

  if (i->txt_lst)
    avahi_string_list_free(i->txt_lst);
  h_free(i);
}

/**
 * Upon resceiving the USR1 signal, print local services
 */
void print_services(int signal) {
  ServiceInfo *i;
  FILE *f = NULL;

  if (!(f = fopen(config.output_file, "w+"))) {
    WARN("Could not open %s. Using stdout instead.", config.output_file);
    f = stdout;
  }

  for (i = services; i; i = i->info_next) {
    if (i->resolved)
      _print_service(f, i);
  }

  if (f != stdout)
    fclose(f);
}

int
verify_signature(ServiceInfo *i)
{
  int verdict = 0;
  
  char *to_verify = NULL;
  CHECK(create_signing_template(i,&to_verify) > 0, "Failed to create signing template");
  
  char sas_buf[2*SAS_SIZE+1] = {0};
  
  CHECK(keyring_send_sas_request_client(i->key,strlen(i->key),sas_buf,2*SAS_SIZE+1),"Failed to fetch signing key");
  
  bool output;
  co_obj_t *co_conn = NULL, *co_req = NULL, *co_resp = NULL;
  CHECK((co_conn = co_connect(config.co_sock,strlen(config.co_sock)+1)),
	"Failed to connect to Commotion socket");
  CHECK_MEM((co_req = co_request_create()));
  CO_APPEND_STR(co_req,"verify");
  CO_APPEND_STR(co_req,sas_buf);
  CO_APPEND_STR(co_req,i->signature);
  CO_APPEND_STR(co_req,to_verify);
  CHECK(co_call(co_conn,&co_resp,"serval-crypto",sizeof("serval-crypto"),co_req)
	&& co_response_get_bool(co_resp,&output,"result",sizeof("result")),
	"Failed to verify signature");
  
  /* Is the signature valid? 1=yes, 0=no */
  if (output == true)
    verdict = 1;
  
error:
  if (co_req)
    co_free(co_req);
  if (co_resp)
    co_free(co_resp);
  if (co_conn)
    co_disconnect(co_conn);
  if (to_verify)
    free(to_verify);
  return verdict;
}

int
create_signature(ServiceInfo *i)
{
  char *to_sign = NULL;
  CHECK(create_signing_template(i,&to_sign) > 0, "Failed to create signing template");
  
  co_obj_t *co_conn = NULL, *co_req = NULL, *co_resp = NULL;
  CHECK((co_conn = co_connect(config.co_sock,strlen(config.co_sock)+1)),
	"Failed to connect to Commotion socket");
  CHECK_MEM((co_req = co_request_create()));
  CO_APPEND_STR(co_req,"sign");
  if (i->key) {
    CO_APPEND_STR(co_req,i->key);
  }
  CO_APPEND_STR(co_req,to_sign);
  
  CHECK(co_call(co_conn,&co_resp,"serval-crypto",sizeof("serval-crypto"),co_req),
	"Failed to sign service announcement");
  
  char *signature = NULL, *sid = NULL;
  CHECK(co_response_get_str(co_resp,&signature,"signature",sizeof("signature")),
	"Failed to fetch signature from response");
  CHECK(co_response_get_str(co_resp,&sid,"sid",sizeof("sid")),
	"Failed to fetch SID from response");
  CSM_SET(i, signature, signature);
  if (!i->key) {
    CSM_SET(i, key, sid);
    // set UUID
    char uuid[UUID_LEN + 1] = {0};
    CHECK(get_uuid(sid,strlen(sid),uuid,UUID_LEN + 1) == UUID_LEN, "Failed to get UUID");
    CSM_SET(i, uuid, uuid);
  }
  
  return 1;
error:
  if (co_req)
    co_free(co_req);
  if (co_resp)
    co_free(co_resp);
  if (co_conn)
    co_disconnect(co_conn);
  if (to_sign)
    free(to_sign);
  return 0;
}