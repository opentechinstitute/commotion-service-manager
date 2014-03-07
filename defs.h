/**
 *       @file  defs.h
 *      @brief  internal macros and structs for CSM
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

#ifndef CSM_INTERNAL_H
#define CSM_INTERNAL_H

#include <stdlib.h>

#include <avahi-core/core.h>
#include <avahi-core/lookup.h>
#include <avahi-core/publish.h>
#include <avahi-client/client.h>
#include <avahi-client/lookup.h>
#include <avahi-client/publish.h>
#include <avahi-common/llist.h>

#include "extern/halloc.h"

#include "config.h"

/** Length (in hex chars) of Serval IDs */
#define FINGERPRINT_LEN 64
/** Length (in hex chars) of Serval-created signatures */
#define SIG_LENGTH 128

#define CO_APPEND_STR(R,S) CHECK(co_request_append_str(co_req,S,strlen(S)+1),"Failed to append to request")

#define CSM_SET(I,M,S) \
  do { \
    I->M = halloc(I->M, strlen(S) + 1); \
    CHECK_MEM(I->M); \
    memset(I->M, 0, strlen(S) + 1); \
    hattach(I->M, I); \
    strcpy(I->M, S); \
  } while (0)

#ifdef CLIENT
#define TYPE_BROWSER AvahiServiceTypeBrowser
#define TYPE_BROWSER_NEW(A,B,C,D,E) avahi_service_type_browser_new(client,A,B,C,D,E,client)
#define TYPE_BROWSER_FREE(J) avahi_service_type_browser_free(J)
#define BROWSER AvahiServiceBrowser
#define BROWSER_NEW(A,B,C,D,E,F) avahi_service_browser_new(client,A,B,C,D,E,F,client)
#define RESOLVER AvahiServiceResolver
#define RESOLVER_NEW(A,B,C,D,E,F,G,H,I) avahi_service_resolver_new(client,A,B,C,D,E,F,G,H,I)
#define RESOLVER_FREE(J) avahi_service_resolver_free(J)
#define ENTRY_GROUP AvahiEntryGroup
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
#define ENTRY_GROUP AvahiSEntryGroup
#define AVAHI_ERROR avahi_strerror(avahi_server_errno(server))
#define AVAHI_BROWSER_ERROR AVAHI_ERROR
#define FREE_AVAHI() if (server) avahi_server_free(server);
#endif

typedef struct csm_config csm_config;
struct csm_config {
  char *co_sock;
  #ifdef USE_UCI
  int uci;
  #endif
  int nodaemon;
  char *output_file;
  char *pid_file;
  char *sid;
};

typedef struct ServiceTXTFields ServiceTXTFields;
struct ServiceTXTFields {
  char *name;
  char *description;
  char *uri;
  char *icon;
  char **categories;
  int cat_len;
  int ttl;
  long lifetime;
  char *key;
  char *signature;
};

typedef struct ServiceInfo ServiceInfo;
typedef struct ServiceInfo {
  /** Common members for all services */
  AvahiIfIndex interface;
  AvahiProtocol protocol;
  char *host_name;
  char *uuid;
  char *type;
  char *domain;
  uint16_t port;
  union {
    ServiceTXTFields fields;
    ServiceTXTFields;
  };
  char *expiration;
  AvahiTimeout *timeout; /** Timer set for the service's expiration date */
  int resolved; /**< Flag indicating whether all the fields have been resolved */

  /** Local services */
  ENTRY_GROUP *group;

  /** Remote services */
  char address[AVAHI_ADDRESS_STR_MAX];
  AvahiStringList *txt_lst; /**< Collection of all the user-defined txt fields */
//   char *txt; /**< string representing all the txt fields */
  RESOLVER *resolver;

  /** Linked list */
  AVAHI_LLIST_FIELDS(ServiceInfo, info);
} ServiceInfo;

#endif