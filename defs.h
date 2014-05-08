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

#include <avahi-client/publish.h>
#include <avahi-client/lookup.h>
#include <avahi-common/address.h>
#include <avahi-common/watch.h>
#include <avahi-common/strlst.h>
#include <avahi-common/llist.h>

#include "extern/halloc.h"

#include "config.h"

/** Length (in hex chars) of Serval IDs */
#define FINGERPRINT_LEN 64
/** Length (in hex chars) of Serval-created signatures */
#define SIG_LENGTH 128
/** Length of UUID (which is base32 encoding of Serval ID) */
#define UUID_LEN 52

#define CO_APPEND_STR(R,S) CHECK(co_request_append_str(co_req,S,strlen(S)+1),"Failed to append to request")

#if 0
#define CSM_SET(I,M,S) \
  do { \
    I->M = halloc(I->M, strlen(S) + 1); \
    CHECK_MEM(I->M); \
    memset(I->M, 0, strlen(S) + 1); \
    hattach(I->M, I); \
    strcpy(I->M, S); \
  } while (0)
#endif
  
#ifdef CLIENT

#define TYPE_BROWSER AvahiServiceTypeBrowser
#define TYPE_BROWSER_NEW(A,B,C,D,E,F) avahi_service_type_browser_new(client,A,B,C,D,E,F)
#define TYPE_BROWSER_FREE(J) avahi_service_type_browser_free(J)
#define BROWSER AvahiServiceBrowser
#define BROWSER_NEW(A,B,C,D,E,F,G) avahi_service_browser_new(client,A,B,C,D,E,F,G)
#define RESOLVER AvahiServiceResolver
#define RESOLVER_NEW(A,B,C,D,E,F,G,H,I) avahi_service_resolver_new(client,A,B,C,D,E,F,G,H,I)
#define RESOLVER_FREE(J) avahi_service_resolver_free(J)
#define ENTRY_GROUP AvahiEntryGroup
#define ENTRY_GROUP_NEW(A,B) avahi_entry_group_new(client,A,B)
#define ENTRY_GROUP_EMPTY avahi_entry_group_is_empty
#define ENTRY_GROUP_ADD_SERVICE(A,B,C,D,E,F,G,H,I,J) avahi_entry_group_add_service_strlst(A,B,C,D,E,F,G,H,I,J)
#define ENTRY_GROUP_UPDATE_SERVICE(A,B,C,D,E,F,G,H) avahi_entry_group_update_service_txt_strlst(A,B,C,D,E,F,G,H)
#define ENTRY_GROUP_COMMIT avahi_entry_group_commit
#define ENTRY_GROUP_RESET avahi_entry_group_reset
#define ENTRY_GROUP_FREE avahi_entry_group_free
#define AVAHI_ERROR avahi_strerror(avahi_client_errno(client))
#define FREE_AVAHI(CTX) do { if (ctx->client) avahi_client_free(ctx->client); } while(0)

#else

#define TYPE_BROWSER AvahiSServiceTypeBrowser
#define TYPE_BROWSER_NEW(A,B,C,D,E,F) avahi_s_service_type_browser_new(server,A,B,C,D,E,F)
#define TYPE_BROWSER_FREE(J) avahi_s_service_type_browser_free(J)
#define BROWSER AvahiSServiceBrowser
#define BROWSER_NEW(A,B,C,D,E,F,G) avahi_s_service_browser_new(server,A,B,C,D,E,F,G)
#define RESOLVER AvahiSServiceResolver
#define RESOLVER_NEW(A,B,C,D,E,F,G,H,I) avahi_s_service_resolver_new(server,A,B,C,D,E,F,G,H,I)
#define RESOLVER_FREE(J) avahi_s_service_resolver_free(J)
#define ENTRY_GROUP AvahiSEntryGroup
#define ENTRY_GROUP_NEW(A,B) avahi_s_entry_group_new(server,A,B)
#define ENTRY_GROUP_EMPTY avahi_s_entry_group_is_empty
#define ENTRY_GROUP_ADD_SERVICE(A,B,C,D,E,F,G,H,I,J) avahi_server_add_service_strlst(server,A,B,C,D,E,F,G,H,I,J)
#define ENTRY_GROUP_UPDATE_SERVICE(A,B,C,D,E,F,G,H) avahi_server_update_service_txt_strlst(server,A,B,C,D,E,F,G,H)
#define ENTRY_GROUP_COMMIT avahi_s_entry_group_commit
#define ENTRY_GROUP_RESET avahi_s_entry_group_reset
#define ENTRY_GROUP_FREE avahi_s_entry_group_free
#define AVAHI_ERROR avahi_strerror(avahi_server_errno(server))
#define FREE_AVAHI(CTX) do { if (ctx->server) avahi_server_free(ctx->server); } while(0)

#endif

typedef struct {
  char *co_sock;
#ifdef USE_UCI
  int uci;
#endif
  int nodaemon;
  char *output_file;
  char *pid_file;
  char *sid;
} csm_config;

typedef struct {
#ifdef CLIENT
  AvahiClient *client;
#else
  AvahiServer *server;
#endif
  TYPE_BROWSER *stb;
  csm_service_list *service_list;
  csm_service *service;
} csm_ctx;

#if 0
typedef struct ServiceTXTFields {
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
  char *version;
} ServiceTXTFields;

typedef struct ServiceInfo {
  /** Common members for all services */
  AvahiIfIndex interface;
  AvahiProtocol protocol;
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
  int uptodate;

  /** Remote services */
  char *host_name;
  char address[AVAHI_ADDRESS_STR_MAX];
  AvahiStringList *txt_lst; /**< Collection of all the user-defined txt fields */
  RESOLVER *resolver;

  /** Linked list */
  AVAHI_LLIST_FIELDS(struct ServiceInfo, info);
} ServiceInfo;
#endif

#endif
