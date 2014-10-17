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

#ifdef CLIENT
#include <avahi-client/publish.h>
#include <avahi-client/lookup.h>
#else
#include <avahi-core/core.h>
#include <avahi-core/lookup.h>
#include <avahi-core/publish.h>
#endif
#include <avahi-common/address.h>
#include <avahi-common/watch.h>
#include <avahi-common/strlst.h>
#include <avahi-common/llist.h>

#include <commotion/obj.h>

#include "extern/halloc.h"
#include "config.h"

/** Length (in hex chars) of Serval IDs */
#define FINGERPRINT_LEN 64
/** Length (in hex chars) of Serval-created signatures */
#define SIG_LENGTH 128
/** Length of UUID (which is base32 encoding of Serval ID) */
#define UUID_LEN 52

#ifndef container_of
#define container_of(ptr, type, member) ({ \
  const typeof( ((type *)0)->member ) *__mptr = (ptr); \
  (type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#define CO_APPEND_STR(R,S) CHECK(co_request_append_str(co_req,S,strlen(S)+1),"Failed to append to request")
  
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
#define FREE_AVAHI(CTX) do { if (CTX->client) avahi_client_free(CTX->client); } while(0)

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
#define FREE_AVAHI(CTX) do { if (CTX->server) avahi_server_free(CTX->server); } while(0)

#endif

struct csm_config {
  char *co_sock;
#ifdef USE_UCI
  int uci;
#endif
  int nodaemon;
  char *pid_file;
  char *schema_dir;
};

struct csm_service;
struct csm_service_list;
struct csm_schema_t;

typedef struct csm_pending_service {
  char name[256];
  struct csm_pending_service *_prev;
  struct csm_pending_service *_next;
} csm_pending_service;

typedef struct {
#ifdef CLIENT
  AvahiClient *client;
#else
  AvahiServer *server;
#endif
  TYPE_BROWSER *stb;
  struct csm_pending_service *pending;
  
  struct csm_service_list *service_list;
//   struct csm_service *service;
  struct csm_schema_t *schema;
} csm_ctx;

/** 
 * libcommotion object extended type for CSM contexts
 * (used for passing to command handlers in parameter list) 
 */
typedef struct {
  co_obj_t _header;
  uint8_t _exttype;
  uint8_t _len;
  csm_ctx *ctx;
} co_ctx_t;

#define _ctx 253

#define IS_CTX(J) (IS_EXT(J) && ((co_ctx_t *)J)->_exttype == _ctx)

static inline co_obj_t *co_ctx_create(csm_ctx *ctx) {
  co_ctx_t *output = h_calloc(1,sizeof(co_ctx_t));
  CHECK_MEM(output);
  output->_header._type = _ext8;
  output->_exttype = _ctx;
  output->_len = (sizeof(co_ctx_t));
  output->ctx = ctx;
  return (co_obj_t*)output;
error:
  return NULL;
}

#endif
