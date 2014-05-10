/**
 *       @file  publish.c
 *      @brief  functionality for publishing and multicasting service announcements
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

#include <unistd.h>
#include <limits.h>

#include <avahi-common/error.h>
#include <avahi-core/core.h>
#include <avahi-core/publish.h>
#include <avahi-client/client.h>
#include <avahi-client/publish.h>

#include <commotion/debug.h>
#include <commotion/obj.h>
#include <commotion/list.h>

#include "defs.h"
#include "service.h"
#include "service_list.h"
#include "publish.h"

#if 0
extern ServiceInfo *services;
#endif

/* Private */

#ifdef CLIENT
static void
client_entry_group_callback(AvahiEntryGroup *g, AvahiEntryGroupState state, AVAHI_GCC_UNUSED void *userdata)
{
  /* Called whenever the entry group state changes */
  switch (state) {
    case AVAHI_ENTRY_GROUP_COLLISION :
    case AVAHI_ENTRY_GROUP_FAILURE :
      ERROR("Entry group failure: %s\n", avahi_strerror(avahi_client_errno(avahi_entry_group_get_client(g))));
    default:
      ;
  }
}
#else
static void
server_entry_group_callback(AvahiServer *s, AvahiSEntryGroup *g, AvahiEntryGroupState state, AVAHI_GCC_UNUSED void *userdata)
{
  assert(s);
  /* Called whenever the entry group state changes */
  switch (state) {
    case AVAHI_ENTRY_GROUP_COLLISION:
    case AVAHI_ENTRY_GROUP_FAILURE :
      ERROR("Entry group failure: %s\n", avahi_strerror(avahi_server_errno(s)));
    default:
      ;
  }
}
#endif

static co_obj_t *
_csm_publish_service_i(co_obj_t *list, co_obj_t *current, void *context)
{
  if (IS_LIST(current)) return NULL;
  assert(context);
  csm_ctx *ctx = (csm_ctx*)context;
  CHECK(csm_publish_service(((co_service_t*)current)->service, ctx),
        "Failed to publish service");
  return NULL;
error:
  return current;
}

static co_obj_t *
_csm_unpublish_service_i(co_obj_t *list, co_obj_t *current, void *context)
{
  if (IS_LIST(current)) return NULL;
  assert(context);
  csm_ctx *ctx = (csm_ctx*)context;
  CHECK(csm_unpublish_service(((co_service_t*)current)->service, ctx),
        "Failed to unpublish service");
  return NULL;
error:
  return current;
}

/* Public */

int
csm_publish_all(csm_ctx *ctx)
{
  CHECK(co_list_parse(ctx->service_list->services, _csm_publish_service_i, ctx) == NULL,
        "Error publishing services");
  return 1;
error:
  return 0;
}

int
csm_unpublish_all(csm_ctx *ctx)
{
  CHECK(co_list_parse(ctx->service_list->services, _csm_unpublish_service_i, ctx) == NULL,
	"Error publishing services");
  return 1;
error:
  return 0;
}

int
csm_unpublish_service(csm_service *s, csm_ctx *ctx)
{
  if (!s->address && s->group) { // only remote services have address set
    CHECK(ENTRY_GROUP_RESET(s->group) == AVAHI_OK, "Failed to reset entry group");
    ENTRY_GROUP_FREE(s->group);
    s->uptodate = 0;
  }
  return 1;
error:
  return 0;
}

int
csm_publish_service(csm_service *s, csm_ctx *ctx)
{
  assert(ctx);
  
  int ret = 0;
  AvahiStringList *t = NULL;
  
  char *name = csm_service_get_name(s);
  char *description = csm_service_get_description(s);
  char *uri = csm_service_get_uri(s);
  char *icon = csm_service_get_icon(s);
  int ttl = csm_service_get_ttl(s);
  long lifetime = csm_service_get_lifetime(s);
  char **categories = NULL;
  int cat_len = csm_service_categories_to_array(s, &categories);
  char *key = csm_service_get_key(s);
  char *signature = csm_service_get_signature(s);
  
  CHECK(s &&
	name &&
	description &&
	uri &&
	icon &&
	ttl &&
	lifetime &&
	cat_len,
	"Service missing required fields");
  
#ifdef CLIENT
  AvahiClient *client = ctx->client;
  AvahiClientState state = avahi_client_get_state(client);
  CHECK(state == AVAHI_CLIENT_S_RUNNING, "Avahi server in bad state");
#else
  AvahiServer *server = ctx->server;
  AvahiServerState state = avahi_server_get_state(server);
  CHECK(state == AVAHI_SERVER_RUNNING, "Avahi server in bad state");
#endif

  // TODO should we exit if i->address?
  if (!s->address) { // only remote services have address set
    if (!s->group) {
#ifdef CLIENT
      s->group = ENTRY_GROUP_NEW(client_entry_group_callback, NULL);
#else
      s->group = ENTRY_GROUP_NEW(server_entry_group_callback, NULL);
#endif
      CHECK(s->group,"ENTRY_GROUP_NEW failed: %s", AVAHI_ERROR);
      hattach(s->group, s);
    }
    
    t = avahi_string_list_add_printf(t, "%s=%s", "name", name);
    t = avahi_string_list_add_printf(t, "%s=%s", "description", description);
    t = avahi_string_list_add_printf(t, "%s=%s", "uri", uri);
    t = avahi_string_list_add_printf(t, "%s=%s", "icon", icon);
    t = avahi_string_list_add_printf(t, "%s=%s", "fingerprint", key);
    t = avahi_string_list_add_printf(t, "%s=%s", "signature", signature);
    t = avahi_string_list_add_printf(t, "%s=%d", "ttl", ttl);
    t = avahi_string_list_add_printf(t, "%s=%ld", "lifetime", lifetime);
    for (int j = 0; j < cat_len; j++) {
      t = avahi_string_list_add_printf(t, "%s=%s", "type", categories[j]);
    }
    
    /* If the group is empty (either because it was just created, or
    * because it was reset previously, add our entries.  */
    if (ENTRY_GROUP_EMPTY(s->group)) {
      char hostname[HOST_NAME_MAX] = {0};
      CHECK(gethostname(hostname,HOST_NAME_MAX) == 0, "Failed to get hostname");
      int avahi_ret = ENTRY_GROUP_ADD_SERVICE(s->group,
					      s->interface,
					      s->protocol,
					      0,
					      s->uuid,
					      s->type,
					      s->domain,
					      hostname,
					      s->port,
					      t);
      CHECK(avahi_ret == AVAHI_OK, "Failed to add entry group");
    } else if (!s->uptodate) {
      int avahi_ret = ENTRY_GROUP_UPDATE_SERVICE(s->group,
						 s->interface,
						 s->protocol,
						 0,
						 s->uuid,
						 s->type,
						 s->domain,
						 t);
      CHECK(avahi_ret == AVAHI_OK, "Failed to update entry group");
    }
    CHECK(ENTRY_GROUP_COMMIT(s->group) == AVAHI_OK, "Failed to commit entry group");
    s->uptodate = 1;
  }
  
  ret = 1;
error:
  if (categories)
    h_free(categories);
  if (t)
    avahi_string_list_free(t);
  return ret;
}