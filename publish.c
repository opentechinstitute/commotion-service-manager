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
#include <avahi-core/lookup.h>
#include <avahi-core/publish.h>
#include <avahi-client/client.h>
#include <avahi-client/lookup.h>
#include <avahi-client/publish.h>

#include "defs.h"
#include "debug.h"
#include "publish.h"

extern ServiceInfo *services;

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

/* Public */

int
register_all(void *avahi)
{
  for (ServiceInfo *i = services; i; i = i->info_next)
    CHECK(register_service(i, avahi), "Failed to register service %s", i->uuid);
  return 1;
error:
  return 0;
}

int
unregister_all(void)
{
  for (ServiceInfo *i = services; i; i = i->info_next)
    CHECK(unregister_service(i), "Failed to unregister service %s", i->uuid);
  return 1;
error:
  return 0;
}

int
unregister_service(ServiceInfo *i)
{
  if (!i->address && i->group) { // only remote services have address set
    CHECK(ENTRY_GROUP_RESET(i->group) == AVAHI_OK, "Failed to reset entry group");
    ENTRY_GROUP_FREE(i->group);
    i->uptodate = 0;
  }
  return 1;
error:
  return 0;
}

int
register_service(ServiceInfo *i, void *avahi)
{
  int ret = 0;
  AvahiStringList *t = NULL;
  
  CHECK(i &&
	i->name &&
	i->description &&
	i->uri &&
	i->icon &&
	i->ttl &&
	i->lifetime &&
	i->categories,
	"Service missing required fields");
  
#ifdef CLIENT
  AvahiClient *client = avahi;
  AvahiClientState state = avahi_client_get_state(client);
  if (state != AVAHI_CLIENT_S_RUNNING) {
    WARN("Avahi server in bad state");
    goto error;
  }
#else
  AvahiServer *server = avahi;
  AvahiServerState state = avahi_server_get_state(server);
  if (state != AVAHI_SERVER_RUNNING) {
    WARN("Avahi server in bad state");
    goto error;
  }
#endif

  if (!i->address) { // only remote services have address set
    if (!i->group) {
#ifdef CLIENT
      i->group = ENTRY_GROUP_NEW(client_entry_group_callback, NULL);
#else
      i->group = ENTRY_GROUP_NEW(server_entry_group_callback, NULL);
#endif
      CHECK(i->group,"ENTRY_GROUP_NEW failed: %s", AVAHI_ERROR);
      hattach(i->group, i);
    }
    
    t = avahi_string_list_add_printf(t, "%s=%s", "name", i->name);
    t = avahi_string_list_add_printf(t, "%s=%s", "description", i->description);
    t = avahi_string_list_add_printf(t, "%s=%s", "uri", i->uri);
    t = avahi_string_list_add_printf(t, "%s=%s", "icon", i->icon);
    t = avahi_string_list_add_printf(t, "%s=%s", "fingerprint", i->key);
    t = avahi_string_list_add_printf(t, "%s=%s", "signature", i->signature);
    t = avahi_string_list_add_printf(t, "%s=%d", "ttl", i->ttl);
    t = avahi_string_list_add_printf(t, "%s=%ld", "lifetime", i->lifetime);
    for (int j = 0; j < i->cat_len; j++) {
      t = avahi_string_list_add_printf(t, "%s=%s", "type", i->categories[j]);
    }
    
    /* If the group is empty (either because it was just created, or
    * because it was reset previously, add our entries.  */
    if (ENTRY_GROUP_EMPTY(i->group)) {
      char hostname[HOST_NAME_MAX] = {0};
      CHECK(gethostname(hostname,HOST_NAME_MAX) == 0, "Failed to get hostname");
      int avahi_ret = ENTRY_GROUP_ADD_SERVICE(i->group,
					      i->interface,
					      i->protocol,
					      0,
					      i->uuid,
					      i->type,
					      i->domain,
					      hostname,
					      i->port,
					      t);
      CHECK(avahi_ret == AVAHI_OK, "Failed to add entry group");
    } else if (!i->uptodate) {
      int avahi_ret = ENTRY_GROUP_UPDATE_SERVICE(i->group,
						 i->interface,
						 i->protocol,
						 0,
						 i->uuid,
						 i->type,
						 i->domain,
						 t);
      CHECK(avahi_ret == AVAHI_OK, "Failed to update entry group");
    }
    CHECK(ENTRY_GROUP_COMMIT(i->group) == AVAHI_OK, "Failed to commit entry group");
    i->uptodate = 1;
  }
  
  ret = 1;
error:
  if (t)
    avahi_string_list_free(t);
  return ret;
}