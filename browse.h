/**
 *       @file  browse.h
 *      @brief  functionality for receiving and processing service announcements
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

#ifndef CSM_BROWSE_H
#define CSM_BROWSE_H

#include <stdlib.h>

#include <avahi-core/core.h>
#include <avahi-core/lookup.h>
#include <avahi-client/client.h>
#include <avahi-client/lookup.h>
#include <avahi-common/llist.h>

#include "defs.h"

/**
 * Handler called whenever a service is (potentially) resolved
 * @param userdata the ServiceFile object of the service in question
 * @note if compiled with UCI support, write the service to UCI if
 *       it successfully resolves
 * @note if txt fields fail verification, the service is removed from
 *       the local list
 */
void resolve_callback(
  RESOLVER *r,
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

/**
 * Handler for Avahi service browser events. Called whenever a new 
 * services becomes available on the LAN or is removed from the LAN
 */
void browse_service_callback(
  BROWSER *b,
  AvahiIfIndex interface,
  AvahiProtocol protocol,
  AvahiBrowserEvent event,
  const char *name,
  const char *type,
  const char *domain,
  AVAHI_GCC_UNUSED AvahiLookupResultFlags flags,
  void* userdata);

/**
 * Handler for creating Avahi service browser
 */
void browse_type_callback(
  TYPE_BROWSER *b,
  AvahiIfIndex interface,
  AvahiProtocol protocol,
  AvahiBrowserEvent event,
  const char *type,
  const char *domain,
  AVAHI_GCC_UNUSED AvahiLookupResultFlags flags,
  void* userdata);

#endif