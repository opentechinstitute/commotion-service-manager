/**
 *       @file  service.h
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

#ifndef CSM_SERVICE_H
#define CSM_SERVICE_H

#include <stdlib.h>

#include <avahi-core/core.h>
#include <avahi-core/lookup.h>
#include <avahi-core/publish.h>
#include <avahi-client/client.h>
#include <avahi-client/lookup.h>
#include <avahi-client/publish.h>
#include <avahi-common/llist.h>

ServiceInfo *find_service(const char *uuid);
ServiceInfo *add_service(BROWSER *b, 
			 AvahiIfIndex interface, 
			 AvahiProtocol protocol, 
			 const char *uuid, 
			 const char *type, 
			 const char *domain);
int process_service(ServiceInfo *i);
void remove_service(AvahiTimeout *t, void *userdata);
void print_services(int signal);

/**
 * Verify the Serval signature in a service announcement
 * @param i the service to verify (includes signature and fingerprint txt fields)
 * @returns 1 if the signature is valid, 0 if it is invalid
 */
int verify_signature(ServiceInfo *i);
int create_signature(ServiceInfo *i);

#endif