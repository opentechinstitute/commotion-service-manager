/**
 *       @file  service_list.h
 *      @brief  service list-related functionality of the Commotion Service Manager
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

#ifndef CSM_SERVICE_LIST_H
#define CSM_SERVICE_LIST_H

#include <commotion/obj.h>
#include "service.h"

typedef struct csm_service_list {
  /** 
   * co_list16_t of csm_service pointers. This is used
   * to access the services' meta-data.
   */
  co_obj_t *services;
  
  /**
   * co_list16_t of service field maps. These maps contain
   * data that is useful to consumers of CSM updates, and 
   * is thus what gets passed over the wire in messages 
   * and updates.
   * 
   * Although these service fields correspond to the
   * csm_services in the services list above, there is no
   * guarantee they will be in the same order.
   */
  co_obj_t *service_fields;
  
  /**
   * co_list16_t of co_cbptr_t callback functions that
   * will be called (in the order they were registered)
   * whenever a change is commited to the list of services.
   */
  co_obj_t *update_handlers;
  
} csm_service_list;

csm_service_list *csm_services_init(void);
void csm_services_destroy(csm_service_list *services);

int csm_services_commit(csm_service_list *services);
int csm_services_register_commit_hook(csm_service_list *services, co_cb_t handler);

int csm_add_service(csm_service_list *services, csm_service *service);
int csm_update_service(csm_service_list *services, csm_service *service);
csm_service *csm_find_service(csm_service_list *services, const char *uuid);
csm_service *csm_remove_service(AvahiTimeout *t, void *service);
void csm_print_services(csm_service_list *services);

#if 0
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
#endif

#endif