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

#include <avahi-common/address.h>
#include <avahi-common/watch.h>

#include <commotion/obj.h>

#include "defs.h"

struct csm_service_list;

typedef struct csm_service {
  /** Common members for all services */
  co_obj_t *fields; // co_tree16_t map of user-defined service fields
  struct csm_service_list *parent;
  
  AvahiIfIndex interface;
  AvahiProtocol protocol;
  char *uuid;
  char *type;
  char *domain;
  uint16_t port;
  char *expiration;
  AvahiTimeout *timeout; /** Timer set for the service's expiration date */
  
  /** Local services only */
  ENTRY_GROUP *group;
  int uptodate;
  
  /** Remote services only */
  char *host_name;
  char address[AVAHI_ADDRESS_STR_MAX];
  AvahiStringList *txt_lst; /**< Collection of all the user-defined txt fields */
  RESOLVER *resolver;
} csm_service;

csm_service *csm_service_new(AvahiIfIndex interface,
			     AvahiProtocol protocol,
			     const char *uuid,
			     const char *type,
			     const char *domain);
void csm_service_destroy(csm_service *s);

char *csm_service_get_name(csm_service *s);
char *csm_service_get_description(csm_service *s);
char *csm_service_get_uri(csm_service *s);
char *csm_service_get_icon(csm_service *s);
co_obj_t *csm_service_get_categories(csm_service *s);
int csm_service_get_ttl(csm_service *s);
long csm_service_get_lifetime(csm_service *s);
char *csm_service_get_key(csm_service *s);
char *csm_service_get_signature(csm_service *s);
char *csm_service_get_version(csm_service *s);

int csm_service_set_name(csm_service *s, const char *str);
int csm_service_set_description(csm_service *s, const char *str);
int csm_service_set_uri(csm_service *s, const char *str);
int csm_service_set_icon(csm_service *s, const char *str);
int csm_service_set_categories(csm_service *s, co_obj_t *categories);
int csm_service_set_ttl(csm_service *s, int ttl);
int csm_service_set_lifetime(csm_service *s, long lifetime);
int csm_service_set_key(csm_service *s, const char *str);
int csm_service_set_signature(csm_service *s, const char *str);
int csm_service_set_version(csm_service *s, const char *str);

void print_service(FILE *f, csm_service *s);
size_t csm_service_categories_to_array(csm_service *s, char ***cat_array);

int verify_signature(csm_service *service);
int create_signature(csm_service *service);

/** 
 * libcommotion object extended type for CSM services 
 * (used for storing in lists) 
 */
typedef struct {
  co_obj_t _header;
  uint8_t _exttype;
  uint8_t _len;
  csm_service *service;
} co_service_t;

#define _service 254

#define IS_SERVICE(J) (IS_EXT(J) && ((co_service_t *)J)->_exttype == _service)

co_obj_t *co_service_create(csm_service *service);

#endif