/**
 *       @file  commotion-service-manager.h
 *      @brief  client API for the Commotion Service Manager
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

#ifndef COMMOTION_SERVICE_MANAGER_H
#define COMMOTION_SERVICE_MANAGER_H

typedef struct CSMCategory {
  struct CSMCategory *_next;
  //   size_t len;
  char category[1];
} CSMCategory;

typedef struct CSMService {
  char *key;
  char *name;
  char *description;
  char *uri;
  char *icon;
  uint8_t ttl;
  long lifetime;
  CSMCategory categories[1];
} CSMService;

/* It is the responsibility of the caller to make sure
 * all strings are NULL-terminated. */
int add_service(char const *key,
		char const *name,
		char const *description,
		char const *uri,
		char const *icon,
		uint8_t ttl,
		long lifetime,
		CSMCategory const *categories);

int remove_service(char const *key);

int get_services(CSMService **services);

#endif
