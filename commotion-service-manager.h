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

// typedef char** StringArray;
// typedef struct CSMService CSMService;
// typedef CSMService** CSMServiceArray;
typedef void CSMService;
typedef void CSMServiceList;
typedef void CategoryList;



// edit service if key exists in list of services, otherwise create new
// int edit_service(char *key, CSMService *service);

// CSMService *service_new(void);
// void service_free(CSMService *service);
void *service_new(void *services);
// void service_free(void *service);

/* It is the responsibility of the caller to make sure
 * all strings are NULL-terminated, and less than 256 chars. */
// int service_set_key(CSMService *service,  const *key);
int service_set_name(CSMService *service, char const *name);
int service_set_description(CSMService *service, char const *description);
int service_set_uri(CSMService *service, char const *uri);
int service_set_icon(CSMService *service, char const *icon);
int service_set_ttl(CSMService *service, int ttl);
int service_set_lifetime(CSMService *service, long lifetime);
int service_set_categories(CSMService *service, char const * const *categories, size_t cat_len);
int service_add_category(CSMService *service, char const *category);
int service_remove_category(CSMService *service, char const *category);

// CSMService *service_get(CSMService **services, char const *key);

char *service_get_key(CSMService *service);
char *service_get_name(CSMService *service);
char *service_get_description(CSMService *service);
char *service_get_uri(CSMService *service);
char *service_get_icon(CSMService *service);
int service_get_ttl(CSMService *service);
long service_get_lifetime(CSMService *service);
int service_get_categories(CSMService *service, CategoryList **categories);
char *categories_get(CategoryList *categories, int index);
char *service_get_signature(CSMService *service);

/**
 * adds or updates service, also generates signature (and key if needed)
 */
int service_commit(CSMService *service);
/* calls service_free() */
int service_remove(CSMService *service);
/* returns # of services */
// int get_services(CSMServiceArray *services);
// int free_services(CSMServiceArray services, int n_services);

int services_fetch(CSMServiceList **services);
CSMService *services_get(CSMServiceList *services, int index);
int services_free(CSMServiceList *services);

// TODO register socket w/ CSM daemon for "push" notifications of service changes? (using DBus?)

#endif
