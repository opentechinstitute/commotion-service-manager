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

#include "schema.h"

#define CSM_ERROR -1
#define CSM_OK 0

typedef void CSMService;
typedef void CSMServiceList;
typedef void CSMField;
typedef void CSMSchema;

// TODO schema functions
int schema_fetch(CSMSchema **schema); // returns number of fields


int services_fetch(CSMServiceList **service_list);
int services_free(CSMServiceList *service_list);

CSMService *service_create(void);
int service_commit(CSMService *service); // adds key and signature to service
int service_remove(CSMService *service); // does not destroy service or remove from list

CSMService *services_get_by_index(CSMServiceList *service_list, int index);
CSMService *services_get_by_key(CSMServiceList *service_list, char *key);

int service_is_local(CSMService *service);

int service_fields_get_length(CSMService *service);
CSMField *service_field_get_next(CSMService *service, CSMField *current, char **name); // set name if not NULL
CSMField *service_field_get_by_name(CSMService *service, const char *name);

char *service_field_get_name(CSMField *field);
int service_field_get_type(CSMField *field);
long service_field_get_int(CSMField *field);
char *service_field_get_string(CSMField *field);

int service_field_get_list_subtype(CSMField *field);
int service_field_get_list_length(CSMField *field);
long service_field_get_list_int(CSMField *field, int index);
char *service_field_get_list_string(CSMField *field, int index);

int service_field_set_int(CSMField *field, long n);
int service_field_set_string(CSMField *field, const char *str);
int service_field_set_int_list_from_array(CSMField *field, long *array, int length);
int service_field_set_string_list_from_array(CSMField *field, const char **array, int length);
int service_field_list_append_int(CSMField *field, long n);
int service_field_list_append_str(CSMField *field, const char *str);

int service_set_int(CSMService *service, const char *field, long n);
int service_set_string(CSMService *service, const char *field, const char *str);
int service_set_int_list_from_array(CSMService *service, const char *field, long *array, int length);
int service_set_string_list_from_array(CSMService *service, const char *field, const char **array, int length);
int service_list_append_int(CSMService *service, const char *field, long n);
int service_list_append_string(CSMService *service, const char *field, const char *str);

int service_remove_field(CSMService *service, const char *field);

#endif