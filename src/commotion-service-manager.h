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

enum {
  CSM_OK = 0,
  CSM_ERROR = -1,
  CSM_NOT_SET = -2
};

typedef void CSMConfig;
typedef void CSMService;
typedef void CSMServiceList;
typedef void CSMField;
typedef void CSMSchema;
typedef void CSMSchemaField;

// config functions
CSMConfig *csm_config_create(void);
int csm_config_set_mgmt_sock(CSMConfig *config, const char *sock);
void csm_config_free(CSMConfig *config);

// schema functions
int csm_schema_fetch(CSMSchema **schema, CSMConfig *config); // returns number of fields
int csm_schema_free(CSMSchema *schema);
int csm_schema_get_major_version(CSMConfig *config);
double csm_schema_get_minor_version(CSMConfig *config);
int csm_schema_length(CSMSchema *schema);

CSMSchemaField *csm_schema_get_next_field(CSMSchema *schema, CSMSchemaField *current, char **name); // set name if not NULL
CSMSchemaField *csm_schema_get_field_by_index(CSMSchema *schema, int index, char **name);
CSMSchemaField *csm_schema_get_field_by_name(CSMSchema *schema, char *name);

char *csm_schema_field_get_name(CSMSchemaField *schema_field);
int csm_schema_field_get_required(CSMSchemaField *schema_field, bool *out);
int csm_schema_field_get_generated(CSMSchemaField *schema_field, bool *out);
int csm_schema_field_get_type(CSMSchemaField *schema_field);

int csm_schema_field_get_list_subtype(CSMSchemaField *schema_field);
int csm_schema_field_get_string_length(CSMSchemaField *schema_field);
int csm_schema_field_get_min(CSMSchemaField *schema_field, long *out);
int csm_schema_field_get_max(CSMSchemaField *schema_field, long *out);

// service list functions
int csm_services_fetch(CSMServiceList **service_list, CSMConfig *config);
int csm_services_free(CSMServiceList *service_list);
int csm_services_length(CSMServiceList *service_list);

CSMService *csm_services_get_next_service(CSMServiceList *service_list, CSMService *current);
CSMService *csm_services_get_by_index(CSMServiceList *service_list, int index);
CSMService *csm_services_get_by_key(CSMServiceList *service_list, char *key);

// service functions
CSMService *csm_service_create(void);
void csm_service_destroy(CSMService *service);
int csm_service_commit(CSMService *service, CSMConfig *config); // adds key and signature to service
int csm_service_remove(CSMService *service, CSMConfig *config); // does not destroy service or remove from list

int csm_service_is_local(CSMService *service);

int csm_service_fields_get_length(CSMService *service);
CSMField *csm_service_get_next_field(CSMService *service, CSMField *current, char **name); // set name if not NULL
CSMField *csm_service_get_field_by_name(CSMService *service, const char *name);

// service field functions
char *csm_field_get_name(CSMField *field);
int csm_field_get_type(CSMField *field);
int csm_field_get_int(CSMField *field, long *out);
char *csm_field_get_string(CSMField *field);

int csm_field_get_list_subtype(CSMField *field);
int csm_field_get_list_length(CSMField *field);
int csm_field_get_list_int(CSMField *field, int index, long *out);
char *csm_field_get_list_string(CSMField *field, int index);

int csm_field_set_int(CSMField *field, long n);
int csm_field_set_string(CSMField *field, const char *str);
int csm_field_set_int_list_from_array(CSMField *field, long *array, int length);
int csm_field_set_string_list_from_array(CSMField *field, const char **array, int length);
int csm_field_list_append_int(CSMField *field, long n);
int csm_field_list_append_str(CSMField *field, const char *str);

int csm_service_set_int(CSMService *service, const char *field, long n);
int csm_service_set_string(CSMService *service, const char *field, const char *str);
int csm_service_set_int_list_from_array(CSMService *service, const char *field, long *array, int length);
int csm_service_set_string_list_from_array(CSMService *service, const char *field, const char **array, int length);
int csm_service_list_append_int(CSMService *service, const char *field, long n);
int csm_service_list_append_string(CSMService *service, const char *field, const char *str);

int csm_service_remove_field(CSMService *service, const char *field);

#endif