/**
 *       @file  schema.h
 *      @brief  functions for reading and parsing service announcement schema
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

#ifndef CSM_SCHEMA_H
#define CSM_SCHEMA_H

#include <commotion/obj.h>

typedef enum {
  CSM_FIELD_STRING = 1,
  CSM_FIELD_LIST,
  CSM_FIELD_INT,  /** int32_t */
  CSM_FIELD_HEX,
} csm_field_type;

struct csm_schema_version {
  int major;
  double minor;
};

typedef struct csm_schema_t {
  struct csm_schema_field_t *fields;
  //   char version[8];
  struct csm_schema_version version;
  struct csm_schema_t *_next;
  struct csm_schema_t *_prev;
} csm_schema_t;

csm_schema_t *csm_schema_new(void);
// void csm_schema_destroy(csm_schema_t *schema);
void csm_destroy_schemas(csm_ctx *ctx);
// int csm_import_service_schema(csm_schema_t *schema, const char *path);
int csm_import_schemas(csm_ctx *ctx, const char *dir);
int csm_validate_fields(csm_schema_t *schema, co_obj_t *entries);
// int csm_validate_field(csm_schema_t *schema, const char *field_name, csm_field_type type, co_obj_t *entry);

#endif