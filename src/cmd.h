/**
 *       @file  cmd.h
 *      @brief  command handlers for Commotion Service Manager
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

#ifndef CSM_CMD_H
#define CSM_CMD_H

#include <commotion/obj.h>

int cmd_help(co_obj_t *self, co_obj_t **output, co_obj_t *params);
int cmd_commit_service(co_obj_t *self, co_obj_t **output, co_obj_t *params);
int cmd_remove_service(co_obj_t *self, co_obj_t **output, co_obj_t *params);
int cmd_list_services(co_obj_t *self, co_obj_t **output, co_obj_t *params);
int cmd_get_schema(co_obj_t *self, co_obj_t **output, co_obj_t *params);
int cmd_get_schema_version(co_obj_t *self, co_obj_t **output, co_obj_t *params);

#endif