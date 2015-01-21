/**
 *       @file  util.h
 *      @brief  utility functions for the Commotion Service Manager
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

#ifndef UTIL_H
#define UTIL_H

#include <commotion/obj.h>

typedef void (*_csm_iter_t)(co_obj_t *data, co_obj_t *key, co_obj_t *val, void *context);

int isHex(const char *str, size_t len);
int isNumeric (const char *s);
int isValidFingerprint(const char *sid, size_t sid_len);

/**
 * Derives the UUID of a service, as a base32 encoding of the service's key
 * @param key hex-encoded service key
 * @param key_len length of service key
 * @param[out] buf character buffer in which to store UUID
 * @param buf_size size of character buffer
 * @return length of UUID on success, 0 on error
 */
int get_uuid(char *key, size_t key_len, char *buf, size_t buf_size);

int csm_tree_process(co_obj_t *tree, const _csm_iter_t iter, void *context);
int csm_list_parse(co_obj_t *list, co_obj_t *key, _csm_iter_t iter, void *context);

#endif