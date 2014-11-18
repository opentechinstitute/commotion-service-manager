/**
 *       @file  util.c
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

#include "util.h"

#include <ctype.h>
#include <math.h>

#include <commotion/debug.h>
#include <commotion/obj.h>
#include <commotion/tree.h>
#include <commotion/list.h>

#include "extern/base32.h"

#include "defs.h"

int isHex(const char *str, size_t len) {
  int i;
  for (i = 0; i < len; ++i) {
    if (!isxdigit(str[i]))
      return 0;
  }
  return 1;
}

int isNumeric (const char *s)
{
  if (s == NULL || *s == '\0' || isspace(*s))
    return 0;
  char * p;
  strtoll (s, &p, 10);
  return *p == '\0';
}

int isValidFingerprint(const char *sid, size_t sid_len) {
  return sid_len == FINGERPRINT_LEN && strlen(sid) == FINGERPRINT_LEN && isHex(sid,sid_len);
}

/* Copyright (C) 2012 Serval Project Inc. */
static inline int hexvalue(char c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

/* Convert nbinary*2 ASCII hex characters [0-9A-Fa-f] to nbinary bytes of data.  Can be used to
 *  perform the conversion in-place, eg, fromhex(buf, (char*)buf, n);  Returns -1 if a non-hex-digit
 *  character is encountered, otherwise returns the number of binary bytes produced (= nbinary).
 *  @author Andrew Bettison <andrew@servalproject.com>
 *  Copyright (C) 2012 Serval Project Inc.
 */
static size_t fromhex(unsigned char *dstBinary, const char *srcHex, size_t nbinary)
{
  size_t count = 0;
  while (count != nbinary) {
    unsigned char high = hexvalue(*srcHex++);
    if (high & 0xf0) return -1;
    unsigned char low = hexvalue(*srcHex++);
    if (low & 0xf0) return -1;
    dstBinary[count++] = (high << 4) + low;
  }
  return count;
}

/**
 * Derives the UUID of a service, as a base32 encoding of the service's key
 * @param key hex-encoded service key
 * @param key_len length of service key
 * @param[out] buf character buffer in which to store UUID
 * @param buf_size size of character buffer
 * @return length of UUID on success, 0 on error
 */
int get_uuid(char *key, size_t key_len, char *buf, size_t buf_size) {
  int ret = 0;
  int uuid_len = (int)ceil((key_len / 2) * 8.0 / 5.0);
  
  CHECK(buf_size >= uuid_len + 1, "Insufficient buffer size");
  
  uint8_t bin_key[FINGERPRINT_LEN / 2] = {0};
  CHECK(fromhex(bin_key, key, FINGERPRINT_LEN / 2) == key_len / 2, "Unable to stow key");
  
  ret = base32_encode(bin_key, key_len / 2, (uint8_t*)buf, buf_size);
  
  CHECK(ret == uuid_len, "Failed to base32 encode UUID");
  
error:
  return ret;
}

static inline void
_csm_tree_process_r(co_obj_t *tree, _treenode_t *current, const _csm_iter_t iter, void *context)
{
  CHECK(IS_TREE(tree), "Recursion target is not a tree.");
  if(current != NULL)
  {
    if(current->value != NULL) iter(tree, current->key, current->value, context);
    _csm_tree_process_r(tree, current->low, iter, context); 
    _csm_tree_process_r(tree, current->equal, iter, context); 
    _csm_tree_process_r(tree, current->high, iter, context); 
  }
  return;
error:
  return;
}

int
csm_tree_process(co_obj_t *tree, const _csm_iter_t iter, void *context)
{
  CHECK(IS_TREE(tree), "Recursion target is not a tree.");
  _csm_tree_process_r(tree, ((co_tree16_t *)tree)->root, iter, context);
  return 1;
error:
  return 0;
}

struct _listnode_t
{
  _listnode_t *prev;
  _listnode_t *next;
  co_obj_t *value;
} __attribute__((packed));

static _listnode_t *
_co_list_get_first_node(const co_obj_t *list)
{
  CHECK_MEM(list);
  _listnode_t *n = NULL;
  if(CO_TYPE(list) == _list16)
  {
    n = ((co_list16_t *)list)->_first;
  } 
  else if(CO_TYPE(list) == _list32) 
  {
    n = ((co_list32_t *)list)->_first;
  }
  else SENTINEL("Specified object is not a list.");

  return n;
error:
  return NULL;
}

int
csm_list_parse(co_obj_t *list, co_obj_t *key, _csm_iter_t iter, void *context)
{
  CHECK(IS_LIST(list), "Not a list object.");
  _listnode_t *next = _co_list_get_first_node(list);
  while(next != NULL)
  {
    iter(list, key, next->value, context);
    next = ((_listnode_t *)next)->next;
  }
  return 1;
error:
  return 0;
}