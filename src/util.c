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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <unistd.h>
#include <math.h>

#include <commotion/debug.h>
#include <commotion/obj.h>
#include <commotion/tree.h>
#include <commotion/list.h>

#include "defs.h"
#include "util.h"

#include "extern/base32.h"

#define ESCAPE_QUOTE "&quot;"
#define ESCAPE_QUOTE_LEN 6
#define ESCAPE_LF "&#10;"
#define ESCAPE_LF_LEN 5
#define ESCAPE_CR "&#13;"
#define ESCAPE_CR_LEN 5

#define OPEN_DELIMITER "\""
#define OPEN_DELIMITER_LEN 1
#define CLOSE_DELIMITER "\""
#define CLOSE_DELIMITER_LEN 1
#define FIELD_DELIMITER ","
#define FIELD_DELIMITER_LEN 1

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

int isUCIEncoded(const char *s, size_t s_len) {
  int i, ret = 0;
  for(i = 0; i < s_len; ++i) {
    if (!isalnum(s[i]) && s[i] != '_') {
      ret = 1;
      break;
    }
  }
  return ret;
}

int isValidTtl(int ttl) {
  return ttl >= 0 && ttl < 256;
}

int isValidLifetime(long lifetime) {
  return lifetime >= 0;
}

int isValidFingerprint(const char *sid, size_t sid_len) {
  return sid_len == FINGERPRINT_LEN && strlen(sid) == FINGERPRINT_LEN && isHex(sid,sid_len);
}

int isValidSignature(const char *sig, size_t sig_len) {
  return sig_len == SIG_LENGTH && strlen(sig) == SIG_LENGTH && isHex(sig,sig_len);
}

/**
 * Compare strings alphabetically, used in qsort
 */
int cmpstringp(const void *p1, const void *p2) {
  /* The actual arguments to this function are "pointers to
   *      pointers to char", but strcmp(3) arguments are "pointers
   *      to char", hence the following cast plus dereference */
  
  return strcmp(* (char * const *) p1, * (char * const *) p2);
}

int tohex(unsigned char *str, size_t str_len, char *buf, size_t buf_size) {
  CHECK(buf_size >= 2 * str_len,"Insufficient buffer size");
  for (int i = 0; i < str_len; i++)
    sprintf(&buf[i*2], "%02X", str[i]);
  return 1;
error:
  return 0;
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

/**
 * UCI-escape a string. Alphanum and underscores are only chars allowed in UCI section titles
 * @param[in] to_escape the string to escape
 * @param[in] to_escape_len the length of the string to escape
 * @param[out] escaped_len length of escaped string
 * @return pointer to escaped string
 * @warning returned string must be freed by caller
 */
char *uci_escape(char *to_escape, size_t to_escape_len, size_t *escaped_len) {
  char *escaped = NULL;
  char escaped_char[5];
  int replacement_len = 0;
  int i = 0;
  
  *escaped_len = 0;
  while (i<to_escape_len) {
    
    /*
     * Our alloc'd size is always one ahead 
     * of the string length to accommodate 
     * the NULL for the NULL-termination.
     */
    if (isalnum(to_escape[i])) {
      CHECK_MEM((escaped = (char*)realloc(escaped, (*escaped_len)+1+1)));
      escaped[*escaped_len] = to_escape[i];
      *escaped_len = *escaped_len + 1;
    } else {
      if (to_escape[i] < 10)
	replacement_len = 1;
      else if (to_escape[i] < 100)
	replacement_len = 2;
      else
	replacement_len = 3;
      sprintf(escaped_char,"%d",to_escape[i]);
      CHECK_MEM((escaped = (char*)realloc(escaped, (*escaped_len) + replacement_len + 1 + 1)));
      strncpy(escaped + *escaped_len, "_", 1);
      strncpy(escaped + *escaped_len + 1, escaped_char, replacement_len);
      *escaped_len = *escaped_len + replacement_len + 1;
    }
    escaped[*escaped_len] = '\0';
    i++;
  }
error:
  return escaped;
}

/**
 * Escape a string for use in printing service to file. Escapes \",\\n,\\r.
 * @param[in] to_escape the string to escape
 * @param[out] escaped_len length of escaped string
 * @return pointer to escaped string
 * @warning returned string must be freed by caller
 */
char *escape(char *to_escape, size_t *escaped_len) {
  char *escaped = NULL;
  char *escape_quote = ESCAPE_QUOTE;
  char *escape_lf = ESCAPE_LF;
  char *escape_cr = ESCAPE_CR;
  int i = 0;
  int to_escape_len = strlen(to_escape);
  
  *escaped_len = 0;
  while (i<to_escape_len) {
    
    /*
     * Our alloc'd size is always one ahead 
     * of the string length to accommodate 
     * the NULL for the NULL-termination.
     */
    switch (to_escape[i]) {
      case '\"':
	CHECK_MEM((escaped = (char*)realloc(escaped, (*escaped_len) + ESCAPE_QUOTE_LEN + 1)));
	memcpy(escaped + *escaped_len, escape_quote, ESCAPE_QUOTE_LEN);
	*escaped_len = *escaped_len + ESCAPE_QUOTE_LEN;
	break;
      case '\n':
	CHECK_MEM((escaped = (char*)realloc(escaped, (*escaped_len) + ESCAPE_LF_LEN + 1)));
	memcpy(escaped + *escaped_len, escape_lf, ESCAPE_LF_LEN);
	*escaped_len = *escaped_len + ESCAPE_LF_LEN;
	break;
      case '\r':
	CHECK_MEM((escaped = (char*)realloc(escaped, (*escaped_len) + ESCAPE_CR_LEN + 1)));
	memcpy(escaped + *escaped_len, escape_cr, ESCAPE_CR_LEN);
	*escaped_len = *escaped_len + ESCAPE_CR_LEN;
	break;
      default:
	CHECK_MEM((escaped = (char*)realloc(escaped, (*escaped_len)+1+1)));
	escaped[*escaped_len] = to_escape[i];
	*escaped_len = *escaped_len + 1;
    }
    escaped[*escaped_len] = '\0';
    i++;
  }
error:
  return escaped;
}

/**
 * Convert an AvahiStringList to a string
 */
char *
csm_txt_list_to_string(char *cur, size_t *cur_len, char *append, size_t append_len)
{
  char *open_delimiter = OPEN_DELIMITER;
  char *close_delimiter = CLOSE_DELIMITER;
  char *field_delimiter = FIELD_DELIMITER;
  char *escaped = escape(append, &append_len);
  CHECK_MEM(escaped);
  cur = realloc(cur, *cur_len
		     + OPEN_DELIMITER_LEN
		     + append_len
		     + CLOSE_DELIMITER_LEN
		     + FIELD_DELIMITER_LEN
		     + 1);
  CHECK_MEM(cur);
  cur[*cur_len] = '\0';
  
  strcat(cur, open_delimiter);
  strcat(cur, escaped);
  strcat(cur, close_delimiter);
  strcat(cur, field_delimiter);
  
  *cur_len += OPEN_DELIMITER_LEN + append_len + CLOSE_DELIMITER_LEN + FIELD_DELIMITER_LEN;
  cur[*cur_len] = '\0';

error:
  if (escaped)
    free(escaped);
  return cur;
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

#define _LIST_NEXT(J) (((_listnode_t *)J)->next)
#define _LIST_PREV(J) (((_listnode_t *)J)->prev)

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
    next = _LIST_NEXT(next);
  }
  return 1;
error:
  return 0;
}