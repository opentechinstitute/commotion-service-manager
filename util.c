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

#include <avahi-core/core.h>

#include "defs.h"
#include "util.h"
#include "debug.h"

#include "extern/sha1.h"

#define ESCAPE_QUOTE "&quot;"
#define ESCAPE_QUOTE_LEN 6
#define ESCAPE_LF "&#10;"
#define ESCAPE_LF_LEN 5
#define ESCAPE_CR "&#13;"
#define ESCAPE_CR_LEN 5

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

/**
 * Derives the UUID of a service, as a SHA1sum of the concatenation of (UCI-escaped) URI, port, and hostname
 * @param uri URI of the service
 * @param uri_len length of the URI
 * @param port (optional) the service port
 * @param[out] buf character buffer in which to store UUID
 * @param buf_size size of character buffer
 * @return length of UUID on success, 0 on error
 */
int get_uuid(char *uri, size_t uri_len, int port, char *hostname, size_t hostname_len, char *buf, size_t buf_size) {
  char *uri_escaped = NULL;
  char *uuid = NULL;
  int ret = 0;
  
  CHECK(buf_size >= 2 * SHA1_DIGEST_SIZE,"UUID buffer too small");
  
  CHECK(uri && uri_len > 0,"Missing values needed for deriving UUID");
  
  size_t uri_escaped_len;
  uri_escaped = uci_escape(uri,uri_len,&uri_escaped_len);
  CHECK(uri_escaped,"Failed to escape URI");
  
  char port_str[6] = {0};
  if (port > 0)
    sprintf(port_str,"%d",port);
  
  uuid = calloc(uri_escaped_len + strlen(port_str) + hostname_len + 1,sizeof(char));
  CHECK_MEM(uuid);
  
  strncpy(uuid,uri_escaped,uri_escaped_len);
  strcat(uuid,port_str);
  strcat(uuid,hostname);
  
  SHA1_CTX ctx;
  SHA1_Init(&ctx);
  SHA1_Update(&ctx, (const uint8_t*)uuid, strlen(uuid));
  unsigned char sha1sum[SHA1_DIGEST_SIZE] = {0};
  SHA1_Final(&ctx, (uint8_t*)sha1sum);
  CHECK(tohex(sha1sum,SHA1_DIGEST_SIZE,buf,buf_size),"Failed to convert sha1sum to hex");

  ret = 2 * SHA1_DIGEST_SIZE;
error:
  if (uri_escaped) free(uri_escaped);
  if (uuid) free(uuid);
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
