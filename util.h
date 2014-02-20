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

#include <avahi-core/core.h>

#ifndef _GNU_SOURCE
#define asprintf(B,T,...) ({ \
  int n = snprintf(NULL,0,T,##__VA_ARGS__); \
  *B = calloc(n+1,sizeof(char)); \
  snprintf(*B,n,T,##__VA_ARGS__); \
})
#endif

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

int isHex(const char *str, size_t len);
int isNumeric (const char *s);
int isUCIEncoded(const char *s, size_t s_len);
int isValidTtl(int ttl);
int isValidLifetime(long lifetime);
int isValidFingerprint(const char *sid, size_t sid_len);
int isValidSignature(const char *sig, size_t sig_len);

/**
 * Compare strings alphabetically, used in qsort
 */
int cmpstringp(const void *p1, const void *p2);

int tohex(unsigned char *str, size_t str_len, char *buf, size_t buf_size);

/**
 * Derives the UUID of a service, as a SHA1sum of the concatenation of (UCI-escaped) URI, port, and hostname
 * @param uri URI of the service
 * @param uri_len length of the URI
 * @param port (optional) the service port
 * @param[out] buf character buffer in which to store UUID
 * @param buf_size size of character buffer
 * @return length of UUID on success, 0 on error
 */
int get_uuid(char *uri, size_t uri_len, int port, char *hostname, size_t hostname_len, char *buf, size_t buf_size);

/**
 * UCI-escape a string. Alphanum and underscores are only chars allowed in UCI section titles
 * @param[in] to_escape the string to escape
 * @param[in] to_escape_len the length of the string to escape
 * @param[out] escaped_len length of escaped string
 * @return pointer to escaped string
 * @warning returned string must be freed by caller
 */
char *uci_escape(char *to_escape, size_t to_escape_len, size_t *escaped_len);

/**
 * Escape a string for use in printing service to file. Escapes ",\n,\r.
 * @param[in] to_escape the string to escape
 * @param[out] escaped_len length of escaped string
 * @return pointer to escaped string
 * @warning returned string must be freed by caller
 */
char *escape(char *to_escape, int *escaped_len);

/**
 * Convert an AvahiStringList to a string
 */
char *txt_list_to_string(AvahiStringList *txt);

#endif