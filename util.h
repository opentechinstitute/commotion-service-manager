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

/**
 * Compare strings alphabetically, used in qsort
 */
int cmpstringp(const void *p1, const void *p2);

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

// TODO document
char *createSigningTemplate(
  const char *type,
  const char *domain,
  const int port,
  const char *name,
  const int ttl,
  const char *ipaddr,
  const char **app_types,
  const int app_types_len,
  const char *icon,
  const char *description,
  const long expiration,
  int *ret_len);

#endif