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

#include <avahi-core/core.h>

#include "commotion-service-manager.h"
#include "util.h"
#include "debug.h"

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

int isValidTtl(const char *ttl) {
  return isNumeric(ttl) && atoi(ttl) >= 0;
}

int isValidLifetime(const char *expiration_str) {
  return isNumeric(expiration_str) && atol(expiration_str) > 0;
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
      escaped = (char*)realloc(escaped, (*escaped_len)+1+1);
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
      escaped = (char*)realloc(escaped, (*escaped_len) + replacement_len + 1 + 1);
      strncpy(escaped + *escaped_len, "_", 1);
      strncpy(escaped + *escaped_len + 1, escaped_char, replacement_len);
      *escaped_len = *escaped_len + replacement_len + 1;
    }
    escaped[*escaped_len] = '\0';
    i++;
  }
  return escaped;
}

/**
 * Escape a string for use in printing service to file. Escapes \",\\n,\\r.
 * @param[in] to_escape the string to escape
 * @param[out] escaped_len length of escaped string
 * @return pointer to escaped string
 * @warning returned string must be freed by caller
 */
char *escape(char *to_escape, int *escaped_len) {
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
	escaped = (char*)realloc(escaped, (*escaped_len) + ESCAPE_QUOTE_LEN + 1);
	memcpy(escaped + *escaped_len, escape_quote, ESCAPE_QUOTE_LEN);
	*escaped_len = *escaped_len + ESCAPE_QUOTE_LEN;
	break;
      case '\n':
	escaped = (char*)realloc(escaped, (*escaped_len) + ESCAPE_LF_LEN + 1);
	memcpy(escaped + *escaped_len, escape_lf, ESCAPE_LF_LEN);
	*escaped_len = *escaped_len + ESCAPE_LF_LEN;
	break;
      case '\r':
	escaped = (char*)realloc(escaped, (*escaped_len) + ESCAPE_CR_LEN + 1);
	memcpy(escaped + *escaped_len, escape_cr, ESCAPE_CR_LEN);
	*escaped_len = *escaped_len + ESCAPE_CR_LEN;
	break;
      default:
	escaped = (char*)realloc(escaped, (*escaped_len)+1+1);
	escaped[*escaped_len] = to_escape[i];
	*escaped_len = *escaped_len + 1;
    }
    escaped[*escaped_len] = '\0';
    i++;
  }
  return escaped;
}

/**
 * Convert an AvahiStringList to a string
 */
char *txt_list_to_string(AvahiStringList *txt) {
  char *list = NULL;
  char *open_delimiter = OPEN_DELIMITER;
  char *close_delimiter = CLOSE_DELIMITER;
  char *field_delimiter = FIELD_DELIMITER;
  int list_len = 0;
  for (; txt; txt = txt->next) {
    int escaped_len = 0;
    char *escaped = escape(txt->text, &escaped_len);
    
    list = (char*)realloc(list, list_len + 
    OPEN_DELIMITER_LEN +
    CLOSE_DELIMITER_LEN +
    escaped_len + 
    1);
    list[list_len] = '\0';
    
    strcat(list, open_delimiter);
    strcat(list, escaped);
    strcat(list, close_delimiter);
    
    list_len += escaped_len + OPEN_DELIMITER_LEN + CLOSE_DELIMITER_LEN;
    list[list_len] = '\0';
    
    if (txt->next) {
      list = (char*)realloc(list, list_len + FIELD_DELIMITER_LEN + 1);
      strcat(list, field_delimiter);
      list_len += FIELD_DELIMITER_LEN;
      list[list_len] = '\0';
    }
    
    free(escaped);
  }
  return list;
}

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
    int *ret_len) {
    
    const char type_template[] = "<txt-record>type=%s</txt-record>";
    const char *str_template = "<type>%s</type>\n\
<domain-name>%s</domain-name>\n\
<port>%d</port>\n\
<txt-record>application=%s</txt-record>\n\
<txt-record>ttl=%d</txt-record>\n\
<txt-record>ipaddr=%s</txt-record>\n\
%s\n\
<txt-record>icon=%s</txt-record>\n\
<txt-record>description=%s</txt-record>\n\
<txt-record>expiration=%d</txt-record>";
    char *type_str = NULL, *sign_block = NULL, *app_type = NULL;
    int j, prev_len = 0;
    
    *ret_len = 0;
    
    qsort(&app_types[0],app_types_len,sizeof(char*),cmpstringp); /* Sort types into alphabetical order */
    
    /* Concat the types into a single string to add to template */
    for (j = 0; j < app_types_len; ++j) {
      if (app_type) {
	free(app_type);
	app_type = NULL;
      }
      prev_len = type_str ? strlen(type_str) : 0;
      CHECK_MEM(asprintf(&app_type,type_template,app_types[j]) != -1 &&
      (type_str = (char*)realloc(type_str,prev_len + strlen(app_type) + 1)));
      type_str[prev_len] = '\0';
      strcat(type_str,app_type);
    }
    
    /* Add the fields into the template */
    CHECK_MEM(asprintf(&sign_block,str_template,type,domain,port,name,ttl,ipaddr,app_types_len ? type_str : "",icon,description,expiration) != -1);
    
    *ret_len = strlen(sign_block);
    
error:
    if (app_type)
      free(app_type);
    if (type_str)
      free(type_str);
    return sign_block;
}
