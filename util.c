#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <avahi-core/core.h>

#include "util.h"

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
  strtod (s, &p);
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

int cmpstringp(const void *p1, const void *p2) {
  /* The actual arguments to this function are "pointers to
   *      pointers to char", but strcmp(3) arguments are "pointers
   *      to char", hence the following cast plus dereference */
  
  return strcmp(* (char * const *) p1, * (char * const *) p2);
}

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