/**
 *       @file  schema.c
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

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <ctype.h>

#include <commotion/obj.h>
#include <commotion/list.h>
#include <commotion/tree.h>

#include "extern/jsmn.h"

#include "util.h"
#include "schema.h"

#define DEFAULT_TOKENS 128

typedef enum {
  CSM_ATTR_FIELD = 1,
  CSM_ATTR_REQUIRED,
  CSM_ATTR_TYPE,
  CSM_ATTR_SUBTYPE,
  CSM_ATTR_LENGTH,
  CSM_ATTR_MIN,
  CSM_ATTR_MAX
} csm_field_attr;

enum {
  CSM_LIMIT_MIN = (1 << 0),
  CSM_LIMIT_MAX = (1 << 1)
};

// typedef int (*csm_field_validator_t)(co_obj_t *data, csm_field_validator_t *schema);

typedef struct csm_schema_field_t {
  char field[256];
  bool required;
  csm_field_type type;
  
  // lists only
  csm_field_type subtype;
  
  // strings only
  size_t length;
  
  // ints only
  uint8_t limits_flag;
  long min;
  long max;
  
  /** 
   * In the future, we may want to add a validation callback pointer
   * for custom validators
   */
//   csm_field_validator_t validate; 
  
  struct csm_schema_field_t *_next;
} csm_schema_field_t;

struct csm_schema_t {
  struct csm_schema_field_t *fields;
  char version[8];
};

/* Private */

static jsmntok_t *_co_json_string_tokenize(const char *js)
{
  jsmn_parser parser;
  jsmn_init(&parser);

  unsigned int t = DEFAULT_TOKENS;
  jsmntok_t *tokens = h_calloc(t, sizeof(jsmntok_t));
  CHECK_MEM(tokens);

  int ret = jsmn_parse(&parser, js, tokens, t);

  while (ret == JSMN_ERROR_NOMEM)
  {
      t = t * 2 + 1;
      tokens = h_realloc(tokens, sizeof(jsmntok_t) * t);
      CHECK_MEM(tokens);
      ret = jsmn_parse(&parser, js, tokens, t);
  }

  CHECK(ret != JSMN_ERROR_INVAL, "Invalid JSON.");
  CHECK(ret != JSMN_ERROR_PART, "Incomplete JSON.");

  return tokens;
error:
  if(tokens != NULL) h_free(tokens);
  return NULL;
}

static char *_co_json_token_stringify(char *json, const jsmntok_t *token)
{
  json[token->end] = '\0';
  return json + token->start;
}

static int
_csm_attr_str(char *key)
{
  if (0 == strcmp(key, "field"))
    return CSM_ATTR_FIELD;
  else if (0 == strcmp(key, "required"))
    return CSM_ATTR_REQUIRED;
  else if (0 == strcmp(key, "type"))
    return CSM_ATTR_TYPE;
  else if (0 == strcmp(key, "subtype"))
    return CSM_ATTR_SUBTYPE;
  else if (0 == strcmp(key, "length"))
    return CSM_ATTR_LENGTH;
  else if (0 == strcmp(key, "min"))
    return CSM_ATTR_MIN;
  else if (0 == strcmp(key, "max"))
    return CSM_ATTR_MAX;
  return -1;
}

static int
_csm_type_str(char *key)
{
  if (0 == strcmp(key, "string"))
    return CSM_FIELD_STRING;
  else if (0 == strcmp(key, "list"))
    return CSM_FIELD_LIST;
  else if (0 == strcmp(key, "int"))
    return CSM_FIELD_INT;
  else if (0 == strcmp(key, "hex"))
    return CSM_FIELD_HEX;
  return -1;
}

static int
_csm_validate_int(csm_schema_field_t *schema_field, co_obj_t *entry)
{
  if (IS_INT(entry)) {
    int n;
    co_obj_data((char**)&n, entry);
    if ((!(schema_field->limits_flag & CSM_LIMIT_MIN) || n >= schema_field->min)
      && (!(schema_field->limits_flag & CSM_LIMIT_MAX) || n <= schema_field->max))
      return 1;
  }
  return 0;
}

static int
_csm_validate_string(csm_schema_field_t *schema_field, co_obj_t *entry, int hex)
{
  if (IS_STR(entry)) {
    char *str;
    size_t str_len = co_obj_data(&str, entry);
    if (!schema_field->length || str_len < schema_field->length) {
      if (hex) {
	for (int i = 0; i < str_len; ++i) {
	  if (!isxdigit(str[i]))
	    return 0;
	}
      }
      return 1;
    }
  }  
  return 0;
}

static co_obj_t *_csm_validate_list(co_obj_t *list, co_obj_t *current, void *context);

static int
_csm_validate_field(csm_schema_field_t *schema_field, csm_field_type type, co_obj_t *entry)
{
  switch (type) {
    case CSM_FIELD_STRING:
      if (!_csm_validate_string(schema_field, entry, 0)) {
	ERROR("Invalid service string");
	return 0;
      }
      break;
    case CSM_FIELD_INT:
      if (!_csm_validate_int(schema_field, entry)) {
	ERROR("Invalid service int");
	return 0;
      }
      break;
    case CSM_FIELD_HEX:
      if (!_csm_validate_string(schema_field, entry, 1)) {
	ERROR("Invalid service hex");
	return 0;
      }
      break;
    case CSM_FIELD_LIST:
      if (!IS_LIST(entry)) {
	ERROR("Service field is not a list");
	return 0;
      }
      if (co_list_parse(entry, _csm_validate_list, schema_field) != NULL) {
	ERROR("Invalid service field list");
	return 0;
      }
    default:
      ERROR("Invalid field type");
      return 0;
  }
  return 1;
}

static co_obj_t *
_csm_validate_list(co_obj_t *list, co_obj_t *current, void *context)
{
  if (IS_LIST(current)) return NULL;
  csm_schema_field_t *schema_field = (csm_schema_field_t*)context;
  if (!_csm_validate_field(schema_field, schema_field->subtype, current))
    return current;
  return NULL;
}

/* Public */

csm_schema_t *
csm_schema_new(void)
{
  csm_schema_t *schema = h_calloc(1, sizeof(csm_schema_t));
  return schema;
}

void
csm_schema_destroy(csm_schema_t *schema)
{
  csm_schema_field_t *tmp = NULL;
  while (schema->fields) {
    tmp = schema->fields;
    schema->fields = tmp->_next;
    h_free(tmp);
  }
  h_free(schema);
}

int
csm_import_service_schema(csm_schema_t *schema, const char *path)
{
  int ret = 0;
  char *buffer = NULL;
  FILE *schema_file = NULL;
  schema_file = fopen(path, "rb");
  csm_schema_field_t *field = NULL;
  jsmntok_t *tokens = NULL;
  CHECK(schema_file != NULL, "File %s could not be opened", path);
  fseek(schema_file, 0, SEEK_END);
  long fsize = ftell(schema_file);
  rewind(schema_file);
  buffer = h_calloc(1, fsize + 1);
  CHECK(fread(buffer, fsize, 1, schema_file) != 0, "Failed to read from file.");
  fclose(schema_file);
  schema_file = NULL;
  
  buffer[fsize] = '\0';
  tokens = _co_json_string_tokenize(buffer);
  
  typedef enum { START, FIELD, KEY, VALUE, STOP } parse_state;
  parse_state state = START;
  size_t object_tokens = 0;
  char *key = NULL;
  size_t klen = 0;
  
  for (size_t i = 0, j = 1; j > 0; i++, j--)
  {
    jsmntok_t *t = &tokens[i];

    // Should never reach uninitialized tokens
    CHECK(t->start != -1 && t->end != -1, "Tokens uninitialized.");

    if (t->type == JSMN_ARRAY || t->type == JSMN_OBJECT)
      j += t->size;

    switch (state)
    {
      case START:
        if (t->type == JSMN_OBJECT) {
	  state = KEY;
	} else if (t->type == JSMN_ARRAY) {
	  state = FIELD;
	} else {
	  SENTINEL("Invalid root element");
	}
	
        object_tokens = t->size;

        if (object_tokens == 0)
          state = STOP;
	
	if (t->type == JSMN_OBJECT)
	  CHECK(object_tokens % 2 == 0, "Object must have even number of children.");
	
        break;
	
      case KEY:
        object_tokens--;

        CHECK(t->type == JSMN_STRING, "Keys must be strings.");
        state = VALUE;
        key = _co_json_token_stringify(buffer, t);
        klen = t->end - t->start;

        break;

      case VALUE:
	assert(key != NULL && klen > 0);
	
	char *val = _co_json_token_stringify(buffer, t);
	CHECK(val, "Invalid schema version");
	
	if (strcmp(key, "version") == 0) {
	  CHECK(t->type == JSMN_STRING, "Version must be a string");
	  strcpy(schema->version, val);
	  INFO("Registering schema with version %s", schema->version);
	} else if (strcmp(key, "fields") == 0) {
	  // pass
	} else { // field attributes
// 	  assert(field);
	  CHECK(t->type == JSMN_STRING || t->type == JSMN_PRIMITIVE, "Values must be strings or primitive");
	  
	  if (!field) {
	    field = h_calloc(1, sizeof(csm_schema_field_t));
	    CHECK_MEM(field);
	  }
	  
	  csm_field_attr attr = _csm_attr_str(key);
	  int n;
	  long m;
	  switch (attr)
	  {
	    case CSM_ATTR_FIELD:
	      strcpy(field->field, val);
	      break;
	    case CSM_ATTR_REQUIRED:
	      if (strncmp(val, "t", 1) == 0)
		field->required = true;
	      else
		field->required = false;
	      break;
	    case CSM_ATTR_TYPE:
	      n = _csm_type_str(val);
	      CHECK(n != -1, "Invalid field type %s", val);
	      field->type = n;
	      break;
	    case CSM_ATTR_SUBTYPE:
	      n = _csm_type_str(val);
	      CHECK(n != -1, "Invalid field type %s", val);
	      field->subtype = n;
	      break;
	    case CSM_ATTR_LENGTH:
	      n = atoi(val);
	      CHECK(n > 0, "Invalid length");
	      field->length = n;
	      break;
	    case CSM_ATTR_MIN:
	    case CSM_ATTR_MAX:
	      errno = 0;
	      m = strtol(val, NULL, 10);
	      CHECK(errno == 0, "Invalid min/max");
	      if (attr == CSM_ATTR_MIN) {
		field->min = m;
		field->limits_flag |= CSM_LIMIT_MIN;
	      } else {
		field->max = m;
		field->limits_flag |= CSM_LIMIT_MAX;
	      }
	      break;
	    default:
	      SENTINEL("Invalid field attribute");
	  }
	}

        key = NULL;
        klen = 0;
        object_tokens--;
        state = KEY;

        if (object_tokens == 0) {
	  CHECK(strlen(field->field) > 0 && field->type, "Invalid field");
	  if (field->type == CSM_FIELD_LIST)
	    CHECK(field->subtype, "Invalid field subtype");
	  
	  // append field to schema
	  field->_next = schema->fields;
	  schema->fields = field;
	  
	  field = NULL;
          state = STOP;
	}
	
        break;

      case STOP:
	// Just consume the tokens
        break;

      default:
        SENTINEL("Invalid state %u", state);
    }
  }
  
  ret = 1;
error:
  if (buffer)
    h_free(buffer);
  if (schema_file)
    fclose(schema_file);
  if (tokens)
    h_free(tokens);
  if (field)
    h_free(field);
  return ret;
}

int
csm_validate_fields(csm_schema_t *schema, co_obj_t *entries)
{
  assert(IS_TREE(entries));
  // iterate through schema fields
  csm_schema_field_t *schema_field = schema->fields;
  for (; schema_field; schema_field = schema_field->_next) {
    co_obj_t *service_field = co_tree_find(entries, schema_field->field, strlen(schema_field->field) + 1);
    if (schema_field->required && !service_field) {
      ERROR("Missing required field %s", schema_field->field);
      return 0;
    }
    if (service_field
        && !_csm_validate_field(schema_field, schema_field->type, service_field))
      return 0;
  }
  return 1;
}

int
csm_validate_field(csm_schema_t *schema, const char *field_name, csm_field_type type, co_obj_t *entry)
{
  csm_schema_field_t *schema_field = schema->fields;
  for (; schema_field; schema_field = schema_field->_next) {
    if (strcmp(schema_field->field, field_name) == 0)
      break;
  }
  if (!schema_field) {
    ERROR("Schema field name not found");
    return 0;
  }
  return _csm_validate_field(schema_field, type, entry);
}