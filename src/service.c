/**
 *       @file  service.c
 *      @brief  service-related functionality of the Commotion Service Manager
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <net/if.h>

#include <commotion/debug.h>
#include <commotion/obj.h>
#include <commotion/tree.h>
#include <commotion/list.h>
#include <commotion.h>

#include "extern/halloc.h"

#include "defs.h"
#include "util.h"
#include "service.h"
#include "schema.h"

extern struct csm_config csm_config;

// from libcommotion_serval-sas
#define SAS_SIZE 32
extern int keyring_send_sas_request_client(const char *sid_str, 
					   const size_t sid_len,
					   char *sas_buf,
					   const size_t sas_buf_len);

/* Private */

static ssize_t
_csm_signing_template_append(char **txt_fields, size_t txt_len, co_obj_t *fkey, co_obj_t *fval)
{
  char txt[281] = {0};
  int ret = -1, tlen = 0;
  if (IS_STR(fval)) {
    tlen = snprintf(txt,
		    280,
		    "<txt-record>%s=%s</txt-record>",
		    co_obj_data_ptr(fkey),
		    co_obj_data_ptr(fval));
    CHECK(tlen > 0, "Failed to create txt record");
  } else if (IS_INT(fval)) {
    tlen = snprintf(txt,
		    280,
		    "<txt-record>%s=%"PRId32"</txt-record>",
		    co_obj_data_ptr(fkey),
		    ((co_int32_t*)fval)->data);
    CHECK(tlen > 0, "Failed to create txt record");
  } else {
    SENTINEL("Invalid service field");
  }
  // NOTE: for some reason, using h_realloc here was causing heap corruption:
  *txt_fields = realloc(*txt_fields, txt_len + tlen + 1 + 1); // extra +1 for trailing \n
  memset(*txt_fields + txt_len,'\0',tlen + 1 + 1);
  strcat(*txt_fields,txt);
  strcat(*txt_fields,"\n");
  txt_len += tlen + 1;
  ret = txt_len;
error:
  return ret;
}

// #if 0
static co_obj_t *
_csm_sort_list(co_obj_t *list, co_obj_t *current, void *context)
{
  co_obj_t *clone = NULL, *ret = current;
  char *raw = NULL;
  co_obj_t *sorted_list = (co_obj_t*)context;
  ssize_t llen = co_list_length(sorted_list);
  CHECK(llen >= 0, "Invalid list");
  ssize_t rlen = co_obj_raw(&raw, current);
  CHECK(rlen > 0, "Invalid service field");
  CHECK(co_obj_import(&clone, raw, rlen, 0) > 0 && clone, "Failed to clone service field");
  if (llen == 0) {
    CHECK(co_list_append(sorted_list,clone), "Failed to insert clone");
    clone = NULL;
  } else {
    for (int i = 0; i < llen; i++) {
      int cmp = co_str_cmp(clone,co_list_element(sorted_list,i));
      if (cmp < 0) {
	CHECK(co_list_insert_before(sorted_list,clone,co_list_element(sorted_list,i)),
	      "Failed to insert service field into sorted_list");
	clone = NULL;
	break;
      }
    }
    if (clone) {
      CHECK(co_list_append(sorted_list,clone), "Failed to insert service field into sorted list");
      clone = NULL;
    }
  }
  ret = NULL;
error:
  if (clone)
    co_obj_free(clone);
  return ret;
}
// #endif

#if 0
static co_obj_t *
_csm_sort_list(co_obj_t *list, co_obj_t *current, void *context)
{
  DEBUG("sorting %s",co_obj_data_ptr(current));
  co_obj_t *sorted_list = (co_obj_t*)context;
  ssize_t llen = co_list_length(sorted_list);
  CHECK(llen >= 0, "Invalid list");
  if (llen == 0) {
    co_list_append_unsafe(sorted_list,current);
  } else {
    for (int i = 0; i < llen; i++) {
      int cmp = co_str_cmp(current,co_list_element(sorted_list,i));
      if (cmp < 0) {
	CHECK(co_list_insert_before_unsafe(sorted_list,current,co_list_element(sorted_list,i)),
	      "Failed to insert service field into sorted_list");
	current = NULL;
      }
    }
    if (current)
      CHECK(co_list_append_unsafe(sorted_list,current), "Failed to insert service field into sorted list");
  }
  return NULL;
error:
  return current;
}
#endif

static size_t
_csm_create_signing_template(csm_service *s, char **template)
{
  int ret = 0;
  char *txt_fields = NULL;
  size_t txt_len = 0;
  
  /* Sort fields into alphabetical order */
  co_obj_t *fkey = co_tree_next(s->fields,NULL);
  CHECK(fkey, "Unable to get service fields to create signing template");
  for (; fkey ; fkey = co_tree_next(s->fields,fkey)) {
    char *kstr = NULL;
    ssize_t klen = co_obj_data(&kstr, fkey);
    co_obj_t *fval = co_tree_find(s->fields, kstr, klen);
    CHECK(fval, "Unable to get service field value to create signing template");
    if (IS_LIST(fval)) {
      ssize_t llen = co_list_length(fval);
      CHECK(llen > 0, "Invalid list service field");
      co_obj_t *sorted_list = co_list16_create();
      CHECK(co_list_parse(fval, _csm_sort_list, sorted_list) == NULL, "Failed to sort service field list");
      for (int i = 0; i < llen; i++) {
	txt_len = _csm_signing_template_append(&txt_fields, txt_len, fkey, co_list_element(sorted_list,i));
	if (txt_len <= 0) {
	  co_obj_free(sorted_list);
	  SENTINEL("Failed to add txt record to signing template");
	}
      }
      co_obj_free(sorted_list);
    } else {
      if (strcmp(co_obj_data_ptr(fkey),"key") != 0 && strcmp(co_obj_data_ptr(fkey),"signature") != 0) {
	CHECK((txt_len = _csm_signing_template_append(&txt_fields, txt_len, fkey, fval)) > 0,
	      "Failed to add txt record to signing template");
      }
    }
  }
  txt_fields[txt_len] = '\0'; // remove last \n
  
  // finally create the signing template
  int bytes = asprintf(template,
		       "<type>%s</type>\n<domain-name>%s</domain-name>\n<port>%d</port>\n%s",
		       s->type,
		       s->domain,
		       s->port,
		       txt_fields);
  CHECK(bytes > 0, "Failed to create signing template");
  
  ret = strlen(*template);
error:
//   if (fields.fields)
//     h_free(fields.fields);
  if (txt_fields)
    free(txt_fields);
  return ret;
}

/* Public */

static co_obj_t *
co_service_create(void) {
  co_service_t *output = h_calloc(1,sizeof(co_service_t));
  CHECK_MEM(output);
  output->_header._type = _ext8;
  output->_exttype = _service;
  output->_len = (sizeof(co_service_t));
//   output->service = service;
  return (co_obj_t*)output;
error:
  return NULL;
}

csm_service *
csm_service_new(AvahiIfIndex interface,
		AvahiProtocol protocol,
		const char *uuid,
		const char *type,
		const char *domain)
{
  // allocate a full co_service_t that contains the csm_service
  co_service_t *s_obj = (co_service_t*)co_service_create();
  csm_service *s = NULL;
  
  CHECK_MEM(s_obj);
  s = &(s_obj->service);
  
  s->interface = interface;
  s->protocol = protocol;
  if (uuid) {
    s->uuid = h_strdup(uuid);
    CHECK_MEM(s->uuid);
    service_attach(s->uuid, s);
  }
  s->type = h_strdup(type);
  CHECK_MEM(s->type);
  service_attach(s->type, s);
  s->domain = h_strdup(domain);
  CHECK_MEM(s->domain);
  service_attach(s->domain, s);
  
  // create tree for holding user-defined service fields
  co_obj_t *fields = co_tree16_create();
  CHECK_MEM(fields);
  
  s->fields = fields;
  service_attach(s->fields, s);
  return s;
error:
  if (s)
    h_free(s);
  return NULL;
}

void
csm_service_destroy(csm_service *s)
{
  assert(s);
  
  // get the co_service_t container and free that
  co_service_t *s_obj = container_of(s, co_service_t, service);
  
  if (s->r.txt_lst)
    avahi_string_list_free(s->r.txt_lst);
  
  if (s->local && s->l.group)
    ENTRY_GROUP_FREE(s->l.group);
  
  // free co_service_t container
  h_free(s_obj);
}

char *
csm_service_get_str(const csm_service *s, const char *field)
{
  assert(IS_TREE(s->fields));
  co_obj_t *field_obj = co_tree_find(s->fields, field, strlen(field) + 1);
  CHECK(field_obj, "String field %s not found", field);
  return ((co_str8_t*)field_obj)->data;
error:
  return NULL;
}

co_obj_t *
csm_service_get_list(const csm_service *s, const char *field)
{
  assert(IS_TREE(s->fields));
  return co_tree_find(s->fields,"name",sizeof("name"));
}

int32_t
csm_service_get_int(const csm_service *s, const char *field)
{
  assert(IS_TREE(s->fields));
  co_obj_t *field_obj = co_tree_find(s->fields, field, strlen(field) + 1);
  CHECK(field_obj, "Integer field %s not found", field);
  return ((co_int32_t*)field_obj)->data;
error:
  return 0;
}

int
csm_service_set_str(csm_service *s, const char *field, const char *str)
{
  assert(IS_TREE(s->fields));
  if (str) {
    co_obj_t *str_obj = co_str8_create(str, strlen(str) + 1, 0);
    CHECK_MEM(str_obj);
    CHECK(co_tree_insert(s->fields, field, strlen(field) + 1, str_obj),
	  "Failed to insert %s into service", field);
  } else {
    co_obj_t *old_str = co_tree_delete(s->fields, field, strlen(field) + 1);
    if (old_str)
      co_obj_free(old_str);
  }
  return 1;
error:
  return 0;
}

int
csm_service_set_int(csm_service *s, const char *field, int32_t n)
{
  assert(IS_TREE(s->fields));
  co_obj_t *int_obj = co_int32_create(n, 0);
  CHECK_MEM(int_obj);
  CHECK(co_tree_insert(s->fields, field, strlen(field) + 1, int_obj),
	"Failed to insert %s into service", field);
  return 1;
error:
  return 0;
}

int csm_service_remove_int(csm_service *s, const char *field)
{
  assert(IS_TREE(s->fields));
  co_obj_t *old_int = co_tree_delete(s->fields, field, strlen(field) + 1);
  if (old_int)
    co_obj_free(old_int);
  return 1;
}

int
csm_service_set_list(csm_service *s, const char *field, co_obj_t *list)
{
  assert(IS_TREE(s->fields));
  if (list) {
    CHECK(co_tree_insert(s->fields, field, strlen(field) + 1, list),
	  "Failed to insert %s into service", field);
  } else {
    co_obj_t *old_list = co_tree_delete(s->fields, field, strlen(field) + 1);
    if (old_list)
      co_obj_free(old_list);
  }
  return 1;
error:
  return 0;
}

int
csm_service_append_str_to_list(csm_service *s, const char *field, const char *str)
{
  assert(IS_TREE(s->fields));
  co_obj_t *list = co_tree_find(s->fields, field, strlen(field) + 1);
  if (!list) {
    list = co_list16_create();
    CHECK_MEM(list);
    CHECK(co_tree_insert(s->fields, field, strlen(field) + 1, list),
	  "Failed to insert %s into service", field);
  }
  co_obj_t *str_obj = co_str8_create(str, strlen(str) + 1, 0);
  CHECK_MEM(str_obj);
  CHECK(co_list_append(list, str_obj), "Failed to append service field to list");
  return 1;
error:
  return 0;
}

int
csm_service_append_int_to_list(csm_service *s, const char *field, int32_t n)
{
  assert(IS_TREE(s->fields));
  co_obj_t *list = co_tree_find(s->fields, field, strlen(field) + 1);
  if (!list) {
    list = co_list16_create();
    CHECK_MEM(list);
    CHECK(co_tree_insert(s->fields, field, strlen(field) + 1, list),
	  "Failed to insert %s into service", field);
  }
  co_obj_t *int_obj = co_int32_create(n, 0);
  CHECK_MEM(int_obj);
  CHECK(co_list_append(list, int_obj), "Failed to append service field to list");
  return 1;
error:
  return 0;
}

int
csm_verify_signature(csm_service *s)
{
  int verdict = 0, i;
  co_obj_t *co_conn = NULL, *co_req = NULL, *co_resp = NULL;
  char *to_verify = NULL;
  CHECK(s->key && s->signature, "Service missing key or signature");
  CHECK(_csm_create_signing_template(s,&to_verify) > 0, "Failed to create signing template");
  CHECK_MEM(to_verify);
  
  char sas_buf[2*SAS_SIZE+1] = {0};
  
  for (i = 0; i < SAS_FETCH_RETRIES; i++) {
    if (keyring_send_sas_request_client(s->key,strlen(s->key),sas_buf,2*SAS_SIZE+1))
      break;
  }
  if (i == SAS_FETCH_RETRIES)
    SENTINEL("Failed to fetch signing key");
  
  bool output;
  CHECK((co_conn = co_connect(csm_config.co_sock,strlen(csm_config.co_sock)+1)),
	"Failed to connect to Commotion socket");
  CHECK_MEM((co_req = co_request_create()));
  CO_APPEND_STR(co_req,"verify");
  CO_APPEND_STR(co_req,sas_buf);
  CO_APPEND_STR(co_req,s->signature);
  CO_APPEND_STR(co_req,to_verify);
  CHECK(co_call(co_conn,&co_resp,"serval-crypto",sizeof("serval-crypto"),co_req)
	&& co_response_get_bool(co_resp,&output,"result",sizeof("result")),
	"Failed to verify signature");
  
  /* Is the signature valid? 1=yes, 0=no */
  if (output == true)
    verdict = 1;
  
error:
  if (co_req)
    co_free(co_req);
  if (co_resp)
    co_free(co_resp);
  if (co_conn)
    co_disconnect(co_conn);
  if (to_verify)
    free(to_verify); // alloc'd using asprint from _csm_create_signing_template()
  return verdict;
}

int
csm_create_signature(csm_service *s)
{
  int ret = 0;
  char *to_sign = NULL;
  co_obj_t *co_conn = NULL, *co_req = NULL, *co_resp = NULL;
  CHECK(_csm_create_signing_template(s,&to_sign) > 0, "Failed to create signing template");
  CHECK_MEM(to_sign);
  
  CHECK((co_conn = co_connect(csm_config.co_sock,strlen(csm_config.co_sock)+1)),
	"Failed to connect to Commotion socket");
  CHECK_MEM((co_req = co_request_create()));
  CO_APPEND_STR(co_req,"sign");
  if (s->key) {
    CO_APPEND_STR(co_req,s->key);
  }
  CO_APPEND_STR(co_req,to_sign);
  
  CHECK(co_call(co_conn,&co_resp,"serval-crypto",sizeof("serval-crypto"),co_req),
	"Failed to sign service announcement");
  
  char *signature = NULL, *key = NULL;
  CHECK(co_response_get_str(co_resp,&signature,"signature",sizeof("signature")),
	"Failed to fetch signature from response");
  CHECK(co_response_get_str(co_resp,&key,"SID",sizeof("SID")),
	"Failed to fetch SID from response");
  CHECK(csm_service_set_str(s, "signature", signature), "Failed to set signature");
  s->signature = co_obj_data_ptr(co_tree_find(s->fields, "signature", sizeof("signature")));
  
  if (!s->key) {
    CHECK(csm_service_set_str(s, "key", key), "Failed to set key");
    co_obj_t *key_obj = co_tree_find(s->fields, "key", sizeof("key"));
    CHECK(key_obj, "Failed to get service key");
    s->key = co_obj_data_ptr(key_obj);
    // set UUID
    char uuid[UUID_LEN + 1] = {0};
    CHECK(get_uuid(key,strlen(key),uuid,UUID_LEN + 1) == UUID_LEN, "Failed to get UUID");
    s->uuid = h_strdup(uuid);
    CHECK_MEM(s->uuid);
    service_attach(s->uuid, s);
  }
  
  ret = 1;
error:
  if (co_req)
    co_free(co_req);
  if (co_resp)
    co_free(co_resp);
  if (co_conn)
    co_disconnect(co_conn);
  if (to_sign)
    free(to_sign); // alloc'd using asprint from _csm_create_signing_template()
  return ret;
}