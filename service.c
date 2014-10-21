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
#include "commotion-service-manager.h"

extern struct csm_config csm_config;

// from libcommotion_serval-sas
#define SAS_SIZE 32
extern int keyring_send_sas_request_client(const char *sid_str, 
					   const size_t sid_len,
					   char *sas_buf,
					   const size_t sas_buf_len);

/* Private */

struct _csm_fields_array {
  ssize_t num_fields;
  ssize_t current_field;
  char **fields;
};

static void
_csm_sort_service_fields_i(co_obj_t *data, co_obj_t *key, co_obj_t *field, void *context)
{
  struct _csm_fields_array *fields = (struct _csm_fields_array*)context;
  /* max length of TXT record is 256 char, so the max length of our
     template string is 256 + sizeof('<txt-record></txt-record>\0') = 282 */
  fields->fields[fields->current_field] = h_calloc(282, sizeof(char));
  if (IS_STR(field)) {
    snprintf(fields->fields[fields->current_field], 
	     282, 
	     "<txt-record>%s=%s</txt-record>",
	     co_obj_data_ptr(key),
	     co_obj_data_ptr(field));
  } else if (IS_INT(field)) {
    snprintf(fields->fields[fields->current_field], 
	     282, 
	     "<txt-record>%s=%ld</txt-record>",
	     co_obj_data_ptr(key),
	     (long)*co_obj_data_ptr(field));
  } else if (IS_LIST(field)) {
    csm_list_parse(field, key, _csm_sort_service_fields_i, context);
    return;
  } else {
    ERROR("Invalid service field");
    h_free(fields->fields[fields->current_field]);
    return;
  }
  hattach(fields->fields[fields->current_field], fields->fields);
  fields->current_field++;
}

static size_t
_csm_create_signing_template(csm_service *s, char **template)
{
  int ret = 0;
  char *txt_fields = NULL;
  size_t txt_len = 0;
  
  /* Sort fields into alphabetical order */
  ssize_t num_fields = co_tree_length(s->fields);
  struct _csm_fields_array fields = {
    .num_fields = num_fields,
    .current_field = 0,
    .fields = h_calloc(num_fields, sizeof(char*))
  };
  CHECK_MEM(fields.fields);
  CHECK(csm_tree_process(s->fields, _csm_sort_service_fields_i, &fields), 
	"Failed to sort service fields");
  assert(fields.num_fields == fields.current_field);
  
  // Alphabetically sort the array of template strings we've built
  // TODO this might be redundant due to how co_trees are arranged
//   qsort(fields.fields,num_fields,sizeof(char*),cmpstringp);
  
  // build the full txt field template
  for (int i = 0; i < num_fields; i++) {
    txt_fields = h_realloc(txt_fields, (txt_len + strlen(fields.fields[i]) + 1 + 1) * sizeof(char));
    memset(&txt_fields[txt_len],'\0',strlen(fields.fields[i]) + 1 + 1);
    strcat(txt_fields, fields.fields[i]);
    strcat(txt_fields, "\n");
    txt_len += strlen(fields.fields[i]) + 1;
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
  if (fields.fields)
    h_free(fields.fields);
  if (txt_fields)
    h_free(txt_fields);
  return ret;
}

// this is redundant by co_tree_find
#if 0
inline co_obj_t *
csm_tree_find_r(co_obj_t *tree, _treenode_t *current, const _csm_iter_t iter, void *context)
{
  co_obj_t *ret = NULL;
  CHECK(IS_TREE(tree), "Recursion target is not a tree.");
  if(current != NULL)
  {
    if(current->value != NULL) {
      ret = iter(tree, current->key, current->value, context);
      if (ret) return ret;
    }
    ret = csm_tree_process_r(tree, current->low, iter, context);
    if (ret) return ret;
    ret = csm_tree_process_r(tree, current->equal, iter, context);
    if (ret) return ret;
    ret = csm_tree_process_r(tree, current->high, iter, context);
  }
  return ret;
error:
  return NULL;
}
#endif

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
//   csm_service *s = h_calloc(1, sizeof(csm_service));
  
  CHECK_MEM(s_obj);
  csm_service *s = &(s_obj->service);
  
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
  
#if 0
  // set current CSM protocol version
  co_obj_t *version = co_str8_create(CSM_PROTO_VERSION, strlen(CSM_PROTO_VERSION) + 1, 0);
  CHECK_MEM(version);
  CHECK(co_tree_insert(fields, "version", sizeof("version"), version), "Failed to insert version into service fields");
#endif
  
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
  
//   if (s->r.resolver)
//     RESOLVER_FREE(s->r.resolver);
  
  if (s->r.txt_lst)
    avahi_string_list_free(s->r.txt_lst);
  
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

#if 0
/**
 * most getters and setters are wrappers around calls to 
 * functions in commotion-service-manager.h/c
 */
#define SERVICE_GET(M,T) \
inline T \
csm_service_get_##M(csm_service *s) \
{ \
  return service_get_##M(s->fields); \
}
SERVICE_GET(name,char *);
SERVICE_GET(description,char *);
SERVICE_GET(uri,char *);
SERVICE_GET(icon,char *);
SERVICE_GET(ttl,int);
SERVICE_GET(lifetime,long);
SERVICE_GET(key,char *);
SERVICE_GET(signature,char *);
#undef SERVICE_GET

co_obj_t *
csm_service_get_categories(csm_service *s)
{
  assert(IS_TREE(s->fields));
  return co_tree_find(s->fields, "categories", sizeof("categories"));
}

char *
csm_service_get_version(csm_service *s)
{
  assert(IS_TREE(s->fields));
  co_obj_t *version = co_tree_find(s->fields,"version",sizeof("version"));
  CHECK(version,"Service does not have version");
  return ((co_str8_t*)version)->data;
error:
  return NULL;
}

#define SERVICE_SET(M,T) \
inline int \
csm_service_set_##M(csm_service *s, T m) \
{ \
  return service_set_##M(s, m); \
}
SERVICE_SET(name, const char *);
SERVICE_SET(description, const char *);
SERVICE_SET(uri, const char *);
SERVICE_SET(icon, const char *);
SERVICE_SET(ttl, int);
SERVICE_SET(lifetime, long);
#undef SERVICE_SET

int
csm_service_set_categories(csm_service *s, co_obj_t *categories)
{
  assert(IS_TREE(s->fields));
  if (categories) {
    assert(IS_LIST(categories));
    CHECK(co_tree_insert_force(s->fields,
			      "categories",
			      sizeof("categories"),
			      categories),
	  "Failed to insert categories into service");
  } else {
    co_obj_t *cat_obj = co_tree_delete(s->fields, "categories", sizeof("categories"));
    if (cat_obj)
      co_obj_free(cat_obj);
  }
  return 1;
error:
  return 0;
}

int
csm_service_set_key(csm_service *s, const char *key)
{
  assert(IS_TREE(s->fields));
  if (key) {
    co_obj_t *key_obj = co_str8_create(key, strlen(key) + 1, 0);
    CHECK_MEM(key_obj);
    CHECK(co_tree_insert_force(s->fields,
			      "key",
			      sizeof("key"),
			      key_obj),
	  "Failed to insert key into service");
  } else {
    co_obj_t *key_obj = co_tree_delete(s->fields, "key", sizeof("key"));
    if (key_obj)
      co_obj_free(key_obj);
  }
  
  return 1;
error:
  return 0;
}

int
csm_service_set_signature(csm_service *s, const char *signature)
{
  assert(IS_TREE(s->fields));
  if (signature) {
    co_obj_t *sig_obj = co_str8_create(signature, strlen(signature) + 1, 0);
    CHECK_MEM(sig_obj);
    CHECK(co_tree_insert_force(s->fields,
			       "signature",
			       sizeof("signature"),
			       sig_obj),
	  "Failed to insert signature into service");
  } else {
    co_obj_t *sig_obj = co_tree_delete(s->fields, "signature", sizeof("signature"));
    if (sig_obj)
      co_obj_free(sig_obj);
  }
  return 1;
error:
  return 0;
}

int
csm_service_set_version(csm_service *s, const char *version)
{
  assert(IS_TREE(s->fields));
  co_obj_t *version_obj = co_str8_create(version, strlen(version) + 1, 0);
  CHECK_MEM(version_obj);
  CHECK(co_tree_insert_force(s->fields,
			     "version",
			     sizeof("version"),
			     version_obj),
	"Failed to insert version into service");
  return 1;
error:
  return 0;
}
#endif

#if 0
/**
 * caller is responsible for freeing category array
 */
size_t
csm_service_categories_to_array(csm_service *s, char ***cat_array)
{
  size_t cat_len = 0;
  co_obj_t *cats_obj = csm_service_get_categories(s);
  if (cats_obj) {
    cat_len = co_list_length(cats_obj);
    *cat_array = h_calloc(cat_len, sizeof(char*));
    CHECK_MEM(cat_array);
    for (int i = 0; i < cat_len; i++) {
      co_obj_data(&(*cat_array[i]), co_list_element(cats_obj, i));
    }
    /* Sort types into alphabetical order */
    qsort(*cat_array,cat_len,sizeof(char*),cmpstringp);
  }
  return cat_len;
error:
  return 0;
}
#endif

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
  CHECK(_csm_create_signing_template(s,&to_sign) > 0, "Failed to create signing template");
  CHECK_MEM(to_sign);
  
  co_obj_t *co_conn = NULL, *co_req = NULL, *co_resp = NULL;
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
    CHECK(csm_service_set_str(s, "fingerprint", key), "Failed to set key");
    s->key = co_obj_data_ptr(co_tree_find(s->fields, "fingerprint", sizeof("key")));
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