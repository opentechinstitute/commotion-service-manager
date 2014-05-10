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
#include "commotion-service-manager.h"

extern struct csm_config csm_config;

// from libcommotion_serval-sas
#define SAS_SIZE 32
extern int keyring_send_sas_request_client(const char *sid_str, 
					   const size_t sid_len,
					   char *sas_buf,
					   const size_t sas_buf_len);

/* Private */

static size_t
_csm_create_signing_template(csm_service *s, char **template)
{
  int ret = 0;
  const char *type_template = "<txt-record>type=%s</txt-record>";
  const char *str_template = "<type>%s</type>\n"
			     "<domain-name>%s</domain-name>\n"
			     "<port>%d</port>\n"
			     "<txt-record>name=%s</txt-record>\n"
			     "<txt-record>ttl=%d</txt-record>\n"
			     "<txt-record>uri=%s</txt-record>\n"
			     "%s\n"
			     "<txt-record>icon=%s</txt-record>\n"
			     "<txt-record>description=%s</txt-record>\n"
			     "<txt-record>lifetime=%ld</txt-record>";

  char **categories = NULL, *type_str = NULL, *app_type = NULL;
  size_t cat_len = csm_service_categories_to_array(s, &categories);
  if (cat_len) {
    /* Concat the types into a single string to add to template */
    int prev_len = 0;
    for (int j = 0; j < cat_len; j++) {
      if (app_type) {
	free(app_type);
	app_type = NULL;
      }
      prev_len = type_str ? strlen(type_str) : 0;
      CHECK_MEM(asprintf(&app_type, type_template, categories[j]) != -1);
      type_str = h_realloc(type_str, prev_len + strlen(app_type) + 1);
      CHECK_MEM(type_str);
      type_str[prev_len] = '\0';
      strcat(type_str, app_type);
    }
  }
  
  /* Add the fields into the template */
  CHECK_MEM(asprintf(template,
		     str_template,
		     s->type,
		     s->domain,
		     s->port,
		     csm_service_get_name(s),
		     csm_service_get_ttl(s),
		     csm_service_get_uri(s),
		     cat_len ? type_str : "",
		     csm_service_get_icon(s),
		     csm_service_get_description(s),
		     csm_service_get_lifetime(s)) != -1);
  
  ret = strlen(*template);
error:
  if (categories)
    h_free(categories);
  if (app_type)
    free(app_type); // alloc'd using asprintf
  if (type_str)
    h_free(type_str);
  return ret;
}

/* Public */

co_obj_t *co_service_create(csm_service *service) {
  co_service_t *output = h_calloc(1,sizeof(co_service_t));
  CHECK_MEM(output);
  output->_header._type = _ext8;
  output->_exttype = _service;
  output->_len = (sizeof(co_service_t));
  output->service = service;
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
  csm_service *s = h_calloc(1, sizeof(csm_service));
  CHECK_MEM(s);
  
  s->interface = interface;
  s->protocol = protocol;
  if (uuid) {
    s->uuid = h_strdup(uuid);
    CHECK_MEM(s->uuid);
    hattach(s->uuid, s);
  }
  s->type = h_strdup(type);
  CHECK_MEM(s->type);
  hattach(s->type, s);
  s->domain = h_strdup(domain);
  CHECK_MEM(s->domain);
  hattach(s->domain, s);
  
  // create tree for holding user-defined service fields
  co_obj_t *fields = co_tree16_create();
  CHECK_MEM(fields);
  
  // set current CSM protocol version
  co_obj_t *version = co_str8_create(CSM_PROTO_VERSION, strlen(CSM_PROTO_VERSION) + 1, 0);
  CHECK_MEM(version);
  CHECK(co_list_append(fields, version), "Failed to append version to service fields");
  
  s->fields = fields;
  hattach(s->fields, s);
  return s;
error:
  return NULL;
}

void
csm_service_destroy(csm_service *s)
{
  assert(s);
  
  if (s->resolver)
    RESOLVER_FREE(s->resolver);
  
  if (s->txt_lst)
    avahi_string_list_free(s->txt_lst);
  
  h_free(s);
}

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

/**
 * Output service fields to a file
 * @param f File to output to
 * @param service the service to print
 */
void
print_service(FILE *f, csm_service *s)
{
  char interface_string[IF_NAMESIZE];
  const char *protocol_string;
  
  if (!if_indextoname(s->interface, interface_string))
    WARN("Could not resolve the interface name!");
  
  if (!(protocol_string = avahi_proto_to_string(s->protocol)))
    WARN("Could not resolve the protocol name!");
  
  char *txt = NULL;
  size_t txt_len = 0;
  char *name = csm_service_get_name(s);
  txt = csm_txt_list_to_string(txt, &txt_len, name, strlen(name));
  CHECK_MEM(txt);
  char *description = csm_service_get_description(s);
  txt = csm_txt_list_to_string(txt, &txt_len, description, strlen(description));
  CHECK_MEM(txt);
  char *uri = csm_service_get_uri(s);
  txt = csm_txt_list_to_string(txt, &txt_len, uri, strlen(uri));
  CHECK_MEM(txt);
  char *icon = csm_service_get_icon(s);
  txt = csm_txt_list_to_string(txt, &txt_len, icon, strlen(icon));
  CHECK_MEM(txt);
  char **categories = NULL;
  int cat_len = csm_service_categories_to_array(s, &categories);
  for (int i = 0; i < cat_len; i++) {
    txt = csm_txt_list_to_string(txt, &txt_len, categories[i], strlen(categories[i]));
  }
  txt_len = asprintf(&txt, "%sttl=%d;lifetime=%ld;", txt, csm_service_get_ttl(s), csm_service_get_lifetime(s));
  CHECK_MEM(txt_len != -1);
  char *key = csm_service_get_key(s);
  txt = csm_txt_list_to_string(txt, &txt_len, key, strlen(key));
  CHECK_MEM(txt);
  char *signature = csm_service_get_signature(s);
  txt = csm_txt_list_to_string(txt, &txt_len, signature, strlen(signature));
  CHECK_MEM(txt);
  
  fprintf(f, "%s;%s;%s;%s;%s;%s;%u;%s\n",
	  interface_string,
	  protocol_string,
	  s->uuid,
	  s->type,
	  s->domain,
	  s->host_name,
	  s->port,
	  txt);
  
error:
  if (categories)
    h_free(categories);
  if (txt)
    free(txt); // alloc'd with realloc from csm_txt_list_to_string()
}

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

int
verify_signature(csm_service *s)
{
  int verdict = 0;
  co_obj_t *co_conn = NULL, *co_req = NULL, *co_resp = NULL;
  char *to_verify = NULL;
  CHECK(_csm_create_signing_template(s,&to_verify) > 0, "Failed to create signing template");
  CHECK_MEM(to_verify);
  
  char sas_buf[2*SAS_SIZE+1] = {0};
  
  char *key = csm_service_get_key(s);
  CHECK(keyring_send_sas_request_client(key,strlen(key),sas_buf,2*SAS_SIZE+1),"Failed to fetch signing key");
  
  bool output;
  CHECK((co_conn = co_connect(csm_config.co_sock,strlen(csm_config.co_sock)+1)),
	"Failed to connect to Commotion socket");
  CHECK_MEM((co_req = co_request_create()));
  CO_APPEND_STR(co_req,"verify");
  CO_APPEND_STR(co_req,sas_buf);
  CO_APPEND_STR(co_req,csm_service_get_signature(s));
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
create_signature(csm_service *s)
{
  char *to_sign = NULL;
  CHECK(_csm_create_signing_template(s,&to_sign) > 0, "Failed to create signing template");
  CHECK_MEM(to_sign);
  
  co_obj_t *co_conn = NULL, *co_req = NULL, *co_resp = NULL;
  CHECK((co_conn = co_connect(csm_config.co_sock,strlen(csm_config.co_sock)+1)),
	"Failed to connect to Commotion socket");
  CHECK_MEM((co_req = co_request_create()));
  CO_APPEND_STR(co_req,"sign");
  char *key = csm_service_get_key(s);
  if (key) {
    CO_APPEND_STR(co_req,key);
  }
  CO_APPEND_STR(co_req,to_sign);
  
  CHECK(co_call(co_conn,&co_resp,"serval-crypto",sizeof("serval-crypto"),co_req),
	"Failed to sign service announcement");
  
  char *signature = NULL, *sid = NULL;
  CHECK(co_response_get_str(co_resp,&signature,"signature",sizeof("signature")),
	"Failed to fetch signature from response");
  CHECK(co_response_get_str(co_resp,&sid,"sid",sizeof("sid")),
	"Failed to fetch SID from response");
  CHECK(csm_service_set_signature(s, signature), "Failed to set signature");
  if (!key) {
    csm_service_set_key(s, sid);
    // set UUID
    char uuid[UUID_LEN + 1] = {0};
    CHECK(get_uuid(sid,strlen(sid),uuid,UUID_LEN + 1) == UUID_LEN, "Failed to get UUID");
    s->uuid = h_strdup(uuid);
    CHECK_MEM(s->uuid);
    hattach(s->uuid, s);
  }
  
  return 1;
error:
  if (co_req)
    co_free(co_req);
  if (co_resp)
    co_free(co_resp);
  if (co_conn)
    co_disconnect(co_conn);
  if (to_sign)
    free(to_sign); // alloc'd using asprint from _csm_create_signing_template()
  return 0;
}