/**
 *       @file  browse.c
 *      @brief  functionality for receiving and processing service announcements
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

#include <stdlib.h>
#include <assert.h>
#include <time.h>

#include <avahi-core/core.h>
#include <avahi-core/lookup.h>
#include <avahi-client/client.h>
#include <avahi-client/lookup.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>
#include <avahi-common/simple-watch.h>

#include <commotion/debug.h>
#include <commotion/obj.h>
#include <commotion/list.h>
#include <commotion/tree.h>

#include "defs.h"
#include "browse.h"
#include "service.h"
#include "service_list.h"
#include "util.h"

extern AvahiSimplePoll *simple_poll;

/* Private */

static co_obj_t *
_csm_field_list_find_string_i(co_obj_t *data, co_obj_t *current, void *context)
{
  if (IS_LIST(current)) return NULL;
  char *val = (char*)context;
  char *field_val = co_obj_data_ptr(current);
  if (strcmp(val, field_val) == 0)
    return current;
  return NULL;
}

static co_obj_t *
_csm_field_list_find_int_i(co_obj_t *data, co_obj_t *current, void *context)
{
  if (IS_LIST(current)) return NULL;
  int32_t *val = (int32_t*)context;
  int32_t *field_val = (int32_t*)co_obj_data_ptr(current);
  if (*val == *field_val)
    return current;
  return NULL;
}

#if 0
static co_obj_t *
_csm_fields_find_by_key(co_obj_t *fields, co_obj_t *key, co_obj_t *val, void *context)
{
  char *field_name = co_obj_data_ptr(key);
  if (strcmp(field_name, (char*)context) == 0)
    return key;
  return NULL;
}
#endif

static int
_csm_extract_from_txt_list(csm_service *s, AvahiStringList *txt, csm_ctx *ctx)
{
  int ret = 0;
  long int_val;
  char *key = NULL, *val = NULL;
  co_obj_t *obj = NULL, *field_list = NULL, *val_obj = NULL, *list = NULL;
  
  // first get version
  AvahiStringList *version_txt = avahi_string_list_find(txt,"version");
  CHECK(version_txt, "No version string available in TXT records");
  CHECK(avahi_string_list_get_pair(version_txt,NULL,&val,NULL) == 0,
	"Failed to extract version from TXT list");
  char *dot = strchr(val, '.');
  CHECK(dot, "Invalid version string; doesn't use semantic versioning");
  *dot = '\0';
  s->version.major = atoi(val);
  s->version.minor = atof(dot + 1);
  val = NULL;
  
  // reject different major version
  CHECK(s->version.major == ctx->schema->version.major, "Service has different major version");
  
  // get schema
  csm_schema_t *schema = csm_find_schema(ctx->schema, s->version.major, s->version.minor);
  if (!schema) schema = ctx->schema; // if we don't have proper schema, use newest
  
  // parse txt fields according to schema
  for (; txt; txt = avahi_string_list_get_next(txt)) {
    CHECK(avahi_string_list_get_pair(txt,&key,&val,NULL) == 0,
	  "Failed to extract string from TXT list");
    DEBUG("Parsing TXT field %s=%s", key, val);
    csm_schema_field_t *field = csm_schema_get_field(schema, key);
    if (field) {
      switch (field->type) {
	case CSM_FIELD_STRING:
	case CSM_FIELD_HEX:
	  if (field->type == CSM_FIELD_HEX && !isHex(val, strlen(val)))
	    SENTINEL("Invalid hex service field");
	  CHECK(csm_service_set_str(s, key, val), "Failed to set service string");
	  break;
	case CSM_FIELD_INT:
	  CHECK(csm_service_set_int(s, key, atol(val)), "Failed to set service integer");
	  break;
	case CSM_FIELD_LIST:
	  field_list = co_tree_find(s->fields, key, strlen(key) + 1);
	  if (!field_list) {
	    field_list = co_list16_create();
	    CHECK_MEM(field_list);
	    CHECK(csm_service_set_list(s, key, field_list), "Failed to insert field list into service");
	  }
	  // check if list already contains value
	  // if not, insert it based on subtype
	  switch (field->subtype) {
	    case CSM_FIELD_STRING:
	    case CSM_FIELD_HEX:
	      if (!co_list_parse(field_list, _csm_field_list_find_string_i, val)) {
		if (field->subtype == CSM_FIELD_HEX && !isHex(val, strlen(val)))
		  SENTINEL("Invalid hex service field");
		val_obj = co_str8_create(val, strlen(val) + 1, 0);
		CHECK_MEM(val_obj);
		CHECK(co_list_append(field_list, val_obj), "Failed to insert list entry into service");
	      }
	      break;
	    case CSM_FIELD_INT:
	      int_val = atol(val);
	      if (!co_list_parse(field_list, _csm_field_list_find_int_i, &int_val)) {
		val_obj = co_int32_create(atol(val), 0);
		CHECK_MEM(val_obj);
		CHECK(co_list_append(field_list, val_obj), "Failed to insert list entry into service");
	      }
	      break;
	    default:
	      SENTINEL("Invalid schema subtype");
	  }
	  field_list = val_obj = NULL;
	  break;
	default:
	  SENTINEL("Invalid schema type");
      }
    } else {
      char *endptr = NULL;
      int_val = strtol(val, &endptr, 10);
      co_obj_t *existing = co_tree_find(s->fields, key, strlen(key) + 1);
      if (existing) {
	// is existing a list? if so, append to it. it not, turn it into a list and append this
	if (!IS_LIST(existing)) {
	  // convert to list
	  list = co_list16_create();
	  CHECK_MEM(list);
	  obj = co_tree_delete(s->fields, key, strlen(key) + 1);
	  CHECK(obj, "Failed to remove object from service fields");
	  CHECK(co_list_append(list, obj), "Failed to append object to service fields list");
	  CHECK(csm_service_set_list(s, key, list), "Failed to append service fields list to service");
	  list = NULL;
	}
	if (!endptr) { // val was a valid long int
	  CHECK(csm_service_append_int_to_list(s, key, int_val), "Failed to set service integer");
	} else { // val treated as string or hex
	  CHECK(csm_service_append_str_to_list(s, key, val), "Failed to set service string");
	}
      } else {
	// insert into s->fields
	if (!endptr) { // val was a valid long int
	  CHECK(csm_service_set_int(s, key, int_val), "Failed to set service integer");
	} else { // val treated as string or hex
	  CHECK(csm_service_set_str(s, key, val), "Failed to set service string");
	}
      }
    }
    key = val = NULL;
  }
  
  obj = co_tree_find(s->fields, "fingerprint", strlen("fingerprint") + 1);
  CHECK(obj, "Service doesn't contain key/fingerprint field");
  s->key = co_obj_data_ptr(obj);
  obj = co_tree_find(s->fields, "signature", strlen("signature") + 1);
  CHECK(obj, "Service doesn't contain signature field");
  s->signature = co_obj_data_ptr(obj);
  obj = co_tree_find(s->fields, "lifetime", strlen("lifetime") + 1);
  CHECK(obj, "Service doesn't contain lifetime field");
  s->lifetime = atol(co_obj_data_ptr(obj));
  
  ret = 1;
error:
  if (val)
    avahi_free(val);
  if (key)
    avahi_free(key);
  if (field_list)
    co_obj_free(field_list);
  if (val_obj)
    co_obj_free(val_obj);
  if (list)
    co_obj_free(list);
  return ret;
}

static int
_csm_find_pending_service(csm_ctx *ctx, const char *uuid)
{
  csm_pending_service *pending = ctx->pending;
  for (; pending; pending = pending->_next) {
    if (strcmp(uuid, pending->name) == 0)
      return 1;
  }
  return 0;
}

static int
_csm_insert_pending_service(csm_ctx *ctx, const char *uuid)
{
  csm_pending_service *new = h_calloc(1, sizeof(csm_pending_service));
  if (!new) {
    ERROR("Failed to allocate pending service %s", uuid);
    return 0;
  }
  strncpy(new->name, uuid, 255);
  new->_next = ctx->pending;
  if (ctx->pending)
    ctx->pending->_prev = new;
  ctx->pending = new;
  return 1;
}

static int
_csm_remove_pending_service(csm_ctx *ctx, const char *uuid)
{
  if (!ctx->pending)
    return 1;
  csm_pending_service *pending = ctx->pending;
  for (; pending; pending = pending->_next) {
    if (strcmp(uuid, pending->name) == 0) {
      if (ctx->pending == pending) {
	ctx->pending = pending->_next;
      } else {
	pending->_prev->_next = pending->_next;
      }
      if (pending->_next)
	pending->_next->_prev = pending->_prev;
      h_free(pending);
      return 1;
    }
  }
  return 0;
}

void resolve_callback(
    RESOLVER *r,
    AVAHI_GCC_UNUSED AvahiIfIndex interface,
    AVAHI_GCC_UNUSED AvahiProtocol protocol,
    AvahiResolverEvent event,
    const char *uuid,
    const char *type,
    const char *domain,
    const char *host_name,
    const AvahiAddress *address,
    uint16_t port,
    AvahiStringList *txt,
    AvahiLookupResultFlags flags,
    void* userdata) {
    
    assert(userdata);
    csm_ctx *ctx = (csm_ctx*)userdata;
//     csm_service *s = ctx->service;
#ifdef CLIENT
    AvahiClient *client = ctx->client;
#else
    AvahiServer *server = ctx->server;
#endif
    assert(r);
    
    if (!txt) {
      INFO("Resolved service does not contain TXT fields");
      RESOLVER_FREE(r);
      return;
    }

    /* create the service.*/
    csm_service *s = csm_service_new(interface, protocol, uuid, type, domain);
    CHECK_MEM(s);
    
    switch (event) {
        case AVAHI_RESOLVER_FAILURE:
            ERROR("Failed to resolve service '%s' of type '%s' in domain '%s': %s", uuid, type, domain, AVAHI_ERROR);
	    _csm_remove_pending_service(ctx, uuid);
            break;

        case AVAHI_RESOLVER_FOUND: {
	    CHECK(_csm_remove_pending_service(ctx, uuid), "Failed to remove pending service");
	  
            avahi_address_snprint(s->r.address, 
                sizeof(s->r.address),
                address);
	    s->r.host_name = h_strdup(host_name);
	    
	    CHECK_MEM(s->r.host_name);
	    service_attach(s->r.host_name, s);

	    CHECK(port >= 0 && port <= 65535, "Invalid port: %s",uuid);
	    s->port = port;

	    s->r.txt_lst = avahi_string_list_copy(txt);
	    CHECK_MEM(s->r.txt_lst);
	    
	    CHECK(_csm_extract_from_txt_list(s,txt,ctx), "Failed to extract TXT fields");
	    
	    CHECK(csm_add_service(ctx->service_list, s, ctx), "Error processing service");
	    
	    break;
        }
	default:
	  _csm_remove_pending_service(ctx, uuid);
    }
error:
//     RESOLVER_FREE(s->r.resolver);
    RESOLVER_FREE(r);
//     s->r.resolver = NULL;
    // if no signature is present, indicates service resolution failed
    if (event == AVAHI_RESOLVER_FOUND && s && !s->signature) {
      csm_remove_service(ctx->service_list, s);
      csm_service_destroy(s);
    }
}

void browse_service_callback(
    BROWSER *b,
    AvahiIfIndex interface,
    AvahiProtocol protocol,
    AvahiBrowserEvent event,
    const char *uuid,
    const char *type,
    const char *domain,
    AVAHI_GCC_UNUSED AvahiLookupResultFlags flags,
    void* userdata) {

    assert(userdata);
    csm_ctx *ctx = (csm_ctx*)userdata;
#ifdef CLIENT
    AvahiClient *client = ctx->client;
#else
    AvahiServer *server = ctx->server;
#endif
    assert(b);

    switch (event) {

        case AVAHI_BROWSER_FAILURE:

            ERROR("Service browser failure: %s", AVAHI_ERROR);
            avahi_simple_poll_quit(simple_poll);
            return;

        case AVAHI_BROWSER_NEW:
        case AVAHI_BROWSER_REMOVE: {
            INFO("Browser: %s: service '%s' of type '%s' in domain '%s'",event == AVAHI_BROWSER_NEW ? "NEW" : "REMOVE", uuid, type, domain);
	    
	    /* Lookup the service to see if it's already in our list */
	    csm_service *found_service = csm_find_service(ctx->service_list, uuid);
            if (event == AVAHI_BROWSER_NEW && !found_service && !_csm_find_pending_service(ctx, uuid)) {
		if (!_csm_insert_pending_service(ctx, uuid)) {
		  ERROR("Failed to isnert pending service");
		  return;
		}
// 		ctx->service = s;
// 		s->r.resolver = RESOLVER_NEW(interface, protocol, uuid, type, domain, AVAHI_PROTO_UNSPEC, 0, resolve_callback, ctx);
		RESOLVER *r = RESOLVER_NEW(interface, protocol, uuid, type, domain, AVAHI_PROTO_UNSPEC, 0, resolve_callback, ctx);
// 		if (!s->r.resolver) {
		if (!r) {
// 		  csm_service_destroy(s);
		  ERROR("Failed to create resolver for service '%s' of type '%s' in domain '%s': %s", uuid, type, domain, AVAHI_ERROR);
		  return;
		}
            }
            if (event == AVAHI_BROWSER_REMOVE) {
                /* remove the service.*/
		if (found_service)
		  csm_remove_service(NULL, found_service);
		_csm_remove_pending_service(ctx, uuid);
            }
            break;
        }
        case AVAHI_BROWSER_CACHE_EXHAUSTED:
            INFO("Service browser cache exhausted");
            break;
	default:
	    break;
    }
}

void browse_type_callback(
    TYPE_BROWSER *b,
    AvahiIfIndex interface,
    AvahiProtocol protocol,
    AvahiBrowserEvent event,
    const char *type,
    const char *domain,
    AVAHI_GCC_UNUSED AvahiLookupResultFlags flags,
    void* userdata) {

    assert(userdata);
    csm_ctx *ctx = (csm_ctx*)userdata;
#ifdef CLIENT
    AvahiClient *client = ctx->client;
#else
    AvahiServer *server = ctx->server;
#endif
    assert(b);

    INFO("Type browser got an event: %d", event);
    switch (event) {
        case AVAHI_BROWSER_FAILURE:
            ERROR("Service type browser failure: %s", AVAHI_ERROR);
            avahi_simple_poll_quit(simple_poll);
            return;
        case AVAHI_BROWSER_NEW:
            if (!BROWSER_NEW(AVAHI_IF_UNSPEC, 
                             AVAHI_PROTO_UNSPEC, 
                             type, 
                             domain, 
                             0,
                             browse_service_callback,
			     ctx)) {
                ERROR("Failed to create a service " 
                      "browser for type (%s) in domain (%s)", 
                      type, 
                      domain);
                avahi_simple_poll_quit(simple_poll);
            } else {
                DEBUG("Successfully created a service " 
                      "browser for type (%s) in domain (%s)", 
                      type, 
                      domain);
            }
            break;
        case AVAHI_BROWSER_CACHE_EXHAUSTED:
            INFO("Service type browser cache exhausted");
            break;
	default:
	    break;
    }
}