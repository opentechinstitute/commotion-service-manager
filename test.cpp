/**
 *       @file  test.cpp
 *      @brief  unit tests for the Commotion Service Manager
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

#include <stdio.h>
// #include <list>
#include <arpa/inet.h>
#include <avahi-core/lookup.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/llist.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>
extern "C" {
#include <serval-crypto.h>
#include "commotion-service-manager.h"
#include "util.h"
}
#include "gtest/gtest.h"

#define SIG_LENGTH 128

class CSMTest : public ::testing::Test {
  protected:
    AvahiSServiceTypeBrowser *stb;
    AvahiSServiceBrowser *sb;
    int error;
    AvahiServerConfig config;
    ServiceInfo *service;
    AvahiStringList *txt_lst;
    const char *sid;
    
    const char *type;
    const char *domain;
    const char *name;
    const char *host_name;
    int port;
    int ttl;
    const char *uri;
    const char *icon;
    const char *description;
    long lifetime;
    const char *type1;
    const char *type2;
    char signature[SIG_LENGTH + 1];
    AvahiAddress *addr;
    
    void CreateAvahiServer();
    void CreateServiceBrowser();
    void CreateService();
    void GenerateSignature();
    void CreateTxtList();
    void ResolveCallbackTestSetup();
    
    CSMTest() {
      server = NULL;
      simple_poll = NULL;
      stb = NULL;
      sb = NULL;
      service = NULL;
      txt_lst = NULL;
      sid = SID;
      assert(strlen(sid) == FINGERPRINT_LEN && isHex(sid,strlen(sid)));
      printf("SID: %s\n",sid);

      type = "_commotion._tcp";
      domain = "mesh.local";
      name = "service name";
      host_name = "hostname";
      port = 80;
      ttl = 5;
      uri = "https://commotionwireless.net";
      icon = "http://a.b/c.d";
      description = "test description";
      lifetime = 86400;
      type1 = "Community";
      type2 = "Collaboration";
      
      addr = (AvahiAddress*)malloc(sizeof(AvahiAddress));
      avahi_address_parse("127.0.0.1",AVAHI_PROTO_INET,addr);
      
      srand(time(NULL));
      
      avahi_server_config_init(&config);
      config.publish_hinfo = 0;
      config.publish_addresses = 0;
      config.publish_workstation = 0;
      config.publish_domain = 0;
      
      avahi_address_parse("192.168.50.1", AVAHI_PROTO_UNSPEC, &config.wide_area_servers[0]);
      config.n_wide_area_servers = 1;
      config.enable_wide_area = 1;
    }
    virtual ~CSMTest() {
      free(addr);
      if (txt_lst)
	avahi_string_list_free(txt_lst);
      if (service)
	remove_service(NULL, service);
      avahi_server_config_free(&config);
      if (stb)
	avahi_s_service_type_browser_free(stb);
      if (sb)
	avahi_s_service_browser_free(sb);
      if (server)
	avahi_server_free(server);
      if (simple_poll)
	avahi_simple_poll_free(simple_poll);
    }
};

void CSMTest::GenerateSignature() {
  char *sign_block = NULL;
  const char *app_types[2] = {type1, type2};
  int sign_block_len = 0;
  
  sign_block = createSigningTemplate(
    type,
    domain,
    port,
    name,
    ttl,
    uri,
    app_types,
    2,
    icon,
    description,
    lifetime,
    &sign_block_len);
  
  ASSERT_FALSE(serval_sign(sid, strlen(sid), (unsigned char*)sign_block, sign_block_len, signature, SIG_LENGTH + 1,NULL,0));
  
  ASSERT_FALSE(serval_verify(sid,strlen(sid),(unsigned char*)sign_block,sign_block_len,signature,strlen(signature),NULL,0));
  
  if (sign_block)
    free(sign_block);
}

void CSMTest::CreateService() {
  CreateAvahiServer();
  service = add_service(AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, name, type, domain);
  ASSERT_TRUE(service);
  service->port = port;
}

void CSMTest::CreateTxtList() {
  char app_str[256];
  char ttl_str[256];
  char uri_str[256];
  char type1_str[256];
  char type2_str[256];
  char icon_str[256];
  char desc_str[256];
  char exp_str[256];
  char fing_str[256];
  char sig_str[256];

  GenerateSignature();
  
  ASSERT_TRUE(sprintf(app_str,"name=%s",name));
  ASSERT_TRUE(sprintf(ttl_str,"ttl=%d",ttl));
  ASSERT_TRUE(sprintf(uri_str,"uri=%s",uri));
  ASSERT_TRUE(sprintf(type1_str,"type=%s",type1));
  ASSERT_TRUE(sprintf(type2_str,"type=%s",type2));
  ASSERT_TRUE(sprintf(icon_str,"icon=%s",icon));
  ASSERT_TRUE(sprintf(desc_str,"description=%s",description));
  ASSERT_TRUE(sprintf(exp_str,"lifetime=%ld",lifetime));
  ASSERT_TRUE(sprintf(fing_str,"fingerprint=%s",sid));
  ASSERT_TRUE(sprintf(sig_str,"signature=%s",signature));
  
  txt_lst = avahi_string_list_new(
    app_str,
    ttl_str,
    uri_str,
    type1_str,
    type2_str,
    icon_str,
    desc_str,
    exp_str,
    fing_str,
    sig_str,
    NULL
  );
  ASSERT_TRUE(txt_lst);
}

TEST_F(CSMTest, TxtListToStringTest) {
  char *txt = NULL;
  const char expect_tmpl[] = "\"signature=%s\",\"fingerprint=%s\",\"lifetime=86400\",\"description=test description\",\"icon=http://a.b/c.d\",\"type=Collaboration\",\"type=Community\",\"uri=https://commotionwireless.net\",\"ttl=5\",\"name=service name\"";
  char *expect = (char*)calloc(strlen(expect_tmpl) - 4 + 128 + 64 + 1,sizeof(char));
    
  CreateTxtList();
  
  sprintf(expect,expect_tmpl,signature,sid);
  
  txt = txt_list_to_string(txt_lst);
//   printf("%s\n",txt);
  EXPECT_STREQ(expect,txt);
  free(txt);
  free(expect);
}

void CSMTest::CreateAvahiServer() {
  simple_poll = avahi_simple_poll_new();
  ASSERT_TRUE(simple_poll);
  
  server = avahi_server_new(avahi_simple_poll_get(simple_poll), &config, NULL, NULL, &error);
  ASSERT_TRUE(server) << "Failed to create server: " << avahi_strerror(error);
  
  stb = avahi_s_service_type_browser_new(server, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, domain, AVAHI_LOOKUP_USE_MULTICAST, browse_type_callback, server);
  ASSERT_TRUE(stb) << "Failed to create service browser: " << avahi_strerror(avahi_server_errno(server));
}
TEST_F(CSMTest, CreateAvahiServerTest) {
  CreateAvahiServer();
}

TEST_F(CSMTest, BrowseTypeCallbackTest1) {
  CreateAvahiServer();
  
  browse_type_callback(stb, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, AVAHI_BROWSER_NEW, type, domain, AVAHI_LOOKUP_RESULT_MULTICAST, server);
  ASSERT_EQ(0,avahi_simple_poll_iterate(simple_poll,0));
}

TEST_F(CSMTest, BrowseTypeCallbackTest2) {
  CreateAvahiServer();
  
  browse_type_callback(stb, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, AVAHI_BROWSER_FAILURE, type, domain, AVAHI_LOOKUP_RESULT_MULTICAST, server);
  ASSERT_EQ(1,avahi_simple_poll_iterate(simple_poll,0));
}

TEST_F(CSMTest, AddFindRemoveServiceTest) {
  ASSERT_FALSE(service);
  ASSERT_FALSE(services);

  CreateService();

  ASSERT_TRUE(service);
  ASSERT_TRUE(services);

  ASSERT_EQ(service,find_service(name));

  remove_service(NULL, service);
  service = NULL;

  ASSERT_FALSE(service);
  ASSERT_FALSE(services);

  ASSERT_FALSE(find_service(name));
}

void CSMTest::CreateServiceBrowser() {
  CreateAvahiServer();
  sb = avahi_s_service_browser_new(server, 
			      AVAHI_IF_UNSPEC, 
			      AVAHI_PROTO_UNSPEC, 
			      type, 
			      domain, 
			      AVAHI_LOOKUP_USE_MULTICAST, 
			      browse_service_callback, 
			      server);
  ASSERT_TRUE(sb);
}
TEST_F(CSMTest, CreateCSMTest) {
  CreateServiceBrowser();
}

TEST_F(CSMTest, BrowseServiceCallback1) {
  CreateServiceBrowser();
  
  browse_service_callback(sb, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, AVAHI_BROWSER_FAILURE, name, type, domain, AVAHI_LOOKUP_RESULT_MULTICAST, server);
  ASSERT_EQ(1,avahi_simple_poll_iterate(simple_poll,0));
}

TEST_F(CSMTest, BrowseServiceCallback2) {
  CreateServiceBrowser();
  
  ASSERT_FALSE(find_service(name));
  
  browse_service_callback(sb, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, AVAHI_BROWSER_REMOVE, name, type, domain, AVAHI_LOOKUP_RESULT_MULTICAST, server);
  ASSERT_FALSE(find_service(name));
  
  browse_service_callback(sb, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, AVAHI_BROWSER_NEW, name, type, domain, AVAHI_LOOKUP_RESULT_MULTICAST, server);
  ASSERT_STREQ(name,find_service(name)->name);
  
  browse_service_callback(sb, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, AVAHI_BROWSER_REMOVE, name, type, domain, AVAHI_LOOKUP_RESULT_MULTICAST, server);
  ASSERT_FALSE(find_service(name));
}

TEST_F(CSMTest, GenerateSignatureTest) {
  GenerateSignature();
}

TEST_F(CSMTest, CreateServiceInfoTest) {
  CreateService();
}

TEST_F(CSMTest, VerifyAnnouncementTest) {
  CreateService();
  CreateTxtList();
  ASSERT_TRUE(txt_lst);
  
  service->txt_lst = avahi_string_list_copy(txt_lst);
  service->resolved = true;
  
  ASSERT_EQ(0,verify_announcement(service));
}

TEST(UtilTest, TtlTest) {
  EXPECT_TRUE(isValidTtl("0"));
  EXPECT_TRUE(isValidTtl("5"));
  EXPECT_FALSE(isValidTtl("-1"));
  EXPECT_FALSE(isValidTtl("a"));
}

TEST(UtilTest, ExpirationTest) {
  EXPECT_TRUE(isValidLifetime("86400"));
  EXPECT_FALSE(isValidLifetime("0"));
  EXPECT_FALSE(isValidLifetime("-1"));
  EXPECT_FALSE(isValidLifetime("a"));
}

TEST(UtilTest, FingerprintTest) {
  EXPECT_TRUE(isValidFingerprint("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",64));
  EXPECT_FALSE(isValidFingerprint("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",63)); // len = 63
  EXPECT_FALSE(isValidFingerprint("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",65)); // len = 65
  EXPECT_FALSE(isValidFingerprint("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDE",64)); // strlen = 63
  EXPECT_FALSE(isValidFingerprint("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0",64)); // strlen = 65
  EXPECT_FALSE(isValidFingerprint("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEG",64)); // non-hex
}

TEST(UtilTest, SignatureTest) {
  EXPECT_TRUE(isValidSignature("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",128));
  EXPECT_FALSE(isValidSignature("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",127)); // len = 127
  EXPECT_FALSE(isValidSignature("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",129)); // len = 129
  EXPECT_FALSE(isValidSignature("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDE",128)); // strlen = 127
  EXPECT_FALSE(isValidSignature("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0",128)); // strlen = 129
  EXPECT_FALSE(isValidSignature("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEG",128)); // non-hex
}

void CSMTest::ResolveCallbackTestSetup() {
  CreateService();
  CreateTxtList();
  
  ASSERT_TRUE(txt_lst);
  ASSERT_TRUE(service->resolver);
  ASSERT_EQ(service,find_service(name));
  ASSERT_EQ(0,service->resolved);
}

TEST_F(CSMTest, ResolveCallbackTest) {
  ResolveCallbackTestSetup();
  
  resolve_callback(
    service->resolver,
    AVAHI_IF_UNSPEC,
    AVAHI_PROTO_UNSPEC,
    AVAHI_RESOLVER_FOUND,
    name,
    type,
    domain,
    host_name,
    addr,
    port,
    txt_lst,
    AVAHI_LOOKUP_RESULT_MULTICAST,
    service);
  
  EXPECT_FALSE(service->resolver);
  EXPECT_EQ(1,service->resolved);
}

TEST_F(CSMTest, ResolveCallbackTest2) {
  ResolveCallbackTestSetup();
    
  resolve_callback(
    service->resolver,
    AVAHI_IF_UNSPEC,
    AVAHI_PROTO_UNSPEC,
    AVAHI_RESOLVER_FAILURE,
    name,
    type,
    domain,
    host_name,
    addr,
    port,
    txt_lst,
    AVAHI_LOOKUP_RESULT_MULTICAST,
    service);
  
  EXPECT_TRUE(service);
  EXPECT_TRUE(services);
  EXPECT_TRUE(find_service(name));
  EXPECT_EQ(0,service->resolved);
}

TEST_F(CSMTest, ResolveCallbackTest3) {
  ResolveCallbackTestSetup();
  
  resolve_callback(
    service->resolver,
    AVAHI_IF_UNSPEC,
    AVAHI_PROTO_UNSPEC,
    AVAHI_RESOLVER_FOUND,
    name,
    type,
    domain,
    host_name,
    addr,
    -1,
    txt_lst,
    AVAHI_LOOKUP_RESULT_MULTICAST,
    service);
  
  EXPECT_FALSE(services);
  EXPECT_FALSE(find_service(name));
  EXPECT_EQ(0,service->resolved);
  
  service = NULL; // was freed by resolve_callback
}

TEST_F(CSMTest, ResolveCallbackTest4) {
  ResolveCallbackTestSetup();
  
  resolve_callback(
    service->resolver,
    AVAHI_IF_UNSPEC,
    AVAHI_PROTO_UNSPEC,
    AVAHI_RESOLVER_FOUND,
    name,
    type,
    domain,
    host_name,
    addr,
    65536,
    txt_lst,
    AVAHI_LOOKUP_RESULT_MULTICAST,
    service);
  
  EXPECT_FALSE(services);
  EXPECT_FALSE(find_service(name));
  EXPECT_EQ(0,service->resolved);
  
  service = NULL; // was freed by resolve_callback
}

TEST_F(CSMTest, ResolveCallbackTest5) {
  char badsig[] = "signature=0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
  AvahiStringList *oldtxt = NULL;
  
  ResolveCallbackTestSetup();

  oldtxt = avahi_string_list_find(txt_lst,"signature");
  ASSERT_TRUE(oldtxt);
  
  txt_lst = avahi_string_list_add(oldtxt,badsig);
  ASSERT_TRUE(txt_lst);
  
  txt_lst->next = oldtxt->next;
  oldtxt->next = NULL;
  avahi_string_list_free(oldtxt);
  oldtxt = NULL;
  
  resolve_callback(
    service->resolver,
    AVAHI_IF_UNSPEC,
    AVAHI_PROTO_UNSPEC,
    AVAHI_RESOLVER_FOUND,
    name,
    type,
    domain,
    host_name,
    addr,
    port,
    txt_lst,
    AVAHI_LOOKUP_RESULT_MULTICAST,
    service);
  
  EXPECT_FALSE(services);
  EXPECT_FALSE(find_service(name));
  EXPECT_EQ(0,service->resolved);
  
  service = NULL; // was freed by resolve_callback
}