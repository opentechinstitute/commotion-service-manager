#include <avahi-core/lookup.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/llist.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>

extern "C" {
#include "commotion-service-manager.h"
}
#include "gtest/gtest.h"

class ServiceBrowserTest : public ::testing::Test {
  protected:
    AvahiServer *server;
    AvahiSimplePoll *simple_poll;
    AvahiSServiceTypeBrowser *stb;
    int error;
    AvahiServerConfig config;
    
    ServiceBrowserTest() {
      server = NULL;
      simple_poll = NULL;
      stb = NULL;
      
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
    virtual ~ServiceBrowserTest() {
      avahi_server_config_free(&config);
    }
};

TEST_F(ServiceBrowserTest, CreateAvahiServer) {
  simple_poll = avahi_simple_poll_new();
  ASSERT_TRUE(simple_poll);
  
  server = avahi_server_new(avahi_simple_poll_get(simple_poll), &config, NULL, NULL, &error);
  ASSERT_TRUE(server) << "Failed to create server: " << avahi_strerror(error);
  
  stb = avahi_s_service_type_browser_new(server, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, "mesh.local", AVAHI_LOOKUP_USE_MULTICAST, browse_type_callback, server);
  ASSERT_TRUE(stb) << "Failed to create service browser: " << avahi_strerror(avahi_server_errno(server));
}
