include $(TOPDIR)/rules.mk

PKG_NAME:=commotion-service-manager
PKG_RELEASE:=1
PKG_VERSION=master

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=git://github.com/opentechinstitute/commotion-service-manager.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=$(PKG_VERSION)

PKG_SOURCE:=$(PKG_NAME)-$(PKG_SOURCE_VERSION).tar.gz
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION:=commotion
  CATEGORY:=Commotion
  SUBMENU:=Utilities
  TITLE:=Commotion Service Manager
  MAINTAINER:=Open Technology Institute
  DEPENDS:=+libavahi +libuci +serval-dna +libserval-crypto
endef

define Package/$(PKG_NAME)/description
  This is a daemon that browses the mesh.local domain
  for services. It outputs a ;-delimited list of 
  characteristics for each service when it receives
  SIGUSR1, and optionally writes them to UCI.
endef

TARGET_CFLAGS += $(TLS_CFLAGS) -I/usr/include/serval -DUSE_UCI -DOPENWRT -g
TARGET_LDFLAGS += -Wl,-rpath-link=$(STAGING_DIR)/usr/lib -lavahi-core -lavahi-common -lserval-crypto -luci

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/commotion-service-manager $(1)/usr/sbin/commotion-service-manager
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
