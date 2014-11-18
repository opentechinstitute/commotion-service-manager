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
include $(INCLUDE_DIR)/cmake.mk

CMAKE_OPTIONS+=-DDEBUG:Bool=Off -DOPENWRT:Bool=On

define Package/$(PKG_NAME)
  SECTION:=commotion
  CATEGORY:=Commotion
  SUBMENU:=Utilities
  TITLE:=Commotion Service Manager
  MAINTAINER:=Open Technology Institute
  DEPENDS:=+libavahi +libuci +commotiond +libcommotion +commotion-plugins +commotion-mdp-client +libm +argp-standalone +liblua
  URL:=https://commotionwireless.net/
endef

define Package/$(PKG_NAME)/description
  This is a daemon that publishes and browses for
  local services on the mesh.local domain.
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/src/commotion-service-manager.h $(1)/usr/include
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/libcommotion-service-manager.so $(1)/usr/lib
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/commotion-service-manager $(1)/usr/sbin/commotion-service-manager
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/libcommotion-service-manager.so $(1)/usr/lib
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/lua/libcsm_lua.so $(1)/usr/lib
	$(INSTALL_DIR) $(1)/usr/lib/lua
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/lua/csm.lua $(1)/usr/lib/lua
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/openwrt/etc/init.d/commotion-service-manager $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/commotion/csm/schemas.d
	$(CP) $(PKG_BUILD_DIR)/files/schemas.d/* $(1)/etc/commotion/csm/schemas.d
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/openwrt/etc/uci-defaults/CSMv2-upgrade.lua $(1)/etc/uci-defaults
endef

define Package/$(PKG_NAME)/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	( . /etc/uci-defaults/CSMv2-upgrade.lua ) && rm -f /etc/uci-defaults/CSMv2-upgrade.lua
}
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
