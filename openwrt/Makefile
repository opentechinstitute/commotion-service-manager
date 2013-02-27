#
# Copyright (C) 2010-2012 Jo-Philipp Wich <xm@subsignal.org>
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=avahi-client
PKG_RELEASE:=1
PKG_VERSION=1.0

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=git://github.com/opentechinstitute/avahi-client.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=$(PKG_VERSION)

PKG_SOURCE:=$(PKG_NAME)-$(PKG_SOURCE_VERSION).tar.gz
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/avahi-client/default
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=IP Addresses and Names
  TITLE:=Avahi mDNS Browser
  MAINTAINER:=Open Technology Institute
  DEPENDS:=+libavahi
endef

define Package/avahi-client
  $(Package/avahi-client/default)
  MENU:=1
endef

define Package/avahi-client/description
  This is a daemon that browses the mesh.local domain
  for services. It outputs a ;-delimited list of 
  characteristics for each service when it receives
  SIGUSR1. 
endef

TARGET_CFLAGS += $(TLS_CFLAGS)
TARGET_LDFLAGS += -Wl,-rpath-link=$(STAGING_DIR)/usr/lib -lavahi-core -lavahi-common

define Package/avahi-client/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/avahi-client $(1)/usr/sbin/avahi-client
endef

$(eval $(call BuildPackage,avahi-client))
