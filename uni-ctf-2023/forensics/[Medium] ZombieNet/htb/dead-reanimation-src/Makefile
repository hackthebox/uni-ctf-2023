#
# This software is licensed under the Public Domain.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=dead-reanimation
PKG_VERSION:=1.0.0
PKG_RELEASE:=1
PKG_BUILD_DEPENDS:=curl

PKG_MAINTAINER:=canopus

include $(INCLUDE_DIR)/package.mk

define Package/dead-reanimation
	SECTION:=utils
	# Select package by default
	#DEFAULT:=y
	CATEGORY:=Utilities
	DEPENDS:=+curl
	TITLE:=Makes sure everything runs properly
endef

define Package/dead-reanimation/description
	A small application to make sure everything is alright	
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/compile
	$(MAKE) -C $(PKG_BUILD_DIR)
endef

define Package/dead-reanimation/install
	$(CP) ./files/* $(1)/
	$(INSTALL_DIR) $(1)/etc/rc.d
	ln -sf $(1)/etc/init.d/dead-reanimation $(1)/etc/rc.d/S95dead-reanimation

	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/zombie_runner $(1)/sbin/
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dead-reanimation $(1)/usr/bin/
endef

$(eval $(call BuildPackage,dead-reanimation, +curl))
