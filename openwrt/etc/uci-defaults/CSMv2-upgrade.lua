#!/usr/bin/lua

require "luci.model.uci"
require "luci.fs"
require "luci.sys"
require "csm"

local uci = luci.model.uci.cursor()

csm.init()
uci:foreach(
  "applications",
  "application",
  function(app)
    if app.localapp == "1" then
      print("local app: " .. app.name)
      local s = csm.new_service()
      s.version = "2.0"
      s.name = app.name
      s.description = app.description
      s.ttl = tonumber(app.ttl)
      s.lifetime = tonumber(app.lifetime)
      s.uri = app.uri
      s.icon = app.icon
      s.tag = app.type
      s:commit()
      s:free()
      if not uci:delete("applications", app[".name"]) then
	print("Failed to delete app")
      end
    else
      if app.fingerprint then
	uci:set("applications",app[".name"],"key",app.fingerprint)
	uci:delete("applications",app[".name"],"fingerprint")
      end
      if app.type then
	uci:set_list("applications",app[".name"],"tag",app.type)
	uci:delete("applications",app[".name"],"type")
      end
      if app.localapp then
	uci:set("applications",app[".name"],"local",app.local)
	uci:delete("applications",app[".name"],"localapp")
      end
    end
  end
)
uci:save("applications")
uci:commit("applications")
csm.shutdown()

luci.sys.exec("/etc/init.d/commotion-service-manager restart")

for _,f in pairs(luci.fs.dir("/etc/avahi/services")) do
  if f and f ~= "." and f ~= ".." then
    luci.fs.unlink("/etc/avahi/services/"..f)
  end
end
luci.fs.rmdir("/etc/avahi/services")

luci.sys.exec("sed -i -e \'/\\\/etc\\\/avahi\\\/services\\\//d\' /etc/sysupgrade.conf")

uci:foreach(
  "olsrd",
  "LoadPlugin",
  function(plugin)
    if plugin.library == "olsrd_dnssd.so.0.1.2" then
      uci:set("olsrd",plugin[".name"],"library","olsrd_dnssd.so.0.1.3")
      uci:delete("olsrd",plugin[".name"],"ServiceFileDir")
      uci:set("olsrd",plugin[".name"],"CSMSocket","/var/run/commotion-service-manager.sock")
    elseif plugin.library == "olsrd_dnssd.so.0.1.3" then
      uci:delete("olsrd",plugin[".name"])
    end
  end
)
uci:save("olsrd")
uci:commit("olsrd")

luci.sys.exec("/etc/init.d/olsrd restart")