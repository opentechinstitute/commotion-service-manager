--[[
/**
 *       @file  test.lua
 *      @brief  Lua test script for Commotion Service Manager
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
]]--

local inspect = require('inspect')
require("csm")

hex_chars = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"}

function print_services(services, key)
  for s in pairs(services) do
    if not key or key == s.key.value then
      print("Service: "..tostring(s.key))
      print("\tNumber of fields: "..#s)
      print("\tlocal: " .. tostring(s.islocal))
      for f in pairs(s) do
	print("\tfield name: "..f.name..", field_type: "..f.field_type..", length: "..#f)
	if f.field_type == 2 then -- list
	  print("\t\tsubtype: "..f.subtype)
	  for _,val in pairs(f.value) do
	    print("\t\t"..val)
	  end
	else
	  print("\t\t"..f.value)
	end
      end
    end
  end
end

csm.init()
if arg[1] then
  csm.config_set_mgmt_sock(arg[1])
end

schema = csm.fetch_schema()
print("schema version: "..schema.major .. "." .. schema.minor)
print("schema length: "..#schema)
for v in pairs(schema) do
  print("field name: "..v.name)
  print("\ttype: "..v.field_type)
  print("\trequired: "..tostring(v.required))
  print("\tgenerated: "..tostring(v.generated))
  if v.field_type == 2 then -- list
    print("\tsubtype: "..v.subtype)
  elseif v.field_type == 3 then -- int
    if v.min ~= nil then
      print("\tmin: "..v.min)
    end
    if v.max ~= nil then
      print("\tmax: "..v.max)
    end
  elseif v.field_type == 1 or v.field_type == 4 then -- string/hex
    if v.length then
      print("\tlength: "..v.length)
    end
  end
end

l, slen = csm.fetch_services()

print_services(l)

s = csm.new_service()
for v in pairs(schema) do
  if not v.generated then
    if v.name == "version" then
      s.version = "2.0"
    elseif v.field_type == 3 then -- int
      s[v.name] = math.random(v.min ~= nil and v.min or -1000, v.max ~= nil and v.max or 1000)
    elseif v.field_type == 1 then -- string
      local str = "" -- Start string
      local len = v.length and v.length or math.random(1,200)
      for i = 1, len do
	str = str .. string.char(math.random(32, 126)) -- Generate random number from 32 to 126, turn it into character and add to string
      end
      s[v.name] = str
    elseif v.field_type == 4 then -- hex
      local str = "" -- Start string
      local len = v.length and v.length or math.random(1,200)
      for i = 1, len do
	str = str .. hex_chars[math.random(1, 16)]
      end
      s[v.name] = str
    elseif v.field_type == 2 then -- list
      list = {}
      for i=1,3 do
	if v.subtype == 3 then -- int
	  table.insert(list, math.random(v.min ~= nil and v.min or -1000, v.max ~= nil and v.max or 1000))
	elseif v.subtype == 1 then -- string
	  local str = "" -- Start string
	  local len = v.length and v.length or math.random(1,200)
	  for i = 1, len do
	    str = str .. string.char(math.random(32, 126)) -- Generate random number from 32 to 126, turn it into character and add to string
	  end
	  table.insert(list,str)
	elseif v.subtype == 4 then -- hex
	  local str = "" -- Start string
	  local len = v.length and v.length or math.random(1,200)
	  for i = 1, len do
	    str = str .. hex_chars[math.random(1, 16)]
	  end
	  table.insert(list,str)
	end
      end
      s[v.name] = list
    end
  end
end

print("########## New Service ##########")
if not s:commit() then error("Failed to commit service") end
key = s.key.value
s:free()
print("key: " .. key)
l, slen = csm.fetch_services()
print_services(l,key)

print "########## Changing description, new tag array ##########"
s = l[key]
s.description = "new description"
s.tag = {"foo","bar","baz"}
if not s:commit() then error("Failed to commit service") end
l, slen = csm.fetch_services()
print_services(l,key)

print "########## Change item of tag array ##########"
s = l[key]
s.tag[2] = "blah"
if not s:commit() then error("Failed to commit service") end
l, slen = csm.fetch_services()
print_services(l,key)

print "########## Remove item of tag array ##########"
s = l[key]
s.tag[2] = nil
if not s:commit() then error("Failed to commit service") end
l, slen = csm.fetch_services()
print_services(l,key)

print "########## Remove tag fields ##########"
s = l[key]
s.tag = nil
if not s:commit() then error("Failed to commit service") end
l, slen = csm.fetch_services()
print_services(l,key)

print "########## Delete Service ##########"
if not l[key]:remove() then error("Failed to remove service") end
l, slen = csm.fetch_services()
print_services(l)

l:free()
schema:free()
csm.shutdown()