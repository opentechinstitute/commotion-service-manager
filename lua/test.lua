local inspect = require('inspect')
require("csm")

csm.init()
csm.config_set_mgmt_sock("/tmp/csm.sock")
schema = csm.fetch_schema()
print(schema.major)
print(schema.minor)
print(#schema)
-- field = next(schema,nil)
-- print(field.name)
for v in pairs(schema) do
  print(v.name..': field_type '..v.field_type..', required: '..tostring(v.required)..', generated: '..tostring(v.generated))
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

services, slen = csm.fetch_services()
print(slen)
print(#services)
print(services)

function print_services(services)
  for s in pairs(services) do
    print(#s)
    print("local: " .. tostring(s.islocal))
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

print_services(services)

s = services[0]
print("service:")
print(s)
f = s.description
print("description")
print(f)
s.description = "new description"
print(s.description)
-- check if changing an item in a list field works
print("tags")
print(inspect(s.tag.value))
print(s.tag.value[1])
print(s.tag.value[2])
print(s.tag.value[3])
s.tag = {"foo","bar","baz"}
s.tag[1] = nil
s.tag[1] = nil
s.tag = nil
s:commit()

services, slen = csm.fetch_services()
print_services(services)


s = csm.new_service()
-- s:commit() -- CSM command handlers should always return a true/false success object rather than failing
s:free()

services:free()
schema:free()
csm.shutdown()