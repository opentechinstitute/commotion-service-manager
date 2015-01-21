"""
/**
 *       @file  test.py
 *      @brief  Python test script for Commotion Service Manager
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
"""

from commotion.csm import *
import random
import string
import sys

hex_chars = ("0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F")

def print_services(services,key=None):
  for s in services:
    if key and s.key != key:
      continue
    print "Service: " + s.key
    for (k,v) in s:
      print "\t" + k + ": " + repr(v)

if (len(sys.argv) == 2):
  config = CSMConfig(sys.argv[1])
else:
  config = CSMConfig()

schema = CSMSchema(config)
print "schema version: " + str(schema.version['major']) + "." + str(schema.version['minor'])
print "schema length: " + str(len(schema))
for x in schema:
  print "field name: " + x.name + "/" + schema[x.name].name
  print "\ttype: " + FieldTypeToStr(x.type)
  print "\trequired: " + str(x.required)
  print "\tgenerated: " + str(x.generated)
  if x.type == FieldType.LIST:
      print "\tsubtype: " + FieldTypeToStr(x.subtype)
  elif x.type == FieldType.INT:
      if hasattr(x,'min'):
	  print "\tmin: " + str(x.min)
      if hasattr(x,'max'):
	  print "\tmax: " + str(x.max)
  elif x.type == FieldType.STRING or x.type == FieldType.HEX:
      if hasattr(x,'length'):
	print "\tlength: " + str(x.length)

l = CSMServiceList(config)

s = CSMService(config)
for field in schema:
  if field.name == "version":
    s.version = "2.0"
  elif field.generated:
    continue
  elif field.type == FieldType.INT:
    setattr(s,field.name,random.randint(-1000 if not hasattr(field,'min') else field.min, 1000 if not hasattr(field,'max') else field.max))
  elif field.type == FieldType.STRING:
    if hasattr(field,'length'):
      str = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(field.length))
    else:
      str = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randint(1,200)))
    setattr(s,field.name,str)
  elif field.type == FieldType.HEX:
    if hasattr(field,'length'):
      str = ''.join(random.choice(hex_chars) for _ in range(field.length))
    else:
      str = ''.join(random.choice(hex_chars) for _ in range(random.randint(1,200)))
    setattr(s,field.name,str)
  elif field.type == FieldType.LIST:
    list = []
    if field.subtype == FieldType.INT:
      for i in range(3):
	list.append(random.randint(-1000 if not hasattr(field,'min') else field.min, 1000 if not hasattr(field,'max') else field.max))
    elif field.subtype == FieldType.STRING:
      for i in range(3):
	if hasattr(field,'length'):
	  str = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(field.length))
	else:
	  str = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randint(1,200)))
	list.append(str)
    elif field.subtype == FieldType.HEX:
      for i in range(3):
	if hasattr(field,'length'):
	  str = ''.join(random.choice(hex_chars) for _ in range(field.length))
	else:
	  str = ''.join(random.choice(hex_chars) for _ in range(random.randint(1,200)))
	list.append(str)
    setattr(s,field.name,list)

print "########## New Service ##########"
s.commit()
key = s.key
print "key: " + key
s.free()
del s
l.update()
print_services(l,key)

print "########## Changing description, new tag array ##########"
s = l[key]
s.description = "new description"
s.tag = ["foo","bar","baz"]
s.commit()
l.update()
print_services(l,key)

print "########## Change item of tag array ##########"
s = l[key]
s.tag[1] = "blah"
s.commit()
l.update()
print_services(l,key)

print "########## Remove item of tag array ##########"
s = l[key]
del s.tag[1]
s.commit()
l.update()
print_services(l,key)

print "########## Remove tag fields ##########"
s = l[key]
del s.tag
s.commit()
l.update()
print_services(l,key)

print "########## Delete Service ##########"
del l[key]
l.update()
print_services(l)

del l
del schema
del config