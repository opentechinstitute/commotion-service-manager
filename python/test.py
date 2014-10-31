from commotion.csm import *
import random
import string
import sys

hex_chars = ("0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F")

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

s.commit()
del s

l.update()
for s in l:
  for (k,v) in s:
    print "\t" + k + ": " + repr(v)
  #s.remove()

del l
del schema
del config