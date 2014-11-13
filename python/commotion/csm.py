from ctypes import *
from prototypes import libCSM, ReturnCode
import collections

class FieldType:
    STRING,LIST,INT,HEX = range(1,5)

def FieldTypeToStr(type):
    if type == FieldType.STRING:
	return "STRING"
    elif type == FieldType.HEX:
	return "HEX"
    elif type == FieldType.INT:
	return "INT"
    elif type == FieldType.LIST:
	return "LIST"

class CSMConfig(object):
    def __init__(self,path=None):
	self.ptr = libCSM.csm_config_create()
	if (path):
	    libCSM.csm_config_set_mgmt_sock(self.ptr,path)
    
    def __del__(self):
	libCSM.csm_config_free(self.ptr)

class CSMSchema(object):
    def __init__(self,config):
	if not isinstance(config, CSMConfig):
	    raise TypeError
	self.__config = config
	self.ptr = c_void_p()
	self.__len = libCSM.csm_schema_fetch(byref(self.ptr), self.__config.ptr)
	if self.__len <= 0:
	    raise RuntimeError
	self.version = {
	    'major': libCSM.csm_schema_get_major_version(self.__config.ptr),
	    'minor': libCSM.csm_schema_get_minor_version(self.__config.ptr)
	}
    
    def __len__(self):
	return self.__len
    
    def __iter__(self):
	for i in range(self.__len):
	    name = c_char_p()
	    field = libCSM.csm_schema_get_field_by_index(self.ptr,i,byref(name))
	    name = name.value
	    field_type = libCSM.csm_schema_field_get_type(field)
	    if field_type == FieldType.INT:
		yield _CSMSchemaFieldInt(field,name)
	    elif field_type == FieldType.STRING or field_type == FieldType.HEX:
		yield _CSMSchemaFieldString(field,name)
	    elif field_type == FieldType.LIST:
		yield _CSMSchemaFieldList(field,name)
	    else:
		raise TypeError
      
    def __getitem__(self,name):
	field = libCSM.csm_schema_get_field_by_name(self.ptr,name)
	field_type = libCSM.csm_schema_field_get_type(field)
	if field_type == FieldType.INT:
	    return _CSMSchemaFieldInt(field,name)
	elif field_type == FieldType.STRING or field_type == FieldType.HEX:
	    return _CSMSchemaFieldString(field,name)
	elif field_type == FieldType.LIST:
	    return _CSMSchemaFieldList(field,name)
	else:
	    raise TypeError
      
    def __del__(self):
	libCSM.csm_schema_free(self.ptr)

class _CSMSchemaField(object):
    def __init__(self,ptr,name=None):
	self.ptr = ptr
	if not name:
	    self.name = libCSM.csm_schema_field_get_name(self.ptr)
	else:
	    self.name = name
	self.required = c_bool()
	libCSM.csm_schema_field_get_required(self.ptr, byref(self.required))
	self.generated = c_bool()
	libCSM.csm_schema_field_get_generated(self.ptr, byref(self.generated))
	self.type = libCSM.csm_schema_field_get_type(self.ptr)

class _CSMSchemaFieldInt(_CSMSchemaField):
    def __init__(self,ptr,name=None):
	_CSMSchemaField.__init__(self,ptr,name)
	limit = c_long()
	if libCSM.csm_schema_field_get_min(self.ptr,byref(limit)) == ReturnCode.OK:
	    self.min = limit.value
	if libCSM.csm_schema_field_get_max(self.ptr,byref(limit)) == ReturnCode.OK:
	    self.max = limit.value

class _CSMSchemaFieldString(_CSMSchemaField):
    def __init__(self,ptr,name=None):
	_CSMSchemaField.__init__(self,ptr,name)
	length = libCSM.csm_schema_field_get_string_length(self.ptr)
	if length:
	    self.length = length
	
class _CSMSchemaFieldList(_CSMSchemaField):
    def __init__(self,ptr,name=None):
	_CSMSchemaField.__init__(self,ptr,name)
	self.subtype = libCSM.csm_schema_field_get_list_subtype(self.ptr)

class CSMServiceList(collections.Mapping):
    def __init__(self, config):
	if not isinstance(config, CSMConfig):
	    raise TypeError
	self.__config = config
	self.__ptr = None
	#self.__services = []
	self.__len = 0
	self.update()
    
    def __len__(self):
	return self.__len
    
    def __getitem__(self,key):
	if not key:
	    raise KeyError
	if not isinstance(key, basestring):
	    raise TypeError
	return CSMService(self.__config, libCSM.csm_services_get_by_key(self.__ptr,key))
    
    def __iter__(self):
	for i in range(self.__len):
	    yield CSMService(self.__config, libCSM.csm_services_get_by_index(self.__ptr,i))
	    #yield self.__services[i]
    
    def __delitem__(self,key):
	libCSM.csm_service_remove(libCSM.csm_services_get_by_key(self.__ptr,key), self.__config.ptr)
	self.update()
    
    def __del__(self):
	libCSM.csm_services_free(self.__ptr)
    
    def append(self,value):
	if not isinstance(value,CSMService):
	    raise TypeError
	libCSM.csm_service_commit(value.ptr, self.__config.ptr)
	self.update()
    
    def update(self):
        """ Free's current list of services and repopulates it from the Commotion service manager."""
	# first, free current list of services
	if (self.__ptr and self.__len):
	    self.__del__()
	
	# next, fetch list of services from CSM
	self.__ptr = c_void_p()
	self.__len = libCSM.csm_services_fetch(byref(self.__ptr), self.__config.ptr)
	#self.__services = []
	#for i in range(self.__len):
	    #self.__services.append(CSMService(libCSM.csm_services_get_by_index(self.__ptr,i)))
	
class CSMService(object):
    """A service object that handles service creation, modification, comparison, and deletion."""
    def __init__(self, config, ptr=None):
        """
        Uses a pointer to load an existing service, or requests a pointer for a new Commotion service.
        
        ptr : C pointer to a commotion service
        """
        if not isinstance(config, CSMConfig):
	    raise TypeError
	self.__config = config
        self.__dirty = False
        self.__local = 1
        if ptr:
            if type(ptr) != c_void_p:
		raise TypeError
            self.ptr = ptr
            # fetch all fields so client can display service
            self.__len = libCSM.csm_service_fields_get_length(self.ptr)
            key = c_char_p()
            field = libCSM.csm_service_get_next_field(self.ptr, None, byref(key))
            while field.value:
		field_type = libCSM.csm_field_get_type(field)
		if field_type == FieldType.STRING or field_type == FieldType.HEX:
		    self.__dict__[key.value] = libCSM.csm_field_get_string(field)
		elif field_type == FieldType.INT:
		    out = c_long()
		    libCSM.csm_field_get_int(field, byref(out))
		    self.__dict__[key.value] = out.value
		elif field_type == FieldType.LIST:
		    field_subtype = libCSM.csm_field_get_list_subtype(field)
		    list_len = libCSM.csm_field_get_list_length(field)
		    self.__dict__[key.value] = []
		    if field_subtype == FieldType.INT:
			for i in range(list_len):
			    out = c_long()
			    libCSM.csm_field_get_list_int(field,i,byref(out))
			    self.__dict__[key.value].append(out.value)
		    elif field_subtype == FieldType.STRING or field_subtype == FieldType.HEX:
			for i in range(list_len):
			    self.__dict__[key.value].append(libCSM.csm_field_get_list_string(field,i))
		    else:
			raise TypeError
		else:
		    raise TypeError
		# get next field
		try:
		    field = libCSM.csm_service_get_next_field(self.ptr, field, byref(key))
		except:
		    break
            # flag to indicate whether service is local/editable or not
            if libCSM.csm_service_is_local(self.ptr) == 0:
		self.__local = 0
        else:
            self.ptr = libCSM.csm_service_create()
            self.__len = 0
    
    def free(self):
	libCSM.csm_service_destroy(self.ptr)
    
    def is_current(self):
	return not self.__dirty
    
    def __len__(self):
	return self.__len
    
    def __iter__(self):
	for name,val in self.__dict__.iteritems():
	    if name == "_CSMService__local" or name == "_CSMService__dirty" or name == "ptr" or name == "_CSMService__len" or name == "_CSMService__config":
		continue
	    yield (name,val)
    
    def __setattr__(self,name,value):
	if name == "_CSMService__local" or name == "_CSMService__dirty" or name == "ptr" or name == "_CSMService__len" or name == "_CSMService__config":
	    self.__dict__[name] = value
	    return
	if not self.__local:
	    raise TypeError
	field_type = None
	try:
	    field = libCSM.csm_service_get_field_by_name(self.ptr, name)
	    field_type = libCSM.csm_field_get_type(field)
	except:
	    pass
	if isinstance(value,int) or isinstance(value,long):
	    if field_type and field_type != FieldType.INT:
		raise TypeError
	    libCSM.csm_service_set_int(self.ptr, name, c_long(value))
	elif isinstance(value, basestring):
	    if field_type and field_type != FieldType.STRING and field_type != FieldType.HEX:
		raise TypeError
	    libCSM.csm_service_set_string(self.ptr, name, value)
	elif isinstance(value, list):
	    field_subtype = None
	    if field_type:
		if field_type != FieldType.LIST:
		    raise TypeError
		field_subtype = libCSM.csm_field_get_list_subtype(self.ptr)
	    list_len = len(value)
	    if list_len <= 0:
		raise ValueError
	    subtype = type(value[0])
	    for x in value:
		if type(x) != subtype:
		    raise TypeError
	    if subtype == int or subtype == long:
		if field_subtype and field_subtype != FieldType.INT:
		    raise TypeError
		new_list = (c_long * list_len)(*value)
		libCSM.csm_service_set_int_list_from_array(self.ptr,name,new_list,list_len)
	    elif subtype == str:
		if field_subtype and field_subtype != FieldType.STRING and field_subtype != FieldType.HEX:
		    raise TypeError
		new_list = (c_char_p * list_len)(*value)
		libCSM.csm_service_set_string_list_from_array(self.ptr,name,new_list,list_len)
	    else:
		raise TypeError
	else:
	    raise TypeError
	self.__dirty = True
    
    def __getattr__(self,name):
	if name == "_CSMService__local" or name == "_CSMService__dirty" or name == "ptr" or name == "_CSMService__len" or name == "_CSMService__config":
	    return self.__dict__[name]
	field = libCSM.csm_service_get_field_by_name(self.ptr, name)
	if not field.value:
	    raise LookupError
	field_type = libCSM.csm_field_get_type(field)
	if field_type == FieldType.INT:
	    out = c_long()
	    libCSM.csm_field_get_int(field, byref(out))
	    return out.value
	elif field_type == FieldType.STRING or field_type == FieldType.HEX:
	    return libCSM.csm_field_get_string(field)
	elif field_type == FieldType.LIST:
	    field_subtype = libCSM.csm_field_get_list_subtype(field)
	    list_len = libCSM.csm_field_get_list_length(field)
	    ret = []
	    if field_subtype == FieldType.INT:
		for i in range(list_len):
		    out = c_long()
		    libCSM.csm_field_get_list_int(field,i,byref(out))
		    ret.append(out.value)
	    elif field_subtype == FieldType.STRING or field_subtype == FieldType.HEX:
		for i in range(list_len):
		    ret.append(libCSM.csm_field_get_list_string(field,i))
	    else:
		raise TypeError
	    return ret
	else:
	    raise LookupError
    
    def __delattr__(self,name):
	if not self.__local:
	    raise TypeError
	libCSM.csm_service_remove_field(self.ptr,name, self.__config.ptr)
	self.__dirty = True
    
    def __eq__(self, other):
        """Test equality of this service and another.

        other : CSMService object
        return : bool
        """
        return (isinstance(other, self.__class__)
            and self.__dict__ == other.__dict__)

    def __ne__(self, other):
        """Test inequality of this service and another.

        other : CSMService object
        return : bool
        """
        return not self.__eq__(other)
    
    def __repr__(self):
        """
        The official string representation of this service, formatted as a valid Python expression to recreate it.

        return : string
        """
	pass
    
    def __str__(self):
	"""
        The human readable string representation of this service.

        return : string
        """
	pass
    
    def commit(self):
        """Sets current service values to its pointer in the Commotion Service Manager """
        if not self.__local:
	    raise TypeError
        if not self.__dirty:
	    return
	# Upon commiting, key and signature will be set
	libCSM.csm_service_commit(self.ptr, self.__config.ptr)
	self.__dirty = False
    
    def remove(self):
        """Removes the service in both the Commotion Service Manager and locally."""
        if not self.__local:
	    raise TypeError
        libCSM.csm_service_remove(self.ptr, self.__config.ptr)