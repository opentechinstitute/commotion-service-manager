from ctypes import *

libCSM = CDLL("libcommotion-service-manager.so")

libCSM.service_new.argtypes = [POINTER(c_char_p)]
libCSM.service_new.restype = c_void_p

libCSM.service_get_key.restype = c_char_p
libCSM.service_get_name.restype = c_char_p
libCSM.service_get_desciption.restype = c_char_p
libCSM.service_get_uri.restype = c_char_p
libCSM.service_get_icon.restype = c_char_p
libCSM.service_get_key.restype = c_char_p
#libCSM.service_get_categories.argtypes = [c_void_p,POINTER(POINTER(c_char_p))]
libCSM.service_get_categories.argtypes = [c_void_p,POINTER(c_void_p)];
libCSM.categories_get.restype = c_char_p
libCSM.service_get_signature.restype = c_char_p

libCSM.service_set_categories.argtypes = [c_void_p,POINTER(c_char_p),c_int]

#libCSM.commit_service.argtypes = [c_void_p,POINTER(c_char_p)]

#libCSM.get_services.argtypes = [POINTER(POINTER(c_void_p))]
#libCSM.free_services.argtypes = [POINTER(c_void_p),c_int]

libCSM.services_fetch.argtypes = [POINTER(c_void_p)]
libCSM.services_get.restype = c_void_p

class CSM(list):
    """ Fetches all current services.

    list : ????
    """
    def __init__(self):
        """ Sets all defaults to empty"""
	self.services = []
	self.len = 0
    
    def update(self):
        """ Free's current list of services and repopulates it from the Commotion service manager."""
	# first, free current list of services
	if (self._service_list and self.len):
	    assert libCSM.services_free(self._service_list).value == 1
	#if (self.len and self.services):
	    #service_array = c_void_p * self.len
	    #c_services = service_array()
	    #for i in range(self.len):
		#c_services[i] = c_void_p(self.services[i])
	    #assert libCSM.free_services(c_services,c_int(self.len)).value == 1
	
	# next, fetch list of services from CSM
	self._service_list = c_void_p
	self.len = libCSM.services_fetch(byref(self._service_list)).value
	self.services = []
	for i in range(self.len):
	    service = libCSM.services_get(self._service_list,c_int(i))
	    self.services.append(CommotionService(service))
	#c_services = POINTER(c_void_p)()
	#self.len = libCSM.get_services(byref(c_services)).value
	#self.services = []
	# iterator for POINTER doesn't work so well, so we create our own list
	#for i in range(self.len):
	    #self.services.append(CommotionService(c_services[i]))

class CommotionService(object):
    """A service object that handles service creation, modification, comparison, and deletion."""
    def __init__(self, ptr=None):
        """
        Uses a pointer to load an existing service, or requests a pointer for a new Commotion service.
        
        ptr : C pointer to a commotion service
        """
        if (ptr):
            assert type(ptr) = c_void_p
            self.ptr = ptr
            self.key = libCSM.service_get_key(self.ptr).value
            self.name = libCSM.service_get_name(self.ptr).value
            self.description = libCSM.service_get_desciption(self.ptr).value
            self.uri = libCSM.service_get_uri(self.ptr).value
            self.icon = libCSM.service_get_icon(self.ptr).value
            self.ttl = libCSM.service_get_ttl(self.ptr).value
            self.lifetime = libCSM.service_get_lifetime(self.ptr).value
            category_list = c_void_p
            categories_len = libCSM.service_get_categories(self.ptr,byref(category_list)).value
            self.categories = []
            for i in range(categories_len):
		category = libCSM.categories_get(category_list,i)
		self.categories.append(category.value)
            #self.c_categories = POINTER(c_char_p)()
            #self.cat_len = libCSM.service_get_categories(self.ptr,byref(self.c_categories)).value
            #self.categories = []
            #for i in range(self.cat_len):
                #self.categories.append(self.c_categories[i])
            self.signature = libCSM.service_get_signature(self.ptr).value
        else:
            self.ptr = libCSM.service_new()
            #self.key = libCSM.service_get_key(self.ptr).value
    
    def __eq__(self, other):
        """Test equality of this service and another.

        other : CommotionService object
        return : bool
        """
        return (isinstance(other, self.__class__)
            and self.__dict__ == other.__dict__)
        #return (isinstance(other, self.__class__)
            #and self.ptr == other.ptr)

    def __ne__(self, other):
        """Test inequality of this service and another.

        other : CommotionService object
        return : bool
        """
        return not self.__eq__(other)
    
    def __repr__(self):
        """
        The official string representation of this service, formatted as a valid Python expression to recreate it.

        return : string
        """
        categories = '['
        for category in self.categories:
            categories += "%s, " % category
        categories = categories.rstrip(', ') + ']'
        return ("CommotionService("
                "key = %r, "
                "name = %r, "
                "description = %r, "
                "uri = %r, "
                "icon = %r, "
                "ttl = %r, "
                "lifetime = %r, "
                "categories = %r, "
                "signature = %r)") % (self.key,
                                      self.name,
                                      self.description,
                                      self.uri,
                                      self.icon,
                                      self.ttl,
                                      self.lifetime,
                                      categories,
                                      self.signature)
    
    def __str__(self):
                """
        The human readable string representation of this service.

        return : string
        """

        categories = '['
        for category in self.categories:
            categories += "%s, " % category
        categories = categories.rstrip(', ') + ']'
        return ("{\n"
                "\tkey = %s,\n"
                "\tname = %s,\n"
                "\tdescription = %s,\n"
                "\turi = %s,\n"
                "\ticon = %s,\n"
                "\tttl = %d,\n"
                "\tlifetime = %d,\n"
                "\tcategories = %s,\n"
                "\tsignature = %s}") % (self.key,
                                        self.name,
                                        self.description,
                                        self.uri,
                                        self.icon,
                                        self.ttl,
                                        self.lifetime,
                                        categories,
                                        self.signature)
    
    def commit_service(self):
        """Sets current service values to its pointer in the Commotion Service Manager """
        #try:
            assert libCSM.service_set_name(self.ptr,c_char_p(self.name)).value == 1
            assert libCSM.service_set_description(self.ptr,c_char_p(self.description)).value == 1
            assert libCSM.service_set_uri(self.ptr,c_char_p(self.uri)).value == 1
            assert libCSM.service_set_icon(self.ptr,c_char_p(self.icon)).value == 1
            assert libCSM.service_set_ttl(self.ptr,c_int(self.ttl)).value == 1
            assert libCSM.service_set_lifetime(self.ptr,c_long(self.lifetime)).value == 1
            n = len(self.categories)
            cat_array = c_char_p * n
            c_categories = cat_array()
            for i in range(n):
                c_categories[i] = c_char_p(self.categories[i])
            assert libCSM.service_set_categories(self.ptr,c_categories,c_int(n)).value == 1
            # Upon commiting, key and signature will be set
            assert libCSM.commit_service(self.ptr).value == 1
            #c_sig = c_char_p
            #assert libCSM.commit_service(self.ptr,byref(c_sig)).value == 1
            #self.signature = c_sig.value
            
    
    def remove_service(self):
        """Removes the service in both the Commotion Service Manager and locally."""
        assert libCSM.remove_service(self.ptr).value == 1
        self.__del__(self)
