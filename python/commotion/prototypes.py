from ctypes import *

class ReturnCode:
    OK = 0
    ERROR = -1
    
def _check_simple_error(ret,func,args):
    if ret == ReturnCode.ERROR:
	raise RuntimeError
    return ret

def _check_char_pointer_error(ret,func,args):
    if not ret: # function returned NULL
	raise RuntimeError
    return ret
  
def _check_pointer_error(ret,func,args):
    if not ret: # function returned NULL
	raise RuntimeError
    return c_void_p(ret) # ctypes converts c_void_p restypes to ints...that's really annoying

libCSM = CDLL("libcommotion-service-manager.so")

libCSM.csm_config_create.argtypes = []
libCSM.csm_config_create.restype = c_void_p
libCSM.csm_config_create.errcheck = _check_pointer_error
libCSM.csm_config_set_mgmt_sock.argtypes = [c_void_p, c_char_p]
libCSM.csm_config_set_mgmt_sock.errcheck = _check_simple_error
libCSM.csm_config_free.argtypes = [c_void_p]

libCSM.csm_schema_fetch.argtypes = [POINTER(c_void_p), c_void_p]
libCSM.csm_schema_free.argtypes = [c_void_p]
#libCSM.csm_schema_free.errcheck = _check_simple_error
libCSM.csm_schema_get_major_version.argtypes = [c_void_p]
libCSM.csm_schema_get_major_version.errcheck = _check_simple_error
libCSM.csm_schema_get_minor_version.argtypes = [c_void_p]
libCSM.csm_schema_get_minor_version.restype = c_double
libCSM.csm_schema_get_minor_version.errcheck = _check_simple_error

libCSM.csm_schema_get_field_by_index.argtypes = [c_void_p, c_int, POINTER(c_char_p)]
libCSM.csm_schema_get_field_by_index.restype = c_void_p
libCSM.csm_schema_get_field_by_index.errcheck = _check_pointer_error

libCSM.csm_schema_field_get_name.argtypes = [c_void_p]
libCSM.csm_schema_field_get_name.restype = c_char_p
libCSM.csm_schema_field_get_name.errcheck = _check_char_pointer_error
libCSM.csm_schema_field_get_required.argtypes = [c_void_p, POINTER(c_bool)]
libCSM.csm_schema_field_get_required.errcheck = _check_simple_error
libCSM.csm_schema_field_get_generated.argtypes = [c_void_p, POINTER(c_bool)]
libCSM.csm_schema_field_get_generated.errcheck = _check_simple_error
libCSM.csm_schema_field_get_type.argtypes = [c_void_p]
libCSM.csm_schema_field_get_type.errcheck = _check_simple_error

libCSM.csm_schema_field_get_list_subtype.argtypes = [c_void_p]
libCSM.csm_schema_field_get_list_subtype.errcheck = _check_simple_error
libCSM.csm_schema_field_get_string_length.argtypes = [c_void_p]
libCSM.csm_schema_field_get_string_length.errcheck = _check_simple_error
libCSM.csm_schema_field_get_min.argtypes = [c_void_p, POINTER(c_long)]
libCSM.csm_schema_field_get_min.errcheck = _check_simple_error
libCSM.csm_schema_field_get_max.argtypes = [c_void_p, POINTER(c_long)]
libCSM.csm_schema_field_get_max.errcheck = _check_simple_error

libCSM.csm_services_fetch.argtypes = [POINTER(c_void_p), c_void_p]
libCSM.csm_services_fetch.errcheck = _check_simple_error
libCSM.csm_services_free.argtypes = [c_void_p]
#libCSM.csm_services_free.errcheck = _check_simple_error

libCSM.csm_service_create.restype = c_void_p
libCSM.csm_service_create.errcheck = _check_pointer_error
libCSM.csm_service_destroy.argtypes = [c_void_p]
libCSM.csm_service_commit.argtypes = [c_void_p, c_void_p]
libCSM.csm_service_commit.errcheck = _check_simple_error
libCSM.csm_service_remove.argtypes = [c_void_p, c_void_p]
libCSM.csm_service_remove.errcheck = _check_simple_error

libCSM.csm_services_get_by_index.argtypes = [c_void_p, c_int]
libCSM.csm_services_get_by_index.restype = c_void_p
libCSM.csm_services_get_by_index.errcheck = _check_pointer_error
libCSM.csm_services_get_by_key.argtypes = [c_void_p, c_char_p]
libCSM.csm_services_get_by_key.restype = c_void_p
libCSM.csm_services_get_by_key.errcheck = _check_pointer_error

libCSM.csm_service_is_local.argtypes = [c_void_p]

libCSM.csm_service_fields_get_length.argtypes = [c_void_p]
libCSM.csm_service_fields_get_length.errcheck = _check_simple_error
libCSM.csm_service_get_next_field.argtypes = [c_void_p, c_void_p, POINTER(c_char_p)]
libCSM.csm_service_get_next_field.restype = c_void_p
libCSM.csm_service_get_next_field.errcheck = _check_pointer_error
libCSM.csm_service_get_field_by_name.argtypes = [c_void_p, c_char_p]
libCSM.csm_service_get_field_by_name.restype = c_void_p
libCSM.csm_service_get_field_by_name.errcheck = _check_pointer_error

libCSM.csm_field_get_name.argtypes = [c_void_p]
libCSM.csm_field_get_name.restype = c_char_p
libCSM.csm_field_get_name.errcheck = _check_char_pointer_error
libCSM.csm_field_get_type.argtypes = [c_void_p]
libCSM.csm_field_get_type.errcheck = _check_simple_error
libCSM.csm_field_get_int.argtypes = [c_void_p, POINTER(c_long)]
libCSM.csm_field_get_int.errcheck = _check_simple_error
libCSM.csm_field_get_string.argtypes = [c_void_p]
libCSM.csm_field_get_string.restype = c_char_p
libCSM.csm_field_get_string.errcheck = _check_char_pointer_error

libCSM.csm_field_get_list_subtype.argtypes = [c_void_p]
libCSM.csm_field_get_list_subtype.errcheck = _check_simple_error
libCSM.csm_field_get_list_length.argtypes = [c_void_p]
libCSM.csm_field_get_list_length.errcheck = _check_simple_error
libCSM.csm_field_get_list_int.argtypes = [c_void_p, c_int, POINTER(c_long)]
libCSM.csm_field_get_list_int.errcheck = _check_simple_error
libCSM.csm_field_get_list_string.argtypes = [c_void_p, c_int]
libCSM.csm_field_get_list_string.restype = c_char_p
libCSM.csm_field_get_list_string.errcheck = _check_char_pointer_error

libCSM.csm_field_set_int_list_from_array.argtypes = [c_void_p, POINTER(c_long), c_int]
libCSM.csm_field_set_int_list_from_array.errcheck = _check_simple_error
libCSM.csm_field_set_string_list_from_array.argtypes = [c_void_p, POINTER(c_char_p), c_int]
libCSM.csm_field_set_string_list_from_array.errcheck = _check_simple_error

libCSM.csm_service_set_int.argtypes = [c_void_p, c_char_p, c_long]
libCSM.csm_service_set_int.errcheck = _check_simple_error
libCSM.csm_service_set_string.argtypes = [c_void_p, c_char_p, c_char_p]
libCSM.csm_service_set_string.errcheck = _check_simple_error
libCSM.csm_service_set_int_list_from_array.argtypes = [c_void_p, c_char_p, POINTER(c_long), c_int]
libCSM.csm_service_set_int_list_from_array.errcheck = _check_simple_error
libCSM.csm_service_set_string_list_from_array.argtypes = [c_void_p, c_char_p, POINTER(c_char_p), c_int]
libCSM.csm_service_set_string_list_from_array.errcheck = _check_simple_error