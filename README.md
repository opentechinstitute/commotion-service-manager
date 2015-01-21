[![alt tag](http://img.shields.io/badge/maintainer-dismantl-green.svg)](https://github.com/dismantl)

Commotion Service Manager
=========================

The Commotion Service Manager publishes, receives, parses, verifies, and caches service announcements on a local Commotion mesh network. It implements a multicast DNS (mDNS) stack using the [Avahi][] library, and uses the [commotiond][] API for cryptographically signing and verifying service announcements.

Components
==========

commotion-service-manager
-------------------------
commotion-service-manager is a daemon that is in charge of browsing and publishing service announcements. It provides a UNIX domain socket with which clients can issue commands, such as adding and updating services, listing services, removing services, and fetching the latest schema. It can be built with optional UCI integration, to read and write services to a local UCI configuration file.

libcommotion-service-manager
----------------------------
libcommotion-service-manager is a C client library and API for interacting with the commotion-service-manager daemon. It has a simple and comprehensive interface using simple data types and opaque object pointers to represent service lists, services, and fields.

Lua bindings
------------
A Lua library (libcsm_lua.so) and module (csm.lua) are included to allow interacting with CSM from Lua scripts. This was built to be used in OpenWRT's LuCI web interface, but implements several custom data types to provide the full functionality of the C client API. A test script (test.lua) is included that demonstrates the use of the bindings.

Python bindings
---------------
The Python module uses the ctypes Python library for implementing the libcommotion-service-manager client API. The main classes that are exported for use are `CSMConfig`, `CSMSchema`, `CSMServiceList`, and `CSMService`. A test script (test.py) is included that demonstrates the use of the Python module.

Runtime schema system
=====================

Instead of hardcoding the protocol for announcing local services, the protocol is now implemented with a runtime schema system defined in schema configuration files. The schema files are found in `files/schemas.d`. These files, in JSON format, describe the version of the schema and each information field. Each information field can have the following properties:

* `field`: Name of the field.
* `type`: Field values can be either `int`, `string`, `hex`, or `list`.
* `required`: Is the information required to be included in the announcement?
* `generated`: Is the information in the field provided by the user, or automatically generated?
* `subtype` (list only): `int`, `string`, or `hex`. Lists cannot currently mix types.
* `length` (string/hex only): Set this is strings must be a fixed length.
* `min/max` (int only): Minimum and maximum values for integer fields.

Beyond this, the only limits of information fields in service announcements are that integer values must be within the range of 32-bit signed integers, and that the total length of the field name and field value (converted to a string in the case of integer values) must be less than 255 characters. This applies to list field items individually. The limit exists because the fields are advertised as the TXT fields in mDNS announcements, which are limited to 256 characters.

Additionally, each schema **must** include the following fields, as they relate to the internal functioning of CSM:

* `{ "field", "lifetime", "required": true, "type": "int", "min": 0 }`
* `{ "field": "key", "required": true, "generated": true, "type": "hex", "length": "64" }`
* `{ "field": "signature", "required": true, "generated": true, "type": "hex", "length": "128" }`
* `{ "field": "version", "required": true, "type": "string" }`

Schema version numbers should follow [Semantic Versioning][semver]. CSM daemons will only accept the announcements of services with the same major version number as the latest schema it has on file; other announcements will be discarded. To make different minor version of schemas compatible, newer minor versions can only add additional fields, not remove or modify existing fields.
=======
Commotion Service Manager
=========================

The Commotion Service Manager receives, parses, verifies, and caches service announcements on a local Commotion mesh network. It implements an multicast DNS (mDNS) stack using the [Avahi][] library, and verifies signed service announcements using [libcommotion][] and [Serval-DNA][].

Commotion Service Manager is selected as a default build option in Commotion-Router (https://github.com/opentechinstitute/commotion-router)

Changelog
=========

28 Oct 2013: Release v0.2  
28 Dec 2013: Release v0.3  
03 Apr 2014: Release v0.4  
25 Jun 2014: Release v0.4.1  
02 Jul 2014: Release v1.0  
21 Jan 2015: Release v2.0  

[Avahi]: http://avahi.org/
[commotiond]: https://github.com/opentechinstitute/commotiond
[semver]: http://semver.org/