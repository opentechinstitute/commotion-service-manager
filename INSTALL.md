Commotion Service Manager Installation
======================================

Supported Targets
-----------------

The Commotion Service Manager was designed for and successfully builds for the following platforms:

 * Any OpenWRT-compatible router
 * Debian Linux, x86

Dependencies
------------

The Commotion Service Manager is most useful when built with [UCI][] support, which comes by default with OpenWRT.

Other dependencies:
 * [commotiond][]
 * [libavahi][]

Build and Install
-----------------

To build and install for Linux:

    $ git clone git://github.com/opentechinstitute/commotion-service-manager.git
    $ cd commotion-service-manager
    $ mkdir build && cd build
    $ cmake ..
    $ make
    $ sudo make install

To build for OpenWRT, use the supplied Makefile in the `openwrt` directory, or use the [Commotion feed][] in your OpenWRT build tree.

Uninstall
---------

    $ sudo make uninstall

[UCI]: http://nbd.name/gitweb.cgi?p=uci.git
[commotiond]: https://github.com/opentechinstitute/commotiond
[libavahi]: http://avahi.org/
[Commotion feed]: https://github.com/opentechinstitute/commotion-feed