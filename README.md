Commotion Service Manager
=========================

The Commotion Service Manager receives, parses, verifies, and caches service announcements on a local Commotion mesh network. It implements an multicast DNS (mDNS) stack using the [Avahi][] library, and verifies signed service announcements using [libcommotion][] and [Serval-DNA][].

Commotion Service Manager is selected as a default build option in Commotion-Router (https://github.com/opentechinstitute/commotion-router)

Changelog
---------

28 Oct 2013: Release v0.2  
28 Dec 2013: Release v0.3  
3 Apr 2014: Release v0.4

[Avahi]: http://avahi.org/
[libcommotion]: https://github.com/opentechinstitute/commotiond
[Serval-DNA]: https://github.com/servalproject/serval-dna
