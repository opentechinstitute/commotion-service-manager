CFLAGS+=-g -Wall
DAEMONLIBS=-lcommotion -lcommotion_serval-sas -lavahi-core -lavahi-common -luci
DAEMONSRC=internal.h debug.h browse.h browse.c main.c service.h service.c util.h util.c
DAEMONOBJ=browse.o main.o service.o util.o
LIBLIBS=-lcommotion
LIBSRC=internal.h debug.h commotion-service-manager.h commotion-service-manager.c
LIBOBJ=commotion-service-manager.o



# TEST_OBJS=util.o service.o browse.o
# OBJS=$(TEST_OBJS) main.o
# DEPS=Makefile internal.h service.h debug.h util.h uci-utils.h browse.h
# C_DEPS=service.c util.c uci-utils.c browse.c
BINDIR=$(DESTDIR)/usr/bin

ifeq ($(MAKECMDGOALS),openwrt)
CFLAGS+=-DUSE_UCI -DOPENWRT -D_GNU_SOURCE
# OBJS+=uci-utils.o
DAEMONSRC+=uci-utils.h uci-utils.c
DAEMONOBJ+=uci-utils.o
endif
openwrt: commotion-service-manager

ifeq ($(MAKECMDGOALS),linux)
CFLAGS+=-DUSE_UCI -DUSESYSLOG -DCLIENT -D_GNU_SOURCE -DUCIPATH="\"/opt/luci-commotion/etc/config\""
LDFLAGS+=-lavahi-client
# OBJS+=uci-utils.o
DAEMONSRC+=uci-utils.h uci-utils.c
DAEMONOBJ+=uci-utils.o
endif

linux: commotion-service-manager

all: commotion-service-manager

%.o: %.c
	$(CC) -fPIC -c -o $@ $< $(CFLAGS)

commotion-service-manager: $(DAEMONSRC) $(DAEMONOBJ)
	$(CC) $(CFLAGS) -o commotion-service-manager $(DAEMONOBJ) $(DAEMONLIBS) $(LDFLAGS)

libcsm.so: $(LIBSRC) $(LIBOBJ)
	$(CC) $(CFLAGS) -shared -o libcsm.so $(LIBOBJ) $(LIBLIBS) $(LDFLAGS)

install: commotion-service-manager
	install -d $(BINDIR)
	install -m 755 commotion-service-manager $(BINDIR)

uninstall:
	rm -f $(BINDIR)/commotion-service-manager

clean:
	rm -f commotion-service-manager libcsm.so *.o *.a

#
#  Google C++ Testing Framework
#

# GTEST_DIR=gtest
# CPPFLAGS += -isystem $(GTEST_DIR)/include -DGTEST_HAS_PTHREAD=0
# CXXFLAGS += -g -Wall -Wextra
# GTEST_HEADERS = $(GTEST_DIR)/include/gtest/gtest.h \
#                 $(GTEST_DIR)/include/gtest/internal/*.h
# GTEST_SRCS_ = $(GTEST_DIR)/src/*.cc $(GTEST_DIR)/src/*.h $(GTEST_HEADERS)
# 
# gtest-all.o : $(GTEST_SRCS_)
# 	$(CXX) $(CPPFLAGS) -I$(GTEST_DIR) $(CXXFLAGS) -c \
#             $(GTEST_DIR)/src/gtest-all.cc
# 
# gtest_main.o : $(GTEST_SRCS_)
# 	$(CXX) $(CPPFLAGS) -I$(GTEST_DIR) $(CXXFLAGS) -c \
#             $(GTEST_DIR)/src/gtest_main.cc
# 
# gtest.a : gtest-all.o
# 	$(AR) $(ARFLAGS) $@ $^
# 
# gtest_main.a : gtest-all.o gtest_main.o
# 	$(AR) $(ARFLAGS) $@ $^
# 
# ifeq ($(MAKECMDGOALS),test)
# SID = $(shell sudo -u serval servald id self |tail -n1)
# endif
# 
# test.o : test.cpp test.h $(GTEST_HEADERS) $(DEPS) $(C_DEPS)
# ifeq ($(SID),)
# 	@echo Was not able to determine Serval ID. Make sure servald is running!
# 	@exit 1
# else
# 	$(MAKE) clean
# 	$(MAKE) $(TEST_OBJS) CFLAGS="$(CFLAGS)"
# 	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -DSID="\"$(SID)\"" -c test.cpp
# endif
# 
# test : test.o gtest_main.a
# 	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(TEST_OBJS) $^ -o $@ $(LDFLAGS)

.PHONY: all clean install uninstall
