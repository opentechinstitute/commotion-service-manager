CFLAGS+=-g
LDFLAGS+=-lserval-crypto -lavahi-core -lavahi-common -luci
OBJS=util.o commotion-service-manager.o
DEPS=Makefile commotion-service-manager.h debug.h util.h uci-utils.h
BINDIR=$(DESTDIR)/usr/bin

ifeq ($(TARGET), openwrt)
CFLAGS+=-DUSE_UCI -DOPENWRT
OBJS+=uci-utils.o
else ifeq ($(TARGET), linux)
CFLAGS+=-DUSE_UCI -DUSESYSLOG -DUCIPATH="\"/opt/luci-commotion/etc/config\""
OBJS+=uci-utils.o
endif

all: commotion-service-manager

%.o: %.c $(DEPS)
	$(CC) -fPIC -c -o $@ $< $(CFLAGS)

commotion-service-manager: $(DEPS) $(OBJS)
	$(CC) $(CFLAGS) -o commotion-service-manager $(OBJS) $(LDFLAGS)

install: commotion-service-manager
	install -d $(BINDIR)
	install -m 755 commotion-service-manager $(BINDIR)

uninstall:
	rm -f $(BINDIR)/commotion-service-manager

clean:
	rm -f commotion-service-manager *.o *.a test

#
#  Google C++ Testing Framework
#

GTEST_DIR=gtest
CPPFLAGS += -isystem $(GTEST_DIR)/include -DGTEST_HAS_PTHREAD=0
CXXFLAGS += -g -Wall -Wextra
GTEST_HEADERS = $(GTEST_DIR)/include/gtest/gtest.h \
                $(GTEST_DIR)/include/gtest/internal/*.h
GTEST_SRCS_ = $(GTEST_DIR)/src/*.cc $(GTEST_DIR)/src/*.h $(GTEST_HEADERS)

gtest-all.o : $(GTEST_SRCS_)
	$(CXX) $(CPPFLAGS) -I$(GTEST_DIR) $(CXXFLAGS) -c \
            $(GTEST_DIR)/src/gtest-all.cc

gtest_main.o : $(GTEST_SRCS_)
	$(CXX) $(CPPFLAGS) -I$(GTEST_DIR) $(CXXFLAGS) -c \
            $(GTEST_DIR)/src/gtest_main.cc

gtest.a : gtest-all.o
	$(AR) $(ARFLAGS) $@ $^

gtest_main.a : gtest-all.o gtest_main.o
	$(AR) $(ARFLAGS) $@ $^

test.o : test.cpp $(GTEST_HEADERS)
	$(MAKE) $(OBJS) CFLAGS+=-DTESTING
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c test.cpp

test : test.o gtest_main.a
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(OBJS) $^ -o $@ $(LDFLAGS)

.PHONY: all clean install uninstall
