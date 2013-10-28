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
	rm -f commotion-service-manager *.o

.PHONY: all clean install uninstall
