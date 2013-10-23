CFLAGS+=-g
LDFLAGS+=-lserval-crypto -lavahi-core -lavahi-common -luci
OBJS=util.o commotion-service-manager.o
DEPS=Makefile commotion-service-manager.h debug.h util.h uci-utils.h

MAKELINE=$(CC) $(CFLAGS) -o commotion-service-manager $(OBJS) $(LDFLAGS)

all: commotion-service-manager

%.o: %.c $(DEPS)
	$(CC) -fPIC -c -o $@ $< $(CFLAGS)

commotion-service-manager: $(DEPS) $(OBJS)
	$(MAKELINE)

linux: $(DEPS) $(OBJS) uci-utils.o
	$(MAKELINE) -DUSE_UCI -DUSESYSLOG -DUCIPATH="\"/opt/luci-commotion/etc/config\""

openwrt: $(DEPS) $(OBJS) uci-utils.o
	$(MAKELINE) -DUSE_UCI -DOPENWRT

clean:
	rm -f commotion-service-manager *.o

.PHONY: all clean linux openwrt
