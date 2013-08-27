CFLAGS=-I../serval-dna -I../serval-crypto -g
LDFLAGS=-lserval-crypto -lavahi-core -lavahi-common -luci
OBJS=uci-utils.o util.o commotion-service-manager.o
DEPS=Makefile commotion-service-manager.h debug.h

all: commotion-service-manager

%.o: %.c $(DEPS)
	$(CC) -fPIC -c -o $@ $< $(CFLAGS)

commotion-service-manager: $(DEPS) $(OBJS)
	$(CC) $(CFLAGS) -o commotion-service-manager $(OBJS) $(LDFLAGS)

clean:
	rm -f commotion-service-manager *.o

.PHONY: all clean
