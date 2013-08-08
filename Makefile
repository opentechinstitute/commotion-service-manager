CFLAGS=-I../serval-dna -I../serval-crypto
LDFLAGS=-lserval-crypto

client-core: core-browse-services.c escape.h escape.c concat.h concat.c
	$(CC) $(CFLAGS) -g -o avahi-client core-browse-services.c escape.c concat.c -lavahi-core -lavahi-common -I/usr/local/include -luci $(LDFLAGS)
client-client: client-browse-services.c
	$(CC) $(CFLAGS) -o client-client client-browse-services.c -lavahi-client
concat_test: concat.c escape.c escape.h
	$(CC) $(CFLAGS) -o concat_test concat.c escape.c -lavahi-core -lavahi-common
clean:
	rm -f a.out core avahi-client client-client concat_test client escape
