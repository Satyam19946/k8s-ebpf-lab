CLANG   = clang
CC      = gcc
CFLAGS  = -O2 -g -target bpf -D__TARGET_ARCH_x86 \
          -I/usr/include/x86_64-linux-gnu
LDFLAGS = -lbpf

PROGRAMS = tc_drop tc_drop_map mycni xdp_lb tc_policy

.PHONY: all clean $(PROGRAMS)

all: $(PROGRAMS)

tc_drop:
	$(CLANG) $(CFLAGS) -c tc_drop/tc_drop.bpf.c -o tc_drop/tc_drop.bpf.o
	$(CC) -O2 -g -o tc_drop/tc_drop_loader \
		tc_drop/tc_drop_loader.c $(LDFLAGS)

tc_drop_map:
	$(CLANG) $(CFLAGS) -c tc_drop_map/tc_drop_map.bpf.c \
		-o tc_drop_map/tc_drop_map.bpf.o
	$(CC) -O2 -g -o tc_drop_map/tc_drop_map_loader \
		tc_drop_map/tc_drop_map_loader.c $(LDFLAGS)

mycni:
	$(CC) -O2 -g -o mycni/mycni_binary mycni/mycni.c

xdp_lb:
	$(CLANG) $(CFLAGS) -c xdp_lb/xdp_lb.bpf.c -o xdp_lb/xdp_lb.bpf.o
	$(CC) -O2 -g -o xdp_lb/xdp_lb_loader \
		xdp_lb/xdp_lb_loader.c $(LDFLAGS)

tc_policy:
	$(CLANG) $(CFLAGS) -I tc_policy -c tc_policy/tc_policy.bpf.c \
		-o tc_policy/tc_policy.bpf.o
	$(CC) -O2 -g -I tc_policy -o tc_policy/tc_policy_loader \
		tc_policy/tc_policy_loader.c $(LDFLAGS)

clean:
	find . -name "*.bpf.o" -delete
	find . -name "*_loader" -delete
	rm -f mycni/mycni