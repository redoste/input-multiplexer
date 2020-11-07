CFLAGS:=-Wall -Wextra -Wstrict-prototypes -Wpedantic -Werror -pipe -fPIE -fstack-protector-all $(shell pkg-config --cflags libevdev) -Ilibhydrogen
LFLAGS:=-Wl,-z,relro -Wl,-z,now -pie $(shell pkg-config --libs libevdev) -lpthread libhydrogen/libhydrogen.a

ifeq ($(DEBUG), 1)
	CFLAGS+=-O0 -g
else
	CFLAGS+=-O2 -D_FORTIFY_SOURCE=2
	LFLAGS+=-s
endif

.PHONY: all
all: controlled controller keygen

libhydrogen/libhydrogen.a: libhydrogen/Makefile
	make -C libhydrogen lib

%: %.c
	$(CC) $< $(CFLAGS) $(LFLAGS) -o $@

controlled: controlled.c controlled.config.h libhydrogen/libhydrogen.a
controller: controller.c controller.config.h libhydrogen/libhydrogen.a
keygen: keygen.c libhydrogen/libhydrogen.a

.PHONY: clean
clean:
	-rm controlled
	-rm controller
	-rm keygen
