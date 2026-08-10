CC ?= cc
CFLAGS ?= -O2
CPPFLAGS += $(shell pkg-config --cflags gstreamer-rtsp-server-1.0)
CFLAGS += -std=c11 -Wall -Wextra -Werror -Wpedantic
LDLIBS += $(shell pkg-config --libs gstreamer-rtsp-server-1.0)

.PHONY: all clean

all: rtsp-pull-server rtsp-load-reader

rtsp-pull-server: rtsp_pull_server.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LDLIBS) -o $@

rtsp-load-reader: rtsp_load_reader.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LDLIBS) -o $@

clean:
	$(RM) rtsp-pull-server rtsp-load-reader
