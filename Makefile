# Makefile for Executable Network Packets (ENP)
# Supports Linux and macOS.  Use CMakeLists.txt for Windows / MSVC.

CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -Wpedantic -O2 -std=c11
LDFLAGS ?=

# Directories
SRCDIR   = .
INCDIR   = include
COREDIR  = core
NETDIR   = net
WASMDIR  = wasm
UTILSDIR = utils
THIRDDIR = third_party/wasm3

BUILDDIR = build

TARGET   = $(BUILDDIR)/enp

# ---------------------------------------------------------------------------
# wasm3 integration
# Fetch wasm3 with:  make wasm3-fetch
# Then build with:   make ENP_WITH_WASM3=1
# ---------------------------------------------------------------------------
WASM3_DIR      = $(THIRDDIR)
WASM3_SRC      = $(WASM3_DIR)/source
WASM3_SRCFILES = $(wildcard $(WASM3_SRC)/m3_*.c)

ifdef ENP_WITH_WASM3
    WASM_SRCS = wasm/enp_wasm.c $(WASM3_SRCFILES)
    CFLAGS   += -DENP_WITH_WASM3 -I$(WASM3_SRC)
    LDFLAGS  += -lm
else
    WASM_SRCS = wasm/enp_wasm.c
endif

# ---------------------------------------------------------------------------
# Source files
# ---------------------------------------------------------------------------
SRCS = main.c \
       $(COREDIR)/enp_packet.c \
       $(NETDIR)/enp_server.c \
       $(NETDIR)/enp_client.c \
       $(WASM_SRCS) \
       $(UTILSDIR)/enp_logger.c

OBJS = $(patsubst %.c,$(BUILDDIR)/%.o,$(SRCS))

# ---------------------------------------------------------------------------
# Default target
# ---------------------------------------------------------------------------
.PHONY: all clean wasm3-fetch

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Built: $@"

$(BUILDDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -I$(INCDIR) -c -o $@ $<

# ---------------------------------------------------------------------------
# Fetch wasm3 source (requires git)
# ---------------------------------------------------------------------------
wasm3-fetch:
	@if [ -d "$(WASM3_SRC)" ]; then \
	    echo "wasm3 already present at $(WASM3_SRC)"; \
	else \
	    echo "Fetching wasm3 ..."; \
	    git clone --depth=1 --branch v0.5.0 \
	        https://github.com/wasm3/wasm3.git $(WASM3_DIR); \
	fi

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------
clean:
	rm -rf $(BUILDDIR)
