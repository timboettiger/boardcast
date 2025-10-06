# Makefile for Boardcast — Universal Clipboard (ANSI C, no crypto)
# Cross‑platform: macOS (Darwin), Linux, Windows (MinGW/MSYS) and Windows (MSVC)
#
# Usage examples:
#   make                # auto-detect host OS
#   make darwin         # force macOS build
#   make linux          # force Linux build
#   make mingw          # force Windows MinGW build (boardcast.exe)
#   make msvc           # force Windows MSVC build (boardcast.exe)
#   make clean
#
# Overridable vars:
#   CC=clang CFLAGS="-O0 -g" make darwin
#   CC=x86_64-w64-mingw32-gcc make mingw
#
# Notes:
# - Builds **all .c files** in the directory and links them together.
# - On Windows/MinGW we link -lws2_32; on MSVC we link ws2_32.lib.
# - Runtime deps for clipboard backends are detected at runtime (pbcopy/wl-copy/xclip).

# ---- Files ----
SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)

BIN_DARWIN := boardcast
BIN_LINUX  := boardcast
BIN_MINGW  := boardcast.exe
BIN_MSVC   := boardcast.exe

# ---- Common flags (C89, warnings) ----
CFLAGS_COMMON := -std=c89 -Wall -Wextra -O2
# Define this to help some old headers behave (optional):
CFLAGS_COMMON += -D_POSIX_C_SOURCE=200112L

# ---- Host auto-detect ----
UNAME_S := $(shell uname -s 2>/dev/null || echo Unknown)

# Default target picks based on host
ifeq ($(UNAME_S),Darwin)
  DEFAULT := darwin
  BIN := $(BIN_DARWIN)
  LDLIBS :=
else ifeq ($(UNAME_S),Linux)
  DEFAULT := linux
  BIN := $(BIN_LINUX)
  LDLIBS :=
else ifneq (,$(findstring MINGW,$(UNAME_S)))
  DEFAULT := mingw
  BIN := $(BIN_MINGW)
  LDLIBS := -lws2_32
else ifneq (,$(findstring MSYS,$(UNAME_S)))
  DEFAULT := mingw
  BIN := $(BIN_MINGW)
  LDLIBS := -lws2_32
else
  DEFAULT := linux
  BIN := $(BIN_LINUX)
  LDLIBS :=
endif

.PHONY: all darwin linux mingw msvc clean debug release

all: $(DEFAULT)

# Generic link rule (Darwin/Linux/MinGW via GCC/Clang)
$(BIN): $(OBJS)
	$(CC) $(CFLAGS_COMMON) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

# Compile rule
%.o: %.c
	$(CC) $(CFLAGS_COMMON) $(CFLAGS) -c -o $@ $<

# ---- OS-forced targets just set BIN/LDLIBS and reuse generic link ----
darwin: BIN=$(BIN_DARWIN)
darwin: LDLIBS=
darwin: $(BIN)

linux: BIN=$(BIN_LINUX)
linux: LDLIBS=
linux: $(BIN)

mingw: BIN=$(BIN_MINGW)
mingw: LDLIBS=-lws2_32
mingw: $(BIN)

# ---- Windows (MSVC) ----
# Use: make msvc CC=cl
# Notes:
#  - cl uses different flags: /TC (treat as C), /W3 warnings, /O2 optimize
#  - Link with ws2_32.lib
#  - We compile each .c to .obj, then link.

# Convert .c -> .obj for MSVC
MSVC_OBJS := $(SRCS:.c=.obj)

msvc:
	@if command -v cl >/dev/null 2>&1; then \
	  echo "Building with MSVC (cl)"; \
	  for f in $(SRCS); do \
	    cl /nologo /TC /W3 /O2 $(MSVC_FLAGS) /c $$f || exit 1; \
	  done; \
	  link /nologo /OUT:$(BIN_MSVC) $(MSVC_OBJS) ws2_32.lib; \
	else \
	  echo "cl (MSVC) not found. Use Developer Command Prompt or set CC=cl."; \
	  exit 1; \
	fi

# ---- Convenience ----
debug:
	$(MAKE) CFLAGS="-O0 -g" $(DEFAULT)

release:
	$(MAKE) CFLAGS="-O2" $(DEFAULT)

clean:
	$(RM) $(OBJS) $(MSVC_OBJS) $(BIN_DARWIN) $(BIN_LINUX) $(BIN_MINGW) $(BIN_MSVC)
