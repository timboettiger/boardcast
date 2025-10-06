# Makefile for Boardcast — Universal Clipboard (ANSI C, no crypto)
# Cross‑platform: macOS (Darwin), Linux, Windows (MinGW/MSYS) and Windows (MSVC)
#
# Usage examples:
#   make                # auto-detect host OS
#   make darwin         # force macOS build
#   make linux          # force Linux build
#   make mingw          # force Windows MinGW build (boardcast.exe)
#   make msvc           # force Windows MSVC build (boardcast.exe)
#   make install        # install binary + services (systemd/launchd)
#   make uninstall      # remove binary + services
#   make docker-hub     # build Docker image for hub
#   make docker-leaf    # build Docker image for leaf
#   make clean
#
# Overridable vars:
#   CC=clang CFLAGS="-O0 -g" make darwin
#   CC=x86_64-w64-mingw32-gcc make mingw
#
# Notes:
# - Builds all .c files in the current directory and links them together (single-binary layout).
# - On Windows/MinGW link -lws2_32; on MSVC link ws2_32.lib.
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

# ---- Install and packaging paths ----
PREFIX        ?= /usr/local
DESTDIR       ?=
SYSTEMD_DIR   ?= /etc/systemd/system
LAUNCHD_DIR   ?= /Library/LaunchDaemons
SERVICES_DIR  ?= packaging/systemd
LAUNCHD_SRC   ?= packaging/launchd
DOCKER_FILE   ?= packaging/docker/Dockerfile
DOCKER_TAG    ?= boardcast

.PHONY: all darwin linux mingw msvc clean debug release \
        install install-bin install-services uninstall \
        enable-linux start-linux enable-macos docker-hub docker-leaf

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

# ---- Installation ----
install: $(DEFAULT) install-bin install-services

install-bin: $(BIN)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m755 $(BIN) $(DESTDIR)$(PREFIX)/bin/boardcast

install-services:
	@uname_s=$$(uname -s); \
	if [ "$$uname_s" = "Linux" ]; then \
	  if [ -f "$(SERVICES_DIR)/boardcast-hub.service" ]; then \
	    install -D -m644 "$(SERVICES_DIR)/boardcast-hub.service"  "$(DESTDIR)$(SYSTEMD_DIR)/boardcast-hub.service"; \
	  fi; \
	  if [ -f "$(SERVICES_DIR)/boardcast-leaf.service" ]; then \
	    install -D -m644 "$(SERVICES_DIR)/boardcast-leaf.service" "$(DESTDIR)$(SYSTEMD_DIR)/boardcast-leaf.service"; \
	  fi; \
	  systemctl daemon-reload || true; \
	  echo "Installed systemd units (hub/leaf)"; \
	elif [ "$$uname_s" = "Darwin" ]; then \
	  install -d "$(DESTDIR)$(LAUNCHD_DIR)"; \
	  if [ -f "$(LAUNCHD_SRC)/com.boardcast.hub.plist" ]; then \
	    install -m644 "$(LAUNCHD_SRC)/com.boardcast.hub.plist"  "$(DESTDIR)$(LAUNCHD_DIR)/com.boardcast.hub.plist"; \
	  fi; \
	  if [ -f "$(LAUNCHD_SRC)/com.boardcast.leaf.plist" ]; then \
	    install -m644 "$(LAUNCHD_SRC)/com.boardcast.leaf.plist" "$(DESTDIR)$(LAUNCHD_DIR)/com.boardcast.leaf.plist"; \
	  fi; \
	  echo "Installed launchd plists (hub/leaf)"; \
	else \
	  echo "Unsupported OS for service install"; \
	fi

enable-linux:
	systemctl enable boardcast-hub.service || true
	systemctl enable boardcast-leaf.service || true

start-linux:
	systemctl start boardcast-hub.service || true
	systemctl start boardcast-leaf.service || true

enable-macos:
	launchctl load -w /Library/LaunchDaemons/com.boardcast.hub.plist || true
	launchctl load -w /Library/LaunchDaemons/com.boardcast.leaf.plist || true

uninstall:
	@uname_s=$$(uname -s); \
	if [ "$$uname_s" = "Linux" ]; then \
	  systemctl disable boardcast-hub.service 2>/dev/null || true; \
	  systemctl disable boardcast-leaf.service 2>/dev/null || true; \
	  rm -f "$(SYSTEMD_DIR)/boardcast-hub.service" "$(SYSTEMD_DIR)/boardcast-leaf.service"; \
	  systemctl daemon-reload || true; \
	elif [ "$$uname_s" = "Darwin" ]; then \
	  launchctl unload -w /Library/LaunchDaemons/com.boardcast.hub.plist 2>/dev/null || true; \
	  launchctl unload -w /Library/LaunchDaemons/com.boardcast.leaf.plist 2>/dev/null || true; \
	  rm -f "$(LAUNCHD_DIR)/com.boardcast.hub.plist" "$(LAUNCHD_DIR)/com.boardcast.leaf.plist"; \
	fi
	rm -f "$(PREFIX)/bin/boardcast"

# ---- Docker helpers ----
docker-hub:
	docker build -t $(DOCKER_TAG):hub --build-arg ROLE=hub -f $(DOCKER_FILE) .

docker-leaf:
	docker build -t $(DOCKER_TAG):leaf --build-arg ROLE=leaf -f $(DOCKER_FILE) .

# ---- Convenience ----
debug:
	$(MAKE) CFLAGS="-O0 -g" $(DEFAULT)

release:
	$(MAKE) CFLAGS="-O2" $(DEFAULT)

clean:
	$(RM) $(OBJS) $(MSVC_OBJS) $(BIN_DARWIN) $(BIN_LINUX) $(BIN_MINGW) $(BIN_MSVC)
