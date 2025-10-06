# Boardcast — Universal Clipboard

**Boardcast** is a lightweight, cross-platform, universal clipboard written in ANSI C (C89).
It allows plain-text clipboard contents to be shared seamlessly between devices on a local network — without external services, dependencies, or encryption layers.

Why is it written in ANSI C? Well, because I wanted it to run on everything from modern systems to legacy hardware (including Classic Mac OS) to support clipboard sharing an Macintosh devices, too.

---

## Overview

Boardcast implements a simple **hub-and-leaf** architecture:

- **Hub:** Acts as the central clipboard server and also mirrors its own local clipboard.
- **Leaf:** Connects to a hub and synchronizes clipboard text changes. Leafs can be started in two modes:
  - **Direct mode:** A leaf started with `leaf://IP:PORT` connects directly to the specified hub.
  - **Discovery mode:** A leaf started using `leaf` (without parameters) listens for UDP broadcast advertisements from available hubs and connects automatically.

Clipboard synchronization is performed using a minimal, length-prefixed protocol over TCP.
The implementation is single-threaded, fully self-contained, and based on standard BSD sockets.

---

## Features

- Cross-platform: macOS, Linux, Windows, and Classic Mac OS
- Written in portable ANSI C (C89) — no dependencies
- Automatic hub discovery via UDP broadcast
- Reconnects automatically with exponential backoff
- Text-only synchronization (no images or files)
- No encryption (intended for trusted local networks)
- Works with legacy compilers and systems
- One C source file and a portable Makefile

---

## Build Instructions

### Requirements

| Platform        | Clipboard Backend        |
|-----------------|--------------------------|
| macOS           | `pbcopy` / `pbpaste`     |
| Linux (Wayland) | `wl-copy` / `wl-paste`   |
| Linux (X11)     | `xclip`                  |
| Windows         | Win32 Clipboard API      |
| Classic Mac OS  | Scrap Manager (`'TEXT'`) |

### Building

Auto-detect build (recommended):

```bash
make
```

Build explicitly for a target platform:

```bash
make darwin     # macOS
make linux      # Linux / POSIX
make mingw      # Windows (MinGW)
make msvc       # Windows (MSVC)
```

You can override compiler and flags:

```bash
CC=clang CFLAGS="-O0 -g" make linux
```

Clean build artifacts:

```bash
make clean
```

---

## Usage

```bash
boardcast [--debug|-d] [--verbose|-v] [--reconnect|-r N] [--cast|-c 0|1]
           [ hub://IP:PORT | leaf://IP:PORT | leaf | --help|-h ]
```

### Examples

| Command                              | Description                                       |
|--------------------------------------|---------------------------------------------------|
| `boardcast`                          | Start a new hub (on all interfaces, random port)  |
| `boardcast hub://0.0.0.0:33654`      | Start hub on port 33654                           |
| `boardcast leaf://192.168.1.1:33654` | Connect to existing hub                           |
| `boardcast leaf`                     | Wait for hub broadcast and auto-connect           |
| `boardcast -d -v -r 20 --cast 1`     | Verbose mode, 20 reconnect attempts, broadcast on |

---

## Options

| Option                  | Description                               |
|-------------------------|-------------------------------------------|
| `-d`, `--debug`         | Print diagnostic output                   |
| `-v`, `--verbose`       | Post user-facing errors via clipboard     |
| `-r N`, `--reconnect N` | Set reconnect attempt limit (default: 10) |
| `-c 0|1`, `--cast 0|1`  | Enable/disable UDP broadcast (default: 1) |
| `-h`, `--help`          | Display usage help                        |

---

## Protocol Overview

Each clipboard update is sent as a TCP message:

| Field   | Size     | Description                            |
|---------|----------|----------------------------------------|
| Length  | 4 bytes  | Big-endian total length (ID + payload) |
| ID      | 16 bytes | Sender identifier                      |
| Payload | Variable | Clipboard text (UTF-8)                 |

The **hub** rebroadcasts all updates (except to the origin sender).
Clients ignore updates from their own ID to prevent loops.

### Discovery

Hubs periodically broadcast UDP packets to `255.255.255.255:53701`:

```
BOARDCAST v1 <ip> <port> <idhex>\n
```

Leaves in discovery mode listen for these broadcasts and auto-connect.

---

## Limitations

- Transfers **plain text only** (no rich text or images)
- No encryption or authentication — use on trusted networks only!
- Max message size: 64 KiB

---

## License

Boardcast - Universal Clipboard
(C) Copyright 2025 Tim Böttiger
<timboettiger@gmail.com>

Released under the **MIT License**.
See the included `LICENSE` file for full terms.
