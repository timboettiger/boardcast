# Boardcast - Universal Clipboard

**Boardcast** is a lightweight, cross-platform, universal clipboard written in ANSI C (C89).
It shares plain-text clipboard contents between devices on a local network - with zero external services, zero dependencies, and zero encryption.

Why ANSI C? So it runs basically everywhere, from modern systems to legacy machines (including Classic Mac OS), making it handy for vintage Macintosh setups too.

> **Version:** 0.3.1
> **License:** MIT
> **Author:** Tim Böttiger
> **Homepage:** https://github.com/timboettiger/boardcast

---

## Overview

Boardcast uses a simple **hub ↔ leaf** design:

- **Hub**
  Central server that also mirrors its own local clipboard to the network. It can advertise itself via UDP broadcast for auto-discovery.
- **Leaf**
  Connects to a hub and syncs clipboard text changes. Two ways to start:
  - **Direct:** `boardcast leaf://IP:PORT` connects to the given hub.
  - **Discovery:** `boardcast leaf` listens for UDP beacons and auto-joins the first valid hub it hears.

The implementation is single-threaded, uses BSD sockets, and is one C source file.

---

## Features

- Cross-platform: macOS, Linux (Wayland/X11), Windows, Classic Mac OS
- Portable ANSI C (C89) - **no external libs**
- **Auto-discovery** of hubs via UDP broadcast (configurable)
- **Auto-reconnect** with exponential backoff (`-r N`)
- **Text-only** sync (no images/files)
- **No encryption** (intended for trusted local networks)
- One tiny C file + portable Makefile
- Helpful **debug** mode; **verbose** mode surfaces user messages via the clipboard

---

## Build Instructions

### Clipboard backends

| Platform        | Clipboard backend             |
|-----------------|-------------------------------|
| macOS           | `pbcopy` / `pbpaste`          |
| Linux (Wayland) | `wl-copy` / `wl-paste`        |
| Linux (X1l)     | `xclip`                       |
| Windows         | Win32 Clipboard (CF_TEXT)     |
| Classic Mac OS  | Scrap Manager (`'TEXT'`)      |

### Building

Auto-detect (recommended):

```bash
make
```

Explicit targets:

```bash
make darwin     # macOS
make linux      # Linux / POSIX
make mingw      # Windows (MinGW)
make msvc       # Windows (MSVC)
```

Override toolchain/flags:

```bash
CC=clang CFLAGS="-O0 -g" make linux
```

Clean:

```bash
make clean
```

---

## Usage

```bash
boardcast [--debug|-d] [--verbose|-v] [--reconnect|-r N] [--cast|-c]
          [ hub://IP:PORT | leaf://IP:PORT | leaf | --help|-h | --version ]
```

### Behavior

- No URI → start as **hub** on `hub://0.0.0.0:0` (random port on all interfaces).
  The hub mirrors its own clipboard and prints its ID and connect URL.
- `hub://IP:PORT` → start hub bound to `IP:PORT`. If `--cast` is enabled (default), it periodically advertises itself via UDP.
- `leaf://IP:PORT` → start **leaf**, connect to the hub, and auto-reconnect on failure.
- `leaf` → **discovery mode**: wait for a hub broadcast and auto-connect to the first valid hub.

### Options

| Option                   | Description                                                                 |
|--------------------------|-----------------------------------------------------------------------------|
| `-d`, `--debug`          | Print detailed diagnostics to stderr                                        |
| `-v`, `--verbose`        | Post user-facing messages **via the clipboard** instead of the console      |
| `-r N`, `--reconnect N`  | Max reconnect attempts (default: 10)                                        |
| `-c`, `--cast`           | Enable/disable UDP hub broadcast (default: disabled)                        |
| `-h`, `--help`           | Show help and exit                                                          |
| `--version`              | Print version and exit                                                      |

### Examples

| Command                              | Description                                          |
|--------------------------------------|------------------------------------------------------|
| `boardcast`                          | Start a hub on all interfaces (random port)          |
| `boardcast hub://0.0.0.0:33654`      | Start hub on port 33654                              |
| `boardcast hub://192.168.1.123:0`    | Start hub on a specific interface (random port)      |
| `boardcast leaf://192.168.1.1:33654` | Connect a leaf directly to an existing hub           |
| `boardcast leaf`                     | Discovery mode: wait for hub broadcast and auto-join |
| `boardcast -d -v -r 20 --cast`       | Debug + verbose, 20 reconnect attempts, broadcast on |

---

## IDs & Handshake

- **Sender IDs (ID):** 16-bit values. The **hub** chooses its own ID at startup and **assigns** a random unique ID to each connecting leaf. Leaves do **not** self-generate IDs.
- **JOIN → HELO:**
  A leaf sends `JOIN` (system) with **no payload**.
  The hub replies with `HELO` carrying the assigned **2-byte ID (big-endian)** in the payload.
  After `HELO`, the leaf prints its ID (hex). The hub prints its own ID on startup.

---

## Discovery (UDP broadcast)

- **Port:** `53701/udp`
- **Beacon (from hub):**

```
BOARDCAST v1 <ip> <port>

```

- **Interval:** every 5 seconds (default), while `--cast` is enabled.
- **Leaf (discovery mode):** listens on UDP `53701` and connects to the first valid hub it hears.

---

## Protocol (Wire format v2)

All messages are sent over TCP and have this frame layout:

| Byte(s) | Name             | Description                                                                 |
|---------|------------------|-----------------------------------------------------------------------------|
| 0       | `ver/flags`      | High nibble: protocol version (`PROTO_VER`). Low nibble: flags (`bit0=SYS`).|
| 0       | `type/os`        | High nibble: message type (`MT_*`). Low nibble: OS code (see below).        |
| 1..2    | `sender_ID`      | 16-bit big-endian sender ID.                                                |
| 3..5    | `payload_len`    | 24-bit big-endian payload length (0...16777215 bytes)                       |
| 6..N    | `payload`        | Up to 255 bytes, followed by a single `0x00` pad byte.                      |

**Flags**
- `FLAG_SYS` (bit 0 of low nibble in byte 0): system/control message

**Message types (examples)**
- `MT_JOIN`  (SYS) : Leaf → Hub, payload length = 0
- `MT_HELO`  (SYS) : Hub → Leaf, payload = **2 bytes** (assigned ID, big-endian)
- `MT_PAYLOAD`     : Clipboard text (up to 255 bytes)
- `MT_OKOK`  (SYS) : Optional ACK; payload = ASCII checksum (hex) of the last payload
- `MT_UPDT`, `MT_IDNT`, `MT_QUIT`, `MT_RKEY`, `MT_PKEY` reserved/implemented as needed

**OS code (low nibble of byte 1)**
- Linux = 1, Classic Mac = 5, macOS = 6, Windows = 10 (low-nibble stored)

**Notes**
- Fields that formerly duplicated the sender in the payload now use **payload length = 0** because `sender_ID` lives in the header.
- The hub rebroadcasts received `MT_PAYLOAD` to all **other** leaves.
- Leaves ignore self-echoes via local state and can `ACK` via `MT_OKOK`.

---

## Hub & Leaf Behavior

- **Hub**
  - Prints its own **ID** and a **connect URL** at startup.
  - Mirrors its local clipboard to connected leaves.
  - Rebroadcasts leaf `MT_PAYLOAD` messages to all other leaves.
  - Sends UDP discovery beacons while `--cast` is enabled.

- **Leaf**
  - Prints its assigned **ID** (hex) after `HELO`.
  - Watches local clipboard and sends changes via `MT_PAYLOAD`.
  - On incoming `MT_PAYLOAD`, writes to the local clipboard and ACKs with `MT_OKOK` (checksum).
  - Auto-reconnects with exponential backoff (configurable via `-r`).

- **Verbose mode (`-v`)**
  - When not in debug, user-facing notices (e.g., “connection lost”, clipboard errors) are posted **into the clipboard** so you see them even without a terminal.

---

## Limitations

- **Plain text only** (no rich text or images)
- **No encryption or authentication** → use only on trusted local networks
- **Per-message payload limit: 255 bytes** (current v2 frame format)
  > Longer clipboard texts will be truncated by the current implementation.

---

## License

Boardcast - Universal Clipboard
(C) Copyright 2025 Tim Böttiger

Released under the **MIT License**. See `LICENSE` for details.
