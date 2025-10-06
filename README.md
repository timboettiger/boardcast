# Boardcast - Universal Clipboard

**Boardcast** is a lightweight, cross-platform, universal clipboard written in ANSI C (C89).
It shares plain-text clipboard contents between devices on a local network - with zero external services, zero dependencies, and zero encryption (to keep it fast on slow systems).

Why ANSI C? So it runs basically everywhere, from modern systems to legacy machines (including Classic Mac OS), making it handy for vintage Macintosh setups too.

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

## System Services (systemd and launchd)

Boardcast can be installed and managed as a background system service on Linux (using **systemd**) and macOS (using **launchd**).
This setup allows the Hub and Leaf to start automatically at boot and run continuously in the background.

---

### Service Behavior Summary

| Platform  | Role  | Startup Command                                   | Discovery  | Enabled by Default |
|-----------|-------|---------------------------------------------------|------------|--------------------|
| Linux     | Hub   | `boardcast --cast hub://0.0.0.0:33654`            | Broadcasts | Yes                |
| Linux     | Leaf  | `boardcast leaf`                                  | Auto-join  | Optional           |
| macOS     | Hub   | `/usr/local/bin/boardcast --cast hub://...`       | Broadcasts | Yes                |
| macOS     | Leaf  | `/usr/local/bin/boardcast leaf`                   | Auto-join  | Optional           |

---

### Security Considerations

Boardcast runs as a non-privileged user (`nobody` by default).
It communicates over plain TCP/UDP within a trusted LAN. Do **not** expose Hub or Leaf services to public networks.
Restrict access using local firewalls or private VLANs where appropriate.

---

### systemd (Linux)

#### Installation and Management

If you installed Boardcast via `make install`, both units are automatically placed in `/etc/systemd/system/`.
You can enable and start them with:

```bash
sudo systemctl daemon-reload
sudo systemctl enable boardcast-hub.service
sudo systemctl enable boardcast-leaf.service
sudo systemctl start boardcast-hub.service
sudo systemctl start boardcast-leaf.service
```

To check service status:

```bash
systemctl status boardcast-hub.service
systemctl status boardcast-leaf.service
```

To stop or disable:

```bash
sudo systemctl stop boardcast-hub.service
sudo systemctl stop boardcast-leaf.service
sudo systemctl disable boardcast-hub.service
sudo systemctl disable boardcast-leaf.service
```

---

### launchd (macOS)

#### Installation and Management

After running `make install`, the plist files are installed under `/Library/LaunchDaemons/`.

To load and start services:

```bash
sudo launchctl load -w /Library/LaunchDaemons/com.boardcast.hub.plist
sudo launchctl load -w /Library/LaunchDaemons/com.boardcast.leaf.plist
```

To unload or disable:

```bash
sudo launchctl unload -w /Library/LaunchDaemons/com.boardcast.hub.plist
sudo launchctl unload -w /Library/LaunchDaemons/com.boardcast.leaf.plist
```

#### Logs

By default, both daemons write logs to `/var/log/boardcast-*.out` and `/var/log/boardcast-*.err`.
You can also monitor output using the system log stream:

```bash
log stream --predicate 'process == "boardcast"'
```

---

## Docker Support

Boardcast can be deployed and run as a self-contained container without requiring any local installation.
The provided `Dockerfile` (located at `packaging/docker/`) supports both **Hub** and **Leaf** roles.

### Building the Images

```bash
# Build the Hub image (with UDP broadcast enabled)
docker build -t boardcast:hub --build-arg ROLE=hub -f packaging/docker/Dockerfile .

# Build the Leaf image (Discovery mode)
docker build -t boardcast:leaf --build-arg ROLE=leaf -f packaging/docker/Dockerfile .
```

### Running Containers

#### Hub

```bash
docker run -d --name boardcast-hub --net=host boardcast:hub
```

**Behavior:**
- Starts a Hub on all interfaces (`hub://0.0.0.0:33654`)
- Periodically broadcasts its presence via UDP (`--cast`, Port `53701`)
- Accepts incoming connections from Leaf nodes

#### Leaf

```bash
docker run -d --name boardcast-leaf --net=host boardcast:leaf
```

**Behavior:**
- Starts in discovery mode (`leaf`)
- Listens for UDP Hub broadcasts and connects automatically

**Note:** UDP broadcast and auto-discovery require `--net=host`. Without host networking, the Leaf cannot discover Hubs automatically.

### Environment Variables

| Variable     | Default  | Description                                 |
|--------------|----------|---------------------------------------------|
| `ROLE`       | `hub`    | Defines the container role: `hub` or `leaf` |

Example:

```bash
docker run -d --net=host -e ROLE=leaf boardcast:leaf
```

### Logs

To follow container logs:

```bash
docker logs -f boardcast-hub
```

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
  The hub mirrors its own clipboard and prints its ID and connect URI.
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

## Developer Insights

---

### IDs & Handshake

- **Sender IDs (ID):** 16-bit values. The **hub** chooses its own ID at startup and **assigns** a random unique ID to each connecting leaf. Leaves do **not** self-generate IDs.
- **JOIN → HELO:**
  A leaf sends `JOIN` (system) with **no payload**.
  The hub replies with `HELO` carrying the assigned **2-byte ID (big-endian)** in the payload.
  After `HELO`, the leaf prints its ID (hex). The hub prints its own ID on startup.

---

### Discovery (UDP broadcast)

- **Port:** `53701/udp`
- **Beacon (from hub):**

```
BOARDCAST v1 <ip> <port>

```

- **Interval:** every 5 seconds (default), while `--cast` is enabled.
- **Leaf (discovery mode):** listens on UDP `53701` and connects to the first valid hub it hears.

---

### Protocol (Wire format v1)

All messages are sent over TCP and have this frame layout:

| Byte(s) | Name           | Description                                                                 |
|---------|----------------|-----------------------------------------------------------------------------|
| 0       | `ver/flags`    | High nibble: protocol version (`PROTO_VER`). Low nibble: flags (`bit0=SYS`).|
| 1       | `type/os`      | High nibble: message type (`MT_*`). Low nibble: OS code (see below).        |
| 2 & 3    | `sender_ID`   | 16-bit big-endian sender ID (shown in hex)                                  |
| 4 - 6    | `payload_len` | 24-bit big-endian payload length (0...16777215 bytes)                       |
| 7...N    | `payload`     | Up to 255 bytes, followed by a single `0x00` pad byte.                      |

**Flags**

| Flag       | Bit | Byte                 | Description               |
|------------|-----|----------------------|---------------------------|
| `FLAG_SYS` | 0   | Low nibble in byte 0 | system/control message    |

**Message Types**

| Message Type | Category | Payload                  | Description                      |
|--------------|----------|--------------------------|----------------------------------|
| `MT_PAYLOAD` | `DATA`   | **n bytes** (plain text) | only data transport              |
| `MT_JOIN`    | `COMM`   | `NULL`                   | requests hub join and leaf id    |
| `MT_HELO`    | `COMM`   | **2 bytes** (big-endian) | ACK of JOIN, contains leaf id    |
| `MT_OKOK`    | `COMM`   | checksum                 | hex checksum of the last payload |
| `MT_UPDT`    | `COMM`   | `NULL`                   | requests current clipboard data  |
| `MT_IDNT`    | `COMM`   | `NULL`                   | requests id of hub/leaf          |
| `MT_QUIT`    | `COMM`   | `NULL`                   | controlled closing of socket     |
| `MT_RKEY` *  | `COMM`   | `NULL`                   | requests public key of hub/leaf  |
| `MT_PKEY` *  | `COMM`   | `NULL`                   | contains public key of hub/leaf  |

> *) reserved for future enhancements/implemented as needed

**OS code**

(stored in low nibble of byte 1)

| ID   | OS         | Description                          |
|------|------------|--------------------------------------|
| `01` | Linux      | Generic Linux Distribution           |
| `02` | -          | -                                    |
| `03` | -          | -                                    |
| `04` | -          | -                                    |
| `05` | Mac OS     | Classic Mac OS for Macintosh < V.10  |
| `06` | MacOS/OS-X | MacOS >= V.10                        |
| `07` | -          | -                                    |
| `08` | -          | -                                    |
| `09` | -          | -                                    |
| `10` | Windows    | Generic Windows Version              |
| `11` | -          | -                                    |
| `12` | -          | -                                    |
| `13` | -          | -                                    |
| `14` | -          | -                                    |
| `15` | -          | -                                    |

Space for future OS codes is reserved, in case Boardcast is ever ported to other platforms or system specialities have to be distinguished.

**Notes**
- The hub rebroadcasts received `MT_PAYLOAD` to all **other** leaves. (The sender leaf does not get its own message back.)
- Leaves ignore self-echoes via local state and can `ACK` via `MT_OKOK`.

---

### Protocol Sequence and Timing Diagram

**General Overview**

```
Time ->
HUB                                   LEAF
 |                                      |
 |-- UDP beacon --> (every 5s)          |  listen UDP:53701
 |                                      |
 |<------- picks first beacon ----------|
 |                                      |
 |<---------- TCP CONNECT --------------|
 |                                      |
 |<--------- SYS: MT_JOIN --------------|
 |-------- SYS: MT_HELO(LID) ---------->|
 |                                      |  set LID
 |                                      |
 |== Clipboard change on LEAF ==>
 |<-------- MT_PAYLOAD(DATA) -----------|
 |-------- SYS: MT_OKOK(cksum) -------->|
 |                                      |
 |== Clipboard change on HUB ==>
 |-- MT_PAYLOAD(DATA) --> all leaves -->|
```

**Discovery (UDP Broadcast)**

```
Time ->
HUB                             LEAF
 |                               |
 |-- every 5s: UDP "BOARDCAST" --|  (listen on UDP :53701)
 |                               |
 |------------------------------>|  picks first valid hub (IP,PORT)
 |                               |
 ```

**Join / Handshake (TCP)**

```
Time ->
LEAF                                 HUB
 |                                    |
 |---- TCP CONNECT ------------------>|
 |                                    |
 |---- SYS: MT_JOIN (no payload) ---->|
 |                                    |
 |<--- SYS: MT_HELO (SID[2B]) --------|
 |                                    |
 |  set g_sid := assigned SID         |
 |                                    |
 ```

**Clipboard Payload Flow (Rebroadcast)**

```
Time ->
LEAF A                      HUB                      LEAF B, LEAF C, [...]
  |                          |                         |       |       |
  |---- MT_PAYLOAD(DATA) --->|                         |       |       |
  |<-- SYS: MT_OKOK(cksum) --|                         |       |       |
  |                          |--- MT_PAYLOAD(DATA) --->|       |       |
  |                          |<-- SYS: MT_OKOK(cksum) -|       |       |
  |                          |                         |       |       |
  |                          |--- MT_PAYLOAD(DATA) ----------->|       |
  |                          |<-- SYS: MT_OKOK(cksum) ---------|       |
  |                          |                         |       |       |
```

**Reconnect with Exponential Backoff**

```
t=0s   t=1s   t=2s   t=4s   t=8s   ...   (cap ~60s)
 |------X------X------X------X------X----> attempts (max N)
         \      \      \      \
          wait   wait   wait   wait
```

---

## Hub & Leaf Behavior

- **Hub**
  - Prints its own **ID** and a **connect URI** at startup.
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
- **Per-message payload limit: 16.777.215 bytes** (current v1 frame format)
  > Longer clipboard texts will be truncated by the current implementation.

---

## License

Boardcast - Universal Clipboard
(C) Copyright 2025 Tim Böttiger

Released under the **MIT License**. See `LICENSE` for details.
