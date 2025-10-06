/*
* Boardcast — Universal Clipboard — ANSI C (C89)
*
* Binary name: boardcast
*
* Usage:
*   boardcast [--debug|-d] [--verbose|-v] [--reconnect|-r N] [--cast|-c 0|1]
*             [ hub://IP:PORT | leaf://IP:PORT | leaf | --help|-h ]
*
* Examples:
*   boardcast                                   # HUB on 0.0.0.0:0 (random port), also acts as local leaf
*   boardcast hub://0.0.0.0:33654               # HUB bound to all IFs on port 33654
*   boardcast hub://192.168.1.123:0             # HUB bound to a specific IF on random port
*   boardcast leaf://192.168.1.1:33654          # LEAF joining an explicit HUB
*   boardcast leaf                              # LEAF discovery: wait for HUB broadcast and auto-join
*   boardcast -d -v -r 20 --cast 1              # debug+verbose, 20 reconnect attempts, enable hub broadcast
*
* Behavior:
* - No URI → start as HUB (and local leaf) on hub://0.0.0.0:0 (random port on all IFs).
* - hub://IP:PORT → start HUB bound to IP and PORT (0 = random). If --cast/-c is enabled
*   (default: enabled), HUB periodically broadcasts its service via UDP.
* - leaf://IP:PORT → start LEAF and connect to the HUB with auto-reconnect.
* - "leaf" (no IP:PORT) → LEAF enters discovery mode, waits for a HUB broadcast, and connects
*   to the first valid HUB it hears.
*
* IDs & Protocol (current):
* - Peers use a 16-bit sender ID (SID). The HUB chooses its own SID at startup and assigns a
*   unique random SID to each connecting LEAF. A LEAF does NOT self-generate a SID.
* - LEAF sends JOIN (system) without payload; HUB replies with HELO carrying the assigned
*   2-byte SID (big-endian) in the payload. After receiving HELO, the LEAF prints its SID.
*   The HUB prints its own SID at startup.
*
* Wire frame (v2):
*   byte0: 4b version (PROTO_VER), 4b flags (bit0 = system/FLAG_SYS)
*   byte1: 4b message type (MT_*), 4b OS code (lower nibble)
*   byte2..3: sender SID (big-endian 16-bit)
*   byte4: payload length (0..255)
*   byte5..: payload bytes (if any), followed by a single 0x00 pad byte
*
* Message types (examples):
*   - MT_JOIN  (SYS)  : LEAF → HUB, payload length = 0
*   - MT_HELO  (SYS)  : HUB  → LEAF, payload = 2 bytes (assigned SID)
*   - MT_PAYLOAD(DATA): clipboard content (text), length up to 255 bytes
*   - MT_OKOK  (SYS)  : optional ACK, payload = ASCII checksum of last payload
*   - MT_UPDT/MT_IDNT/MT_QUIT etc. as implemented
*
* Notes on payloads:
* - Messages that previously carried only the sender ID in the payload now use payload length = 0,
*   since the sender SID is part of the header.
*
* HUB behavior:
* - Rebroadcasts received MT_PAYLOAD to all other leaves (header’s sender SID identifies origin).
* - Periodically sends UDP discovery beacons if --cast/-c is enabled.
*
* LEAF behavior:
* - Ignores its own clipboard echoes (handled by local state), posts ACK (MT_OKOK) with checksum.
* - Prints the assigned 16-bit SID (hex) after receiving HELO.
*
* Discovery (cast):
* - UDP broadcast on DISC_PORT (default 53701).
* - Beacon payload: "BOARDCAST v1 <ip> <port>\n"
* - HUB sends every CAST_INTERVAL seconds. A LEAF in discovery mode listens and dials
*   the first valid HUB it hears.
*
* Implementation notes:
* - Pure ANSI C (C89). Single source file. No threads. No encryption.
* - Networking: BSD sockets (GUSI on classic Mac OS for classic builds).
* - Clipboard backends:
*     CLASSIC_MAC: Scrap Manager ('TEXT')
*     _WIN32     : Win32 Clipboard (CF_TEXT)
*     POSIX      : pbpaste/pbcopy (Darwin), wl-clipboard (Wayland), xclip (X11)
*/

/* ====== Includes (ANSI C) ====== */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>

/* Platform detection */
#if defined(__APPLE__) && !defined(__MACOS_CLASSIC__)
#define PLATFORM_DARWIN 1
#endif

#if defined(macintosh) || defined(__MWERKS__) || defined(__MC68K__) || defined(__POWERPC__) || defined(__MACOS_CLASSIC__)
#define CLASSIC_MAC 1
#endif

/* --- Sockets --- */
#if defined(_WIN32)
#  include <winsock2.h>
#  include <ws2tcpip.h>
typedef SOCKET sock_t;
#  define CLOSESOCK(s) closesocket(s)
#  define sock_errno() WSAGetLastError()
#else
#  include <unistd.h>
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <netdb.h>
typedef int sock_t;
#  define INVALID_SOCKET (-1)
#  define SOCKET_ERROR (-1)
#  define CLOSESOCK(s) close(s)
#  define sock_errno() errno
#endif

#include <sys/time.h>

/* Classic Mac Scrap Manager */
#ifdef CLASSIC_MAC
#  include <Types.h>
#  include <Scrap.h>
#endif

/* ====== Config ====== */
#define BOARDCAST_VERSION "0.2.1 (beta)"
#define BOARDCAST_YEAR    "2025"
#define BOARDCAST_AUTHOR  "Tim Böttiger"
#define BOARDCAST_LICENSE "MIT License"
#define BOARDCAST_URL     "https://github.com/timboettiger/boardcast"

#define MAX_BUF         65536
#define HEARTBEAT_SEC   2
#define MAX_CLIENTS     32
#define DISC_PORT       53701
#define CAST_INTERVAL   5    /* seconds */

/* ====== Sender-ID (SID) ====== */
/* 16-bit IDs, 0x0000 reserved (no ID yet) */
typedef unsigned short sid_t;
#define SID_NONE  ((sid_t)0x0000)

/* ====== Globals ====== */
static int g_debug = 0;
static int g_verbose = 0;       /* if set and not debug: client posts messages via clipboard */
static int g_reconnect_max = 10;/* default for -r */
static int g_cast = 1;          /* hub broadcasts service by default (-c 0 to disable) */
static sid_t g_sid = SID_NONE;  /* LEAF: erst nach HELO; HUB: eigene SID direkt beim Start */

#define logdbg1(a)         do { if (g_debug) { fprintf(stderr, "[debug] %s\n", (a)); } } while(0)
#define logdbg2(fmt,a)     do { if (g_debug) { fprintf(stderr, "[debug] "); fprintf(stderr, (fmt), (a)); fprintf(stderr, "\n"); } } while(0)
#define logdbg3(fmt,a,b)   do { if (g_debug) { fprintf(stderr, "[debug] "); fprintf(stderr, (fmt), (a), (b)); fprintf(stderr, "\n"); } } while(0)
#define print_local_address(port) do { (void)(port); } while(0)

/* ====== Utility ====== */
static unsigned long checksum(const unsigned char *p, size_t n) { unsigned long c=5381UL; size_t i; for(i=0;i<n;++i) c=((c<<5)+c)+(unsigned long)p[i]; return c; }

static void print_sid_hex(sid_t sid) { fprintf(stdout, "%04X\n", (unsigned)sid); }

static void msleep(unsigned ms){
#if defined(_WIN32)
    Sleep(ms);
#else
    struct timeval tv; tv.tv_sec = (long)(ms/1000U); tv.tv_usec = (long)((ms%1000U)*1000U); select(0,NULL,NULL,NULL,&tv);
#endif
}

/* ====== Frame v2: 1b ver/flags, 1b type/os, 2b sender_sid, 1b payload_len, payload[0..255], 0x00 pad ====== */
#define PROTO_VER 1
#define FLAG_SYS  0x01

enum MsgType { MT_PAYLOAD=0, MT_OKOK=1, MT_JOIN=2, MT_HELO=3, MT_QUIT=4, MT_UPDT=5, MT_IDNT=6, MT_RKEY=7, MT_PKEY=8 };

/* OS codes (lower nibble of byte1) */
#define OS_LINUX          1
#define OS_MAC_CLASSIC    5
#define OS_MAC_OSX        6
#define OS_WINDOWS       10

static unsigned char detect_os_nibble(void) {
#ifdef CLASSIC_MAC
    return OS_MAC_CLASSIC & 0x0F; /* 0x5 */
#elif defined(_WIN32)
    return OS_WINDOWS & 0x0F;     /* 0xA */
#elif defined(PLATFORM_DARWIN)
    return OS_MAC_OSX & 0x0F;     /* 0x6 */
#else
    return OS_LINUX & 0x0F;       /* 0x1 */
#endif
}

/* Debug print decoded frame fields with readable type and OS */
static void debug_print_frame(const char *who, unsigned char ver, unsigned char flags,
                              unsigned char mtype, unsigned char oscode,
                              sid_t sender_sid, const char *payload, unsigned char plen)
{
    const char *type_name = "????";
    const char *os_name = "?UNKNOWN?";
    if (!g_debug) return;

    /* Message type names */
    switch (mtype) {
        case MT_PAYLOAD: type_name = "DATA"; break;
        case MT_OKOK:    type_name = "OKOK"; break;
        case MT_JOIN:    type_name = "JOIN"; break;
        case MT_HELO:    type_name = "HELO"; break;
        case MT_QUIT:    type_name = "QUIT"; break;
        case MT_UPDT:    type_name = "UPDT"; break;
        case MT_IDNT:    type_name = "IDNT"; break;
        case MT_RKEY:    type_name = "RKEY"; break;
        case MT_PKEY:    type_name = "PKEY"; break;
    }

    /* OS code names (lower nibble of byte1) */
    switch (oscode) {
        case OS_LINUX:        os_name = "Linux"; break;
        case OS_MAC_CLASSIC:  os_name = "Macintosh"; break;
        case OS_MAC_OSX:      os_name = "MacOS"; break;
        case OS_WINDOWS:      os_name = "Windows"; break;
    }

    fprintf(stderr,
        "[debug] %s (V%u:%04X) %s %s:%s using %u bytes",
        who,
        (unsigned)ver,
        (unsigned)sender_sid,
        os_name,
        (flags & FLAG_SYS) ? "SAID" : "SENT",
        type_name,
        (unsigned)plen
    );

    if (payload && plen > 0) {
        size_t i, max = 96;
        fprintf(stderr, ": \"");

        /* --- FIX: show 2-byte payloads as big-endian hex (e.g. "3AF2") --- */
        if (plen == 2) {
            unsigned sid = ((unsigned char)payload[0] << 8) | (unsigned char)payload[1];
            fprintf(stderr, "%04X", sid);
        } else {
            for (i = 0; i < plen && i < max; ++i) {
                unsigned char c = (unsigned char)payload[i];
                if (c >= 32 && c <= 126)
                    fputc(c, stderr);
                else if (c == '\n')
                    fputs("\\n", stderr);
                else if (c == '\r')
                    fputs("\\r", stderr);
                else if (c == '\t')
                    fputs("\\t", stderr);
                else
                    fprintf(stderr, "\\x%02X", (unsigned)c);
            }
            if (plen > max)
                fprintf(stderr, "...(%u bytes)", (unsigned)plen);
        }

        fprintf(stderr, "\"");
    }
    fprintf(stderr, "\n");
}

static int send_all(sock_t s, const unsigned char *buf, size_t len) {
    size_t sent = 0; while (sent < len) { int n = send(s, (const char*)buf + sent, (int)(len - sent), 0); if (n <= 0) return -1; sent += (size_t)n; } return 0;
}
static int recv_all(sock_t s, unsigned char *buf, size_t len) {
    size_t recvd = 0; while (recvd < len) { int n = recv(s, (char*)buf + recvd, (int)(len - recvd), 0); if (n <= 0) return -1; recvd += (size_t)n; } return 0;
}

static int send_frame(sock_t s, int is_system, unsigned char mtype, unsigned char oscode,
                      sid_t sender_sid, const char *payload, unsigned char plen)
{
    unsigned char hdr[5];
    unsigned char pad = 0x00;

    /* widen and clamp */
    unsigned int p = (unsigned int)plen;
    if (p > 255U) p = 255U;

    hdr[0] = (unsigned char)(((PROTO_VER & 0x0F) << 4) | ((is_system ? FLAG_SYS : 0) & 0x0F));
    hdr[1] = (unsigned char)(((mtype & 0x0F) << 4) | (oscode & 0x0F));
    hdr[2] = (unsigned char)((sender_sid >> 8) & 0xFF);
    hdr[3] = (unsigned char)(sender_sid & 0xFF);
    hdr[4] = (unsigned char)p;

    if (send_all(s, hdr, 5) != 0) return -1;
    if (p > 0 && payload) {
        if (send_all(s, (const unsigned char*)payload, (size_t)p) != 0) return -1;
    }
    if (send_all(s, &pad, 1) != 0) return -1;

    if (g_debug) debug_print_frame(">>", PROTO_VER, (is_system?FLAG_SYS:0), mtype, oscode, sender_sid, payload, (unsigned char)p);
    return 0;
}

static int recv_frame(sock_t s, unsigned char *ver, unsigned char *flags,
                    unsigned char *mtype, unsigned char *oscode,
                    sid_t *sender_sid_out, char **payload_out, unsigned char *plen_out)
{
    unsigned char hdr[5], pad = 0; char *pl = NULL; unsigned char plen = 0; sid_t ssid = SID_NONE;
    if (recv_all(s, hdr, 5) != 0) return -1;
    *ver   = (hdr[0] >> 4) & 0x0F;
    *flags = (hdr[0] & 0x0F);
    *mtype = (hdr[1] >> 4) & 0x0F;
    *oscode= (hdr[1] & 0x0F);
    ssid   = (sid_t)(((unsigned)hdr[2] << 8) | (unsigned)hdr[3]);
    plen   = hdr[4];
    if (plen > 0) { pl = (char*)malloc(plen); if (!pl) return -1; if (recv_all(s, (unsigned char*)pl, plen) != 0) { free(pl); return -1; } }
    if (recv_all(s, &pad, 1) != 0) { if (pl) free(pl); return -1; }
    if (payload_out) *payload_out = pl; else if (pl) free(pl);
    if (plen_out) *plen_out = plen;
    if (sender_sid_out) *sender_sid_out = ssid;
    if (g_debug) debug_print_frame("<<", *ver, *flags, *mtype, *oscode, ssid, pl, plen);
    return 0;
}

/* ====== Clipboard abstraction ====== */
static char *clip_read(size_t *out_len);
static int   clip_write(const char *data, size_t len);
static void notify_user_clip(const char *msg){ if (!g_debug && g_verbose && msg) { clip_write(msg, strlen(msg)); } }

#ifdef CLASSIC_MAC
/* Classic Mac OS */
static char *clip_read(size_t *out_len) {
    Handle h; long scrapSize = 0; long offset = 0; OSType theType = 'TEXT';
    *out_len = 0; h = NewHandle(0); if (!h) return NULL;
    scrapSize = GetScrap(h, theType, &offset);
    if (scrapSize <= 0) { DisposeHandle(h); return NULL; }
    HLock(h);
    { char *buf = (char*)malloc((size_t)scrapSize); if (!buf) { HUnlock(h); DisposeHandle(h); return NULL; }
    memcpy(buf, *h, (size_t)scrapSize); *out_len = (size_t)scrapSize; HUnlock(h); DisposeHandle(h); return buf; }
}
static int clip_write(const char *data, size_t len) { OSErr err; ZeroScrap(); err = PutScrap((long)len, 'TEXT', (Ptr)data); return (err == noErr) ? 0 : -1; }
#elif defined(_WIN32)
/* Windows */
#  include <windows.h>
static char *clip_read(size_t *out_len) {
    HANDLE h; char *p; SIZE_T n; *out_len=0; if(!OpenClipboard(NULL)) return NULL; h=GetClipboardData(CF_TEXT);
    if(!h){ CloseClipboard(); return NULL; } p=(char*)GlobalLock(h); if(!p){ CloseClipboard(); return NULL; }
    n=strlen(p); { char *buf=(char*)malloc(n); if(!buf){ GlobalUnlock(h); CloseClipboard(); return NULL; }
    memcpy(buf,p,n); *out_len=(size_t)n; GlobalUnlock(h); CloseClipboard(); return buf; }
}
static int clip_write(const char *data, size_t len){ HGLOBAL h; char *p; if(!OpenClipboard(NULL)) return -1; EmptyClipboard(); h=GlobalAlloc(GMEM_MOVEABLE,len+1); if(!h){ CloseClipboard(); return -1; } p=(char*)GlobalLock(h); memcpy(p,data,len); p[len]='\0'; GlobalUnlock(h); SetClipboardData(CF_TEXT,h); CloseClipboard(); return 0; }
#else
/* POSIX/macOS/Wayland/X11 via CLI tools */
static int can_run(const char *cmd)
{ char buf[256]; FILE *fp; int ok = 0; snprintf(buf, sizeof(buf), "which %s 2>/dev/null", cmd); fp = popen(buf, "r"); if (fp) { if (fgets(buf, (int)sizeof(buf), fp) != NULL) { ok = 1; } pclose(fp);} return ok; }
static int env_is(const char *k,const char *v){ const char *e=getenv(k); if(!e||!v) return 0; return strcmp(e,v)==0; }
static int is_wayland(void){ const char *wd=getenv("WAYLAND_DISPLAY"); if(wd&&wd[0]) return 1; if(env_is("XDG_SESSION_TYPE","wayland")) return 1; return 0; }
static char *read_via_popen(const char *cmd,size_t *out_len){ FILE *fp=popen(cmd,"r"); char *buf=NULL; size_t cap=0,n=0; int ch; *out_len=0; if(!fp) return NULL; while((ch=fgetc(fp))!=EOF){ if(n+1>cap){ size_t ncap=cap?cap*2:1024; char *tmp=(char*)realloc(buf,ncap); if(!tmp){ free(buf); pclose(fp); return NULL;} buf=tmp; cap=ncap;} buf[n++]=(char)ch;} if(buf) *out_len=n; pclose(fp); return buf; }
static int write_via_popen(const char *cmd,const char *data,size_t len){ FILE *fp=popen(cmd,"w"); size_t w; if(!fp) return -1; w=fwrite(data,1,len,fp); pclose(fp); return (w==len)?0:-1; }
static char *clip_read(size_t *out_len){
# ifdef PLATFORM_DARWIN
    if(can_run("pbpaste")) return read_via_popen("pbpaste",out_len);
# endif
    if(is_wayland() && can_run("wl-paste")) return read_via_popen("wl-paste --no-newline 2> /dev/null",out_len);
    if(can_run("xclip")) return read_via_popen("xclip -selection clipboard -out",out_len);
    *out_len=0; return NULL;
}
static int clip_write(const char *data,size_t len){
# ifdef PLATFORM_DARWIN
    if(can_run("pbcopy")) return write_via_popen("pbcopy",data,len);
# endif
    if(is_wayland() && can_run("wl-copy")) return write_via_popen("wl-copy",data,len);
    if(can_run("xclip")) return write_via_popen("xclip -selection clipboard -in",data,len);
    return -1;
}
#endif

/* ====== Sockets helpers ====== */
static int startup_sockets(void){
#if defined(_WIN32)
    WSADATA wsa; if(WSAStartup(MAKEWORD(2,2),&wsa)==0) return 0; if(WSAStartup(MAKEWORD(1,1),&wsa)==0) return 0; return -1;
#else
    return 0;
#endif
}
static void cleanup_sockets(void){
#if defined(_WIN32)
    WSACleanup();
#endif
}
static int set_reuse(sock_t s){ int on=1; return setsockopt(s,SOL_SOCKET,SO_REUSEADDR,(char*)&on,sizeof(on)); }
static int set_broadcast(sock_t s){ int on=1; return setsockopt(s,SOL_SOCKET,SO_BROADCAST,(char*)&on,sizeof(on)); }

static int parse_hostport(const char *s,char *host,size_t hostsz,unsigned short *port){ const char *p=strchr(s,':'); if(!p) return -1; if((size_t)(p-s)>=hostsz) return -1; memcpy(host,s,(size_t)(p-s)); host[p-s]='\0'; *port=(unsigned short)atoi(p+1); return 0; }

static int listen_on(const char *ip, unsigned short port, unsigned short *out_port, sock_t *out_sock) {
    sock_t s = socket(AF_INET, SOCK_STREAM, 0); struct sockaddr_in a; unsigned long ina;
    if (s == INVALID_SOCKET) return -1;
    set_reuse(s);
    memset(&a, 0, sizeof(a)); a.sin_family = AF_INET;
    if (ip && ip[0]) { ina = inet_addr(ip); if (ina == 0xFFFFFFFFUL) { a.sin_addr.s_addr = htonl(INADDR_ANY); } else { a.sin_addr.s_addr = ina; } }
    else { a.sin_addr.s_addr = htonl(INADDR_ANY); }
    a.sin_port = htons(port);
    if (bind(s, (struct sockaddr*)&a, sizeof(a)) == SOCKET_ERROR) { CLOSESOCK(s); return -1; }
    if (listen(s, MAX_CLIENTS) == SOCKET_ERROR) { CLOSESOCK(s); return -1; }
    { socklen_t alen = sizeof(a); if (getsockname(s, (struct sockaddr*)&a, &alen) == 0) *out_port = ntohs(a.sin_port); else *out_port = 0; }
    *out_sock = s; return 0;
}

static sock_t accept_one(sock_t ls){ struct sockaddr_in ca; socklen_t clen=sizeof(ca); return accept(ls,(struct sockaddr*)&ca,&clen); }

static sock_t connect_host(const char *host, unsigned short port) {
    sock_t s = socket(AF_INET, SOCK_STREAM, 0); struct sockaddr_in a; struct hostent *he; unsigned long ina;
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    memset(&a, 0, sizeof(a)); a.sin_family = AF_INET; a.sin_port   = htons(port);
    ina = inet_addr(host);
    if (ina != 0xFFFFFFFFUL) { a.sin_addr.s_addr = ina; }
    else { he = gethostbyname(host); if (!he || !he->h_addr_list || !he->h_addr_list[0]) { CLOSESOCK(s); return INVALID_SOCKET; } memcpy(&a.sin_addr, he->h_addr_list[0], (size_t)sizeof(struct in_addr)); }
    if (connect(s, (struct sockaddr*)&a, sizeof(a)) == SOCKET_ERROR) { CLOSESOCK(s); return INVALID_SOCKET; }
    return s;
}

static int guess_local_ip(char *out, size_t outsz){ char hostname[256]; if(gethostname(hostname,sizeof(hostname))==0){ struct hostent *he=gethostbyname(hostname); if(he && he->h_addr_list && he->h_addr_list[0]){ struct in_addr in; memcpy(&in, he->h_addr_list[0], (size_t)he->h_length); strncpy(out, inet_ntoa(in), outsz-1); out[outsz-1]='\0'; return 0; } } strncpy(out, "127.0.0.1", outsz); out[outsz-1]='\0'; return -1; }

/* ====== Discovery (UDP cast) ====== */
static int hub_cast_socket(sock_t *out){ sock_t u=socket(AF_INET,SOCK_DGRAM,0); if(u==INVALID_SOCKET) return -1; set_broadcast(u); *out=u; return 0; }
static int leaf_listen_socket(sock_t *out){ sock_t u=socket(AF_INET,SOCK_DGRAM,0); struct sockaddr_in a; if(u==INVALID_SOCKET) return -1; memset(&a,0,sizeof(a)); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_ANY); a.sin_port=htons(DISC_PORT); if(bind(u,(struct sockaddr*)&a,sizeof(a))==SOCKET_ERROR){ CLOSESOCK(u); return -1; } *out=u; return 0; }

static void hub_broadcast(sock_t ucast, const char *adv_ip, unsigned short adv_port){ struct sockaddr_in b; char msg[256]; memset(&b,0,sizeof(b)); b.sin_family=AF_INET; b.sin_port=htons(DISC_PORT); b.sin_addr.s_addr=htonl(INADDR_BROADCAST); snprintf(msg,sizeof(msg),"BOARDCAST v1 %s %u\n", adv_ip, (unsigned)adv_port); sendto(ucast, msg, (int)strlen(msg), 0, (struct sockaddr*)&b, sizeof(b)); }

static int leaf_wait_for_hub(char *out_ip, size_t out_ipsz, unsigned short *out_port, unsigned timeout_sec){
    sock_t u; if(leaf_listen_socket(&u)!=0) return -1; {
        fd_set rf; struct timeval tv; int nf; for(;;){ FD_ZERO(&rf); FD_SET(u,&rf); tv.tv_sec=timeout_sec; tv.tv_usec=0; nf=select((int)u+1,&rf,NULL,NULL,&tv); if(nf>0 && FD_ISSET(u,&rf)){
                char buf[512]; struct sockaddr_in from; socklen_t flen=sizeof(from); int n=recvfrom(u,buf,sizeof(buf)-1,0,(struct sockaddr*)&from,&flen); if(n>0){ char magic[16]; char ip[64]; unsigned port=0; buf[n]='\0'; if(sscanf(buf, "%15s v1 %63s %u", magic, ip, &port)==3){ if(strcmp(magic,"BOARDCAST")==0){ size_t nn = strlen(ip); if (nn >= out_ipsz) nn = out_ipsz - 1; memcpy(out_ip, ip, nn); out_ip[nn] = '\0'; *out_port=(unsigned short)port; CLOSESOCK(u); return 0; } } }
            } else if(nf==0){ CLOSESOCK(u); return -1; }
        }
    } }

/* ====== Server (hub) ====== */
struct client { sock_t s; int alive; sid_t sid; };

static sid_t generate_random_sid(void)
{
    unsigned seed = (unsigned)time(NULL);
#ifndef CLASSIC_MAC
    seed ^= (unsigned)getpid();
#endif
#if defined(_WIN32)
    seed ^= (unsigned)GetTickCount();
#else
    {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        seed ^= (unsigned)(tv.tv_usec);
    }
#endif
    srand(seed);

    return (sid_t)((rand() & 0xFFFF));
}

/* Return nonzero if SID is already in use by any active client */
static int sid_in_use(struct client *cli, sid_t sid) {
    int i;
    if (sid == SID_NONE || sid == g_sid) return 1; /* reserve 0 */
    for (i = 0; i < MAX_CLIENTS; ++i) {
        if (cli[i].alive && cli[i].sid == sid) return 1;
    }
    return 0;
}

static void print_payload(const char *data, size_t len) {
    size_t i, max = 48; if (!g_verbose || !data || len == 0) return; fprintf(stderr, ": \"");
    for (i = 0; i < len && i < max; ++i) { unsigned char c = (unsigned char)data[i]; if (c >= 32 && c <= 126) fputc(c, stderr); else if (c == '\n') fputs("\\n", stderr); else if (c == '\r') fputs("\\r", stderr); else if (c == '\t') fputs("\\t", stderr); else fprintf(stderr, "?"); }
    if (len > max) fprintf(stderr, "...(%lu bytes)", (unsigned long)len);
    fprintf(stderr, "\"\n");
}

static int run_server_bind_ip(const char *bind_ip, unsigned short bind_port){
    sock_t ls; unsigned short port=0; struct client cli[MAX_CLIENTS]; int i; char *last=NULL; size_t last_len=0; unsigned long last_ck=0; sock_t ucast=INVALID_SOCKET; unsigned last_cast = 0; char adv_ip[64]; unsigned char oscode = detect_os_nibble();

    for(i=0;i<MAX_CLIENTS;++i){ cli[i].s=INVALID_SOCKET; cli[i].alive=0; cli[i].sid=SID_NONE; }

    for(i=0;i<MAX_CLIENTS;++i){
        cli[i].s = INVALID_SOCKET;
        cli[i].alive = 0;
        cli[i].sid = SID_NONE;
    }

    if(listen_on(bind_ip, bind_port, &port, &ls)!=0){ fprintf(stderr,"listen failed\n"); return 1; }

    g_sid = generate_random_sid();

    if(!bind_ip || !bind_ip[0] || strcmp(bind_ip,"0.0.0.0")==0)
        guess_local_ip(adv_ip,sizeof(adv_ip));
    else {
        strncpy(adv_ip, bind_ip, sizeof(adv_ip)-1);
        adv_ip[sizeof(adv_ip)-1]='\0';
    }

    fprintf(stdout,"Boardcast hub started with id %04X.\nConnect using url leaf://%s:%u\n",
            (unsigned)g_sid, adv_ip, (unsigned)port);
    fflush(stdout);

    if(g_cast){ if(hub_cast_socket(&ucast)!=0) { if(g_debug) fprintf(stderr,"[debug] cannot open cast socket\n"); } }

    { size_t blen_seed=0; char *buf_seed=clip_read(&blen_seed); if (buf_seed && blen_seed>0) { last = buf_seed; last_len = blen_seed; last_ck = checksum((const unsigned char*)last,last_len); if (g_debug) fprintf(stderr, "[debug] hub: seeded last from clipboard (%lu bytes)\n", (unsigned long)last_len); } }

    for(;;){
        fd_set rfds; struct timeval tv; int nf, maxfd=(int)ls; unsigned now_sec;
        FD_ZERO(&rfds); FD_SET(ls,&rfds);
        for(i=0;i<MAX_CLIENTS;++i){ if(cli[i].alive){ FD_SET(cli[i].s,&rfds); if((int)cli[i].s>maxfd) maxfd=(int)cli[i].s; } }
        now_sec = (unsigned)time(NULL);
        if (g_cast && ucast!=INVALID_SOCKET && (last_cast==0 || now_sec - last_cast >= CAST_INTERVAL)) { hub_broadcast(ucast, adv_ip, port); last_cast = now_sec; }

        /* Hub clipboard -> broadcast to all leaves */
        {
            char *buf=NULL; size_t blen=0; unsigned long ck; buf=clip_read(&blen);
            if(buf && blen>0){ ck=checksum((const unsigned char*)buf,blen);
                if(ck!=last_ck || blen!=last_len || (last && memcmp(buf,last,blen)!=0)){
                    if (g_debug) { fprintf(stderr, "[debug] hub: clipboard changed, broadcasting %lu bytes", (unsigned long)blen); print_payload(buf, blen); }
                    for(i=0;i<MAX_CLIENTS;++i){ if(cli[i].alive){ unsigned char plen = (unsigned char)((blen>255)?255:blen); (void)send_frame(cli[i].s, 0, MT_PAYLOAD, oscode, g_sid, buf, plen); } }
                    if (last) free(last);
                    last = buf; last_len = blen; last_ck = ck; buf = NULL;
                }
            } else if(!buf && g_verbose && !g_debug){ notify_user_clip("error accessing local clipboard"); }
            if(buf) free(buf);
        }

        tv.tv_sec=HEARTBEAT_SEC; tv.tv_usec=0; nf=select(maxfd+1,&rfds,NULL,NULL,&tv); if(nf<0) continue;

        if(FD_ISSET(ls,&rfds)){
            sock_t ns=accept_one(ls);
            if(ns!=INVALID_SOCKET){ int slotted=0; for(i=0;i<MAX_CLIENTS;++i){ if(!cli[i].alive){ cli[i].s=ns; cli[i].alive=1; cli[i].sid=SID_NONE; slotted=1; if(g_debug) fprintf(stderr,"[debug] hub: unknown client detected (awaiting JOIN)\n"); break; } } if(!slotted) CLOSESOCK(ns); }
        }

        for(i=0;i<MAX_CLIENTS;++i){
            if(cli[i].alive && FD_ISSET(cli[i].s,&rfds)){
                unsigned char ver, flags, mtype, osr; char *pl=NULL; unsigned char plen=0; sid_t ssid=SID_NONE;
                if (recv_frame(cli[i].s, &ver, &flags, &mtype, &osr, &ssid, &pl, &plen) != 0) { if (g_debug && cli[i].sid!=SID_NONE){ fprintf(stderr,"[debug] leaf disconnected: %04X\n", (unsigned)cli[i].sid); } CLOSESOCK(cli[i].s); cli[i].alive=0; cli[i].sid=SID_NONE; if(pl) free(pl); continue; }

                if ((flags & FLAG_SYS) && mtype == MT_JOIN) {
                    /* Assign a unique SID if this client has none yet */
                    if (cli[i].sid == SID_NONE) {
                        sid_t sid_candidate;
                        do {
                            sid_candidate = generate_random_sid();
                        } while (sid_in_use(cli, sid_candidate));

                        cli[i].sid = sid_candidate;

                        if (g_debug) {
                            fprintf(stderr, "[debug] hub: assigning id %04X to new leaf\n",
                                    (unsigned)cli[i].sid);
                        }

                        /* HELO with 2-byte SID payload (big-endian), sender is HUB (g_sid) */
                        {
                            unsigned char helo[2];
                            helo[0] = (unsigned char)((cli[i].sid >> 8) & 0xFF);
                            helo[1] = (unsigned char)(cli[i].sid & 0xFF);
                            (void)send_frame(cli[i].s, 1, MT_HELO, oscode, g_sid, (const char*)helo, 2);
                        }
                    }

                    if (pl) { free(pl); pl = NULL; }
                }
                else if (!(flags & FLAG_SYS) && mtype == MT_PAYLOAD) {
                    if (pl && plen > 0) {
                        clip_write(pl, plen);
                        if (last) free(last);
                        last = pl; last_len = plen;
                        last_ck = checksum((const unsigned char*)last, last_len);
                        pl = NULL;
                        { char ackbuf[32]; sprintf(ackbuf, "%08lX", (unsigned long)last_ck); (void)send_frame(cli[i].s, 1, MT_OKOK, oscode, g_sid, ackbuf, (unsigned char)strlen(ackbuf)); }
                        { int j; for(j=0;j<MAX_CLIENTS;++j){ if(cli[j].alive && j!=i) (void)send_frame(cli[j].s, 0, MT_PAYLOAD, oscode, g_sid, last, (unsigned char)last_len); } }
                    }
                }
                else if ((flags & FLAG_SYS) && mtype == MT_UPDT) {
                    int j; for(j=0;j<MAX_CLIENTS;++j){ if(cli[j].alive && j!=i) (void)send_frame(cli[j].s, 1, MT_UPDT, oscode, g_sid, pl, plen); }
                }
                else if ((flags & FLAG_SYS) && mtype == MT_IDNT) {
                    /* Re-announce hub id; empty payload per rule (sender info only) */
                    (void)send_frame(cli[i].s, 1, MT_HELO, oscode, g_sid, NULL, 0);
                }
                else if ((flags & FLAG_SYS) && mtype == MT_QUIT) {
                    if (g_debug) fprintf(stderr, "[debug] hub: QUIT received, closing client\n");
                    CLOSESOCK(cli[i].s);
                    cli[i].alive = 0;
                    cli[i].sid = SID_NONE;
                }
                if (pl) free(pl);
            }
        }
    }

    if (last) { free(last); }
    CLOSESOCK(ls);
    if (ucast != INVALID_SOCKET) { CLOSESOCK(ucast); }
    for (i = 0; i < MAX_CLIENTS; ++i) { if (cli[i].alive) { CLOSESOCK(cli[i].s); } }
    return 0;
}

/* ====== Client (leaf) ====== */
static int run_client_once(const char *host,unsigned short port,sock_t *out_sock){ sock_t s=connect_host(host,port); if(s==INVALID_SOCKET) return -1; *out_sock=s; return 0; }

static int run_client(const char *host, unsigned short port){
    int attempts = 0; unsigned backoff = 1000; sock_t s = INVALID_SOCKET; unsigned char oscode = detect_os_nibble();
reconnect_start:
    if (attempts > 0) {
        if (attempts >= g_reconnect_max) { notify_user_clip("boardcast: reconnect attempts exhausted"); fprintf(stderr, "reconnect attempts exhausted\n"); return 1; }
        if (backoff > 60000U) { backoff = 60000U; }
        if (g_debug) { fprintf(stderr, "[debug] leaf: waiting %u seconds before retry\n", backoff / 1000); }
        msleep(backoff);
        if (backoff < 60000U) { backoff <<= 1; }
        if (g_debug) { fprintf(stderr, "[debug] leaf: trying to reconnect to hub\n"); }
    }
    if (run_client_once(host, port, &s) != 0) { if (attempts==0) notify_user_clip("boardcast: connection to hub lost"); attempts++; goto reconnect_start; }

    attempts = 0; backoff = 1000; fprintf(stdout,"[debug] leaf: connecting to hub at %s:%u.\n", host, (unsigned)port); fflush(stdout);

    /* JOIN ohne Payload, SID=0 */
    (void)send_frame(s, 1, MT_JOIN, oscode, SID_NONE, NULL, 0);

    /* Auf HELO warten (Payload=2B zugewiesene SID) */
    {
        struct timeval tv; fd_set rf; FD_ZERO(&rf); FD_SET(s,&rf); tv.tv_sec=5; tv.tv_usec=0;
        if (select((int)s+1, &rf, NULL, NULL, &tv) > 0 && FD_ISSET(s,&rf)) {
            unsigned char ver, flags, mtype, osr; char *pl=NULL; unsigned char plen=0; sid_t sender=SID_NONE;
            if (recv_frame(s, &ver, &flags, &mtype, &osr, &sender, &pl, &plen) == 0) {
                if ((flags & FLAG_SYS) && mtype == MT_HELO) {
                    if (pl && plen==2) { g_sid = (sid_t)(((unsigned char)pl[0]<<8) | (unsigned char)pl[1]); }
                    if (pl) { free(pl); pl=NULL; }
                }
            }
        }
    }


    if (g_sid!=SID_NONE) { if (g_debug) { fprintf(stdout, "[debug] leaf: joined hub, adapt id "); print_sid_hex(g_sid); } }
    else { fprintf(stderr, "[error] leaf: joining hub failed."); print_sid_hex(g_sid); }

    {
        char *last=NULL; size_t last_len=0; unsigned long last_ck=0;
        { size_t blen_seed=0; char *buf_seed=clip_read(&blen_seed); if (buf_seed && blen_seed>0) { last = buf_seed; last_len=blen_seed; last_ck=checksum((const unsigned char*)last,last_len); if (g_debug) fprintf(stderr, "[debug] leaf: seeded last from clipboard (%lu bytes)\n", (unsigned long)last_len); } }

        for(;;){
            fd_set rfds; struct timeval tv; int nf, maxfd=(int)s; char *buf=NULL; size_t blen=0; unsigned long ck;
            buf=clip_read(&blen);
            if(buf && blen>0){ ck=checksum((const unsigned char*)buf,blen);
                if(ck!=last_ck || blen!=last_len || (last && memcmp(buf,last,blen)!=0)){
                    if (g_debug) { fprintf(stderr, "[debug] leaf: clipboard changed, sending %lu bytes to hub: ", (unsigned long)blen); print_payload(buf, blen); }
                    { unsigned char plen = (unsigned char)((blen>255)?255:blen); if (send_frame(s, 0, MT_PAYLOAD, oscode, g_sid, buf, plen)!=0){ if(buf) free(buf); notify_user_clip("connection to boardcast hub lost"); break; } }
                    if (last) { free(last); } last = buf; last_len = blen; last_ck = ck; buf = NULL; blen = 0;
                }
            } else if(!buf && g_verbose && !g_debug) { notify_user_clip("error accessing local clipboard"); }
            if(buf) free(buf);

            FD_ZERO(&rfds); FD_SET(s,&rfds); tv.tv_sec=HEARTBEAT_SEC; tv.tv_usec=0; nf=select(maxfd+1,&rfds,NULL,NULL,&tv);
            if(nf>0 && FD_ISSET(s,&rfds)){
                unsigned char ver, flags, mtype, osr; char *rbuf=NULL; unsigned char rlen=0; sid_t sender=SID_NONE;
                if(recv_frame(s, &ver, &flags, &mtype, &osr, &sender, &rbuf, &rlen)!=0){ if(rbuf) free(rbuf); notify_user_clip("connection to boardcast hub lost"); break; }
                if (!(flags & FLAG_SYS) && mtype == MT_PAYLOAD) {
                    if (rbuf && rlen>0){ if (g_debug) { fprintf(stderr, "[debug] leaf: received %u bytes from hub", (unsigned)rlen); print_payload(rbuf, rlen); }
                        clip_write(rbuf, rlen);
                        if (last) free(last);
                        last = rbuf; last_len = rlen;
                        last_ck = checksum((const unsigned char*)last, last_len);
                        rbuf = NULL;
                        { char ackbuf[32]; sprintf(ackbuf, "%08lX", (unsigned long)last_ck); (void)send_frame(s, 1, MT_OKOK, oscode, g_sid, ackbuf, (unsigned char)strlen(ackbuf)); }
                    }
                }
                else if ((flags & FLAG_SYS) && mtype == MT_HELO) {
                    /* possible late/duplicate HELO without payload -> ignore */
                }
                else if ((flags & FLAG_SYS) && mtype == MT_UPDT) {
                    size_t cur_len=0; char *cur=clip_read(&cur_len); if (cur && cur_len>0) { unsigned char plen = (unsigned char)((cur_len>255)?255:cur_len); (void)send_frame(s, 0, MT_PAYLOAD, oscode, g_sid, cur, plen); } if (cur) free(cur);
                }
                else if ((flags & FLAG_SYS) && mtype == MT_IDNT) {
                    /* Re-send JOIN without payload */ (void)send_frame(s, 1, MT_JOIN, oscode, g_sid, NULL, 0);
                }
                else if ((flags & FLAG_SYS) && mtype == MT_QUIT) { break; }
                if(rbuf) free(rbuf);
            }
        }
        if (last) { free(last); }
        if (g_debug) { fprintf(stderr, "[debug] leaf: no hub connection"); }
        CLOSESOCK(s); s = INVALID_SOCKET; attempts++; goto reconnect_start;
    }
}

static int run_client_discover(void){ char ip[64]; unsigned short port=0; fprintf(stdout,"Waiting for Boardcast hub discovery on UDP %u...\n", (unsigned)DISC_PORT); fflush(stdout); if(leaf_wait_for_hub(ip,sizeof(ip),&port,60)!=0){ fprintf(stderr,"no hub discovered\n"); return 1; } fprintf(stdout,"Discovered hub at %s:%u\n", ip, (unsigned)port); return run_client(ip, port); }

/* ====== URI parsing & main ====== */
enum Mode { MODE_HUB=1, MODE_LEAF=2, MODE_LEAF_DISC=3 };

static int has_prefix(const char *s, const char *pfx){ size_t n=strlen(pfx); return strncmp(s,pfx,n)==0; }
static int parse_uri_role(const char *uri, enum Mode *mode, char *ip, size_t ipsz, unsigned short *port){ if(has_prefix(uri,"hub://")) { *mode=MODE_HUB; return parse_hostport(uri+6, ip, ipsz, port); } if(has_prefix(uri,"leaf://")) { *mode=MODE_LEAF; return parse_hostport(uri+7, ip, ipsz, port); } *mode=MODE_LEAF; return parse_hostport(uri, ip, ipsz, port); }

static void usage(const char *prog) {
    /* PLACEHOLDERS: 10 x %s  →  VERSION, YEAR, AUTHOR, LICENSE, URL, prog x5 */
    fprintf(stdout,
    "Boardcast — Universal Clipboard (no encryption)\n"
    "Version: %s\n"
    "Copyright (c) %s %s\n"
    "License: %s\n"
    "Homepage: %s\n"
    "\n"
    "Usage:\n"
    "  %s [OPTIONS] [URI]\n"
    "\n"
    "Description:\n"
    "  Synchronizes plain text via a local HUB/LEAF architecture.\n"
    "\n"
    "Options:\n"
    "  -d, --debug               Enable debug output (stderr)\n"
    "  -v, --verbose             Post user messages via clipboard instead of console\n"
    "  -r, --reconnect <N>       Number of reconnect attempts (default: 10)\n"
    "  -c, --cast <0|1>          Enable or disable UDP hub broadcast (default: 1)\n"
    "  -h, --help                Show this help text and exit\n"
    "\n"
    "Examples:\n"
    "  %s                          Start a hub on all interfaces (random port)\n"
    "  %s hub://0.0.0.0:33654      Start hub on port 33654\n"
    "  %s leaf://192.168.1.1:33654 Join an existing hub\n"
    "  %s leaf                     Wait for hub broadcast and auto-connect\n"
    "  %s -d -v -r 20 --cast 1     Debug + verbose mode, with discovery enabled\n"
    "\n"
    "Notes:\n"
    "  * SIDs are 16-bit hex IDs; the HUB assigns them.\n"
    "  * LEAF prints its SID after HELO. HUB prints its SID at startup.\n"
    "\n",
    BOARDCAST_VERSION,
    BOARDCAST_YEAR,
    BOARDCAST_AUTHOR,
    BOARDCAST_LICENSE,
    BOARDCAST_URL,
    prog, prog, prog, prog, prog, prog
    );
}

int main(int argc, char **argv){ int i; int show_help=0; char *uri=NULL; char ip[256]; unsigned short port=0; enum Mode mode=MODE_HUB; char bind_ip[256]; unsigned short bind_port=0;
    if(startup_sockets()!=0){ fprintf(stderr,"socket init failed\n"); return 1; }

    for(i=1;i<argc;++i){
        if(!strcmp(argv[i],"--debug") || !strcmp(argv[i],"-d")) g_debug=1;
        else if(!strcmp(argv[i],"--verbose") || !strcmp(argv[i],"-v")) g_verbose=1;
        else if(!strcmp(argv[i],"--reconnect") || !strcmp(argv[i],"-r")) { if(i+1<argc){ g_reconnect_max=atoi(argv[++i]); if(g_reconnect_max<1) g_reconnect_max=1; } }
        else if(!strcmp(argv[i],"--cast") || !strcmp(argv[i],"-c")) { if(i+1<argc){ g_cast=atoi(argv[++i])?1:0; } }
        else if(!strcmp(argv[i], "--version")) { fprintf(stdout, "Boardcast %s\n", BOARDCAST_VERSION); cleanup_sockets(); return 0; }
        else if(!strcmp(argv[i],"--help") || !strcmp(argv[i],"-h")) show_help=1;
        else uri=argv[i];
    }
    if(show_help){ usage(argv[0]); cleanup_sockets(); return 0; }

    if(uri==NULL){ strcpy(bind_ip, "0.0.0.0"); bind_port = 0; mode = MODE_HUB; }
    else if(!strcmp(uri, "leaf")) { mode = MODE_LEAF_DISC; }
    else { if(parse_uri_role(uri, &mode, ip, sizeof(ip), &port)!=0){ fprintf(stderr,"bad address/URI. expected hub://IP:PORT or leaf://IP:PORT\n"); cleanup_sockets(); return 1; } if(mode==MODE_HUB){ strncpy(bind_ip, ip, sizeof(bind_ip)-1); bind_ip[sizeof(bind_ip)-1]='\0'; bind_port = port; } }

    if(mode==MODE_HUB){ int rc=run_server_bind_ip(bind_ip, bind_port); cleanup_sockets(); return rc; }
    if(mode==MODE_LEAF){ int rc=run_client(ip, port); cleanup_sockets(); return rc; }
    { int rc=run_client_discover(); cleanup_sockets(); return rc; }
}
