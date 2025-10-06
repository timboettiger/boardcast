/*
 * Boardcast — Universal Clipboard -- ANSI C (C89)
 *
 * Binary name: boardcast
 *
 * Usage:
 *   boardcast [--debug|-d] [--verbose|-v] [--reconnect|-r N] [--cast|-c 0|1]
 *             [ hub://IP:PORT | leaf://IP:PORT | leaf | --help|-h ]
 * Examples:
 *   boardcast                                   # HUB on 0.0.0.0:0 (random port), also acts as local leaf
 *   boardcast hub://0.0.0.0:33654               # HUB bound to all IFs on port 33654
 *   boardcast hub://192.168.1.123:0             # HUB bound to a specific IF on random port
 *   boardcast leaf://192.168.1.1:33654          # LEAF joining an explicit HUB
 *   boardcast leaf                               # LEAF discovery: wait for HUB broadcast and auto-join
 *   boardcast -d -v -r 20 --cast 1              # debug+verbose, 20 reconnect attempts, enable hub broadcast
 *
 * Behavior:
 * - Start with no URI → HUB (also a local leaf) on hub://0.0.0.0:0 (random port all IFs).
 * - Start with hub://IP:PORT → HUB binds to that IP and port (0 = random). HUB periodically
 *   broadcasts its service (UDP broadcast) if --cast/-c is enabled (default enabled).
 * - Start with leaf://IP:PORT → LEAF connects and runs, with auto-reconnect.
 * - Start with "leaf" (no IP:PORT) → LEAF waits for HUB broadcast and connects to the
 *   first HUB it hears (discovery mode).
 *
 * IDs & Protocol:
 * - 16-byte ID per peer at startup: byte0=os-marker, bytes1..15=random.
 * - Wire frame (send-only, no ACKs): 4B big-endian length L = 16 + payload, then ID(16), then TEXT payload.
 * - HUB rebroadcasts to all other leaves including the original sender ID.
 * - Leaves ignore frames whose sender ID equals their own.
 *
 * Discovery (cast):
 * - UDP broadcast on port DISC_PORT (default 53701). Payload: "BOARDCAST v1 <ip> <port> <idhex>\n"
 * - HUB sends every CAST_INTERVAL seconds. LEAF (discovery mode) listens and dials the
 *   first valid HUB it hears.
 *
 * Notes:
 * - Pure ANSI C (C89). No threads. No encryption. One source file.
 * - Networking: BSD sockets (GUSI on classic Mac OS for classic builds).
 * - Clipboards:
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
#define MAX_BUF         65536
#define HEARTBEAT_SEC   2
#define MAX_CLIENTS     32
#define ID_LEN          16
#define DISC_PORT       53701
#define CAST_INTERVAL   5    /* seconds */

/* OS ID markers (first byte of g_id) */
#define OSID_CLASSIC_MAC  0x01
#define OSID_WINDOWS      0x02
#define OSID_DARWIN       0x03
#define OSID_POSIX        0x04

/* ====== Globals ====== */
static int g_debug = 0;
static int g_verbose = 0;       /* if set and not debug: client posts messages via clipboard */
static int g_reconnect_max = 10;/* default for -r */
static int g_cast = 1;          /* hub broadcasts service by default (-c 0 to disable) */
static unsigned char g_id[ID_LEN];

#define logdbg1(a)         do { if (g_debug) { fprintf(stderr, "[debug] %s\n", (a)); } } while(0)
#define logdbg2(fmt,a)     do { if (g_debug) { fprintf(stderr, "[debug] "); fprintf(stderr, (fmt), (a)); fprintf(stderr, "\n"); } } while(0)
#define logdbg3(fmt,a,b)   do { if (g_debug) { fprintf(stderr, "[debug] "); fprintf(stderr, (fmt), (a), (b)); fprintf(stderr, "\n"); } } while(0)
#define print_local_address(port) do { (void)(port); } while(0)

/* ====== Utility ====== */
static unsigned long checksum(const unsigned char *p, size_t n) { unsigned long c=5381UL; size_t i; for(i=0;i<n;++i) c=((c<<5)+c)+(unsigned long)p[i]; return c; }

static void gen_id(void) {
    unsigned char os = 0;
#ifdef CLASSIC_MAC
    os = OSID_CLASSIC_MAC;
#elif defined(_WIN32)
    os = OSID_WINDOWS;
#elif defined(PLATFORM_DARWIN)
    os = OSID_DARWIN;
#else
    os = OSID_POSIX;
#endif
    g_id[0] = os;
#if defined(_WIN32)
    srand((unsigned)time(NULL));
#else
    {
        unsigned seed = (unsigned)time(NULL);
# ifndef CLASSIC_MAC
        seed ^= (unsigned)getpid();
# endif
        srand(seed);
    }
#endif
    { int i; for(i=1;i<ID_LEN;++i) g_id[i]=(unsigned char)(rand() & 0xFF); }
}

static void print_id_hex(const unsigned char *id) { int i; fprintf(stdout, "ID: "); for(i=0;i<ID_LEN;++i) fprintf(stdout, "%02X", (unsigned)id[i]); fprintf(stdout, "\n"); }

static void msleep(unsigned ms){
#if defined(_WIN32)
    Sleep(ms);
#else
    struct timeval tv; tv.tv_sec = (long)(ms/1000U); tv.tv_usec = (long)((ms%1000U)*1000U); select(0,NULL,NULL,NULL,&tv);
#endif
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
static int can_run(const char *cmd){ char buf[256]; FILE *fp; int ok=0; snprintf(buf,sizeof(buf),"which %s 2>/dev/null",cmd); fp=popen(buf,"r"); if(fp){ if(fgets(buf,sizeof(buf),fp)) ok=1; pclose(fp);} return ok; }
static int env_is(const char *k,const char *v){ const char *e=getenv(k); if(!e||!v) return 0; return strcmp(e,v)==0; }
static int is_wayland(void){ const char *wd=getenv("WAYLAND_DISPLAY"); if(wd&&wd[0]) return 1; if(env_is("XDG_SESSION_TYPE","wayland")) return 1; return 0; }
static char *read_via_popen(const char *cmd,size_t *out_len){ FILE *fp=popen(cmd,"r"); char *buf=NULL; size_t cap=0,n=0; int ch; *out_len=0; if(!fp) return NULL; while((ch=fgetc(fp))!=EOF){ if(n+1>cap){ size_t ncap=cap?cap*2:1024; char *tmp=(char*)realloc(buf,ncap); if(!tmp){ free(buf); pclose(fp); return NULL;} buf=tmp; cap=ncap;} buf[n++]=(char)ch;} if(buf) *out_len=n; pclose(fp); return buf; }
static int write_via_popen(const char *cmd,const char *data,size_t len){ FILE *fp=popen(cmd,"w"); size_t w; if(!fp) return -1; w=fwrite(data,1,len,fp); pclose(fp); return (w==len)?0:-1; }
static char *clip_read(size_t *out_len){
# ifdef PLATFORM_DARWIN
    if(can_run("pbpaste")) return read_via_popen("pbpaste",out_len);
# endif
    if(is_wayland() && can_run("wl-paste")) return read_via_popen("wl-paste",out_len);
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
    sock_t s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    unsigned long ina;

    if (s == INVALID_SOCKET) return -1;
    set_reuse(s);
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;

    if (ip && ip[0]) {
        /* inet_addr returns 0xFFFFFFFF on error (oldschool & C89-friendly) */
        ina = inet_addr(ip);
        if (ina == 0xFFFFFFFFUL) {
            a.sin_addr.s_addr = htonl(INADDR_ANY);
        } else {
            a.sin_addr.s_addr = ina;
        }
    } else {
        a.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    a.sin_port = htons(port);

    if (bind(s, (struct sockaddr*)&a, sizeof(a)) == SOCKET_ERROR) { CLOSESOCK(s); return -1; }
    if (listen(s, MAX_CLIENTS) == SOCKET_ERROR) { CLOSESOCK(s); return -1; }
    {
        socklen_t alen = sizeof(a);
        if (getsockname(s, (struct sockaddr*)&a, &alen) == 0) *out_port = ntohs(a.sin_port);
        else *out_port = 0;
    }
    *out_sock = s;
    return 0;
}

static sock_t accept_one(sock_t ls){ struct sockaddr_in ca; socklen_t clen=sizeof(ca); return accept(ls,(struct sockaddr*)&ca,&clen); }

static sock_t connect_host(const char *host, unsigned short port) {
    sock_t s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    struct hostent *he;
    unsigned long ina;

    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port   = htons(port);

    /* Try dotted-quad first */
    ina = inet_addr(host);
    if (ina != 0xFFFFFFFFUL) {
        a.sin_addr.s_addr = ina;
    } else {
        he = gethostbyname(host);
        if (!he || !he->h_addr_list || !he->h_addr_list[0]) { CLOSESOCK(s); return INVALID_SOCKET; }
        memcpy(&a.sin_addr, he->h_addr_list[0], (size_t)sizeof(struct in_addr));
    }

    if (connect(s, (struct sockaddr*)&a, sizeof(a)) == SOCKET_ERROR) {
        CLOSESOCK(s);
        return INVALID_SOCKET;
    }
    return s;
}

static int guess_local_ip(char *out, size_t outsz){ char hostname[256]; if(gethostname(hostname,sizeof(hostname))==0){ struct hostent *he=gethostbyname(hostname); if(he && he->h_addr_list && he->h_addr_list[0]){ struct in_addr in; memcpy(&in, he->h_addr_list[0], (size_t)he->h_length); strncpy(out, inet_ntoa(in), outsz-1); out[outsz-1]='\0'; return 0; } } strncpy(out, "127.0.0.1", outsz); out[outsz-1]='\0'; return -1; }

/* ====== Protocol I/O ======
   Frame: 4-byte big-endian length L, then ID(16) + payload(L-16) */
static int send_packet(sock_t s,const unsigned char *id,const char *data,size_t len){ unsigned char hdr[4]; size_t sent=0; int n; unsigned long L=(unsigned long)(ID_LEN+len);
    hdr[0]=(unsigned char)((L>>24)&0xFF); hdr[1]=(unsigned char)((L>>16)&0xFF); hdr[2]=(unsigned char)((L>>8)&0xFF); hdr[3]=(unsigned char)(L&0xFF);
    n=send(s,(const char*)hdr,4,0); if(n!=4) return -1;
    n=send(s,(const char*)id,ID_LEN,0); if(n!=(int)ID_LEN) return -1;
    while(sent<len){ n=send(s,data+(int)sent,(int)(len-sent),0); if(n<=0) return -1; sent += (size_t)n; }
    return 0; }

static int recv_packet(sock_t s,unsigned char *id_out,char **out,size_t *out_len){ unsigned char hdr[4]; int n; unsigned long L=0; size_t recvd=0; char *buf; *out=NULL; *out_len=0;
    /* header */
    recvd=0; while(recvd<4){ n=recv(s,(char*)hdr+recvd,4-(int)recvd,0); if(n<=0) return -1; recvd+=(size_t)n; }
    L=((unsigned long)hdr[0]<<24)|((unsigned long)hdr[1]<<16)|((unsigned long)hdr[2]<<8)|(unsigned long)hdr[3];
    if(L<ID_LEN || L>MAX_BUF) return -1;
    /* ID */
    recvd=0; while(recvd<ID_LEN){ n=recv(s,(char*)id_out+recvd,(int)(ID_LEN-recvd),0); if(n<=0) return -1; recvd+=(size_t)n; }
    /* payload */
    L -= ID_LEN; buf=(char*)malloc((size_t)L); if(!buf) return -1; recvd=0; while(recvd<(size_t)L){ n=recv(s,buf+recvd,(int)(L-recvd),0); if(n<=0){ free(buf); return -1; } recvd+=(size_t)n; }
    *out=buf; *out_len=(size_t)L; return 0; }

/* ====== Discovery (UDP cast) ====== */
static int hub_cast_socket(sock_t *out){ sock_t u=socket(AF_INET,SOCK_DGRAM,0); if(u==INVALID_SOCKET) return -1; set_broadcast(u); *out=u; return 0; }
static int leaf_listen_socket(sock_t *out){ sock_t u=socket(AF_INET,SOCK_DGRAM,0); struct sockaddr_in a; if(u==INVALID_SOCKET) return -1; memset(&a,0,sizeof(a)); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_ANY); a.sin_port=htons(DISC_PORT); if(bind(u,(struct sockaddr*)&a,sizeof(a))==SOCKET_ERROR){ CLOSESOCK(u); return -1; } *out=u; return 0; }

static void id_to_hex(const unsigned char *id, char *out, size_t outsz){ size_t i; if(outsz< (ID_LEN*2+1)) return; for(i=0;i<ID_LEN;++i) { sprintf(out + (i*2), "%02X", (unsigned)id[i]); } out[ID_LEN*2]='\0'; }

static void hub_broadcast(sock_t ucast, const char *adv_ip, unsigned short adv_port){
    struct sockaddr_in b; char hex[ID_LEN*2+1]; char msg[256]; id_to_hex(g_id,hex,sizeof(hex));
    memset(&b,0,sizeof(b)); b.sin_family=AF_INET; b.sin_port=htons(DISC_PORT); b.sin_addr.s_addr=htonl(INADDR_BROADCAST);
    snprintf(msg,sizeof(msg),"BOARDCAST v1 %s %u %s\n", adv_ip, (unsigned)adv_port, hex);
    sendto(ucast, msg, (int)strlen(msg), 0, (struct sockaddr*)&b, sizeof(b));
}

static int leaf_wait_for_hub(char *out_ip, size_t out_ipsz, unsigned short *out_port, unsigned timeout_sec){
    sock_t u; if(leaf_listen_socket(&u)!=0) return -1; {
        fd_set rf; struct timeval tv; int nf; for(;;){ FD_ZERO(&rf); FD_SET(u,&rf); tv.tv_sec=timeout_sec; tv.tv_usec=0; nf=select((int)u+1,&rf,NULL,NULL,&tv); if(nf>0 && FD_ISSET(u,&rf)){
                char buf[512]; struct sockaddr_in from; socklen_t flen=sizeof(from); int n=recvfrom(u,buf,sizeof(buf)-1,0,(struct sockaddr*)&from,&flen); if(n>0){ char magic[16]; char ip[64]; unsigned port=0; char idhex[64]; buf[n]='\0'; if(sscanf(buf, "%15s v1 %63s %u %63s", magic, ip, &port, idhex)==4){ if(strcmp(magic,"BOARDCAST")==0){ strncpy(out_ip, ip, out_ipsz-1); out_ip[out_ipsz-1]='\0'; *out_port=(unsigned short)port; CLOSESOCK(u); return 0; } } }
            } else if(nf==0){ /* timeout */ CLOSESOCK(u); return -1; }
        }
    } }

/* ====== Server (hub) ====== */
struct client { sock_t s; int alive; int has_id; unsigned char id[ID_LEN]; };

static int run_server_bind_ip(const char *bind_ip, unsigned short bind_port){
    sock_t ls; unsigned short port=0; struct client cli[MAX_CLIENTS]; int i; char *last=NULL; size_t last_len=0; unsigned long last_ck=0; sock_t ucast=INVALID_SOCKET; unsigned last_cast = 0; char adv_ip[64];
    for(i=0;i<MAX_CLIENTS;++i){ cli[i].s=INVALID_SOCKET; cli[i].alive=0; cli[i].has_id=0; }
    if(listen_on(bind_ip, bind_port, &port, &ls)!=0){ fprintf(stderr,"listen failed\n"); return 1; }
    if(!bind_ip || !bind_ip[0] || strcmp(bind_ip,"0.0.0.0")==0) guess_local_ip(adv_ip,sizeof(adv_ip)); else { strncpy(adv_ip, bind_ip, sizeof(adv_ip)-1); adv_ip[sizeof(adv_ip)-1]='\0'; }

    fprintf(stdout,"Boardcast hub started. Address: %s:%u\n", adv_ip, (unsigned)port);
    if(g_debug){ fprintf(stdout,"(debug) "); print_id_hex(g_id); }
    fflush(stdout);

    if(g_cast){ if(hub_cast_socket(&ucast)!=0) { if(g_debug) fprintf(stderr,"[debug] cannot open cast socket\n"); } }

    for(;;){
        fd_set rfds; struct timeval tv; int nf, maxfd=(int)ls; unsigned now_sec;
        FD_ZERO(&rfds); FD_SET(ls,&rfds);
        for(i=0;i<MAX_CLIENTS;++i){ if(cli[i].alive){ FD_SET(cli[i].s,&rfds); if((int)cli[i].s>maxfd) maxfd=(int)cli[i].s; } }
        /* Periodic cast */
        now_sec = (unsigned)time(NULL);
        if (g_cast && ucast!=INVALID_SOCKET && (last_cast==0 || now_sec - last_cast >= CAST_INTERVAL)) {
            hub_broadcast(ucast, adv_ip, port); last_cast = now_sec;
        }
        /* Poll local clipboard for hub-originated changes */
        {
            char *buf=NULL; size_t blen=0; unsigned long ck; buf=clip_read(&blen);
            if(buf && blen>0){ ck=checksum((const unsigned char*)buf,blen);
                if(ck!=last_ck || blen!=last_len || (last && memcmp(buf,last,blen)!=0)){
                    int j; for(j=0;j<MAX_CLIENTS;++j){ if(cli[j].alive) send_packet(cli[j].s, g_id, buf, blen); }
                    if(last) free(last); last=buf; last_len=blen; last_ck=ck; buf=NULL; blen=0;
                }
            } else if(!buf && g_verbose && !g_debug){ notify_user_clip("error accessing local clipboard"); }
            if(buf) free(buf);
        }
        tv.tv_sec=HEARTBEAT_SEC; tv.tv_usec=0; nf=select(maxfd+1,&rfds,NULL,NULL,&tv); if(nf<0) continue;
        /* New connections */
        if(FD_ISSET(ls,&rfds)){
            sock_t ns=accept_one(ls);
            if(ns!=INVALID_SOCKET){ int slotted=0; for(i=0;i<MAX_CLIENTS;++i){ if(!cli[i].alive){ cli[i].s=ns; cli[i].alive=1; cli[i].has_id=0; slotted=1; if(g_debug) fprintf(stderr,"[debug] leaf connected (awaiting ID)\n"); break; } } if(!slotted) CLOSESOCK(ns); }
        }
        /* Client traffic */
        for(i=0;i<MAX_CLIENTS;++i){ if(cli[i].alive && FD_ISSET(cli[i].s,&rfds)){
                unsigned char sid[ID_LEN]; char *rbuf=NULL; size_t rlen=0; int rc=recv_packet(cli[i].s,sid,&rbuf,&rlen);
                if(rc!=0){ if(g_debug && cli[i].has_id){ char hex[ID_LEN*2+1]; id_to_hex(cli[i].id,hex,sizeof(hex)); fprintf(stderr,"[debug] leaf disconnected: %s\n", hex); }
                    CLOSESOCK(cli[i].s); cli[i].alive=0; cli[i].has_id=0; if(rbuf) free(rbuf); continue; }
                if(!cli[i].has_id){ memcpy(cli[i].id, sid, ID_LEN); cli[i].has_id=1; if(g_debug){ char hex[ID_LEN*2+1]; id_to_hex(sid,hex,sizeof(hex)); fprintf(stderr,"[debug] leaf joined: %s\n", hex); } }
                if(rbuf && rlen>0){ clip_write(rbuf,rlen); if(last) free(last); last=rbuf; last_len=rlen; last_ck=checksum((const unsigned char*)last,last_len); rbuf=NULL; }
                { int j; for(j=0;j<MAX_CLIENTS;++j){ if(cli[j].alive && j!=i){ send_packet(cli[j].s, sid, last, last_len); } } }
                if(rbuf) free(rbuf);
        } }
    }

    if(last) free(last); CLOSESOCK(ls); if(ucast!=INVALID_SOCKET) CLOSESOCK(ucast); for(i=0;i<MAX_CLIENTS;++i){ if(cli[i].alive) CLOSESOCK(cli[i].s); }
    return 0; }

/* ====== Client (leaf with reconnect & discovery) ====== */
static int run_client_once(const char *host,unsigned short port,sock_t *out_sock){ sock_t s=connect_host(host,port); if(s==INVALID_SOCKET) return -1; *out_sock=s; return 0; }

static int run_client(const char *host, unsigned short port){
    int attempts = 0; unsigned backoff = 1000; /* ms, grows to 60000 */
    sock_t s = INVALID_SOCKET;

reconnect_start:
    if (attempts > 0) {
        if (attempts >= g_reconnect_max) { notify_user_clip("boardcast: reconnect attempts exhausted"); fprintf(stderr, "reconnect attempts exhausted\n"); return 1; }
        if (backoff > 60000U) backoff = 60000U; msleep(backoff); if (backoff < 60000U) backoff <<= 1;
    }
    if (run_client_once(host, port, &s) != 0) { if (attempts==0) notify_user_clip("connection to boardcast hub lost"); attempts++; goto reconnect_start; }

    /* Connected */
    attempts = 0; backoff = 1000; /* reset */
    fprintf(stdout,"Connected to %s:%u (LEAF).\n", host, (unsigned)port); if(g_debug){ fprintf(stdout,"(debug) "); print_id_hex(g_id); } fflush(stdout);

    { char *last=NULL; size_t last_len=0; unsigned long last_ck=0; for(;;){ fd_set rfds; struct timeval tv; int nf, maxfd=(int)s; char *buf=NULL; size_t blen=0; unsigned long ck;
            /* Poll local clipboard */
            buf=clip_read(&blen);
            if(buf && blen>0){ ck=checksum((const unsigned char*)buf,blen);
                if(ck!=last_ck || blen!=last_len || (last && memcmp(buf,last,blen)!=0)){
                    if(send_packet(s, g_id, buf, blen)!=0){ if(buf) free(buf); notify_user_clip("connection to boardcast hub lost"); break; }
                    if(last) free(last); last=buf; last_len=blen; last_ck=ck; buf=NULL; blen=0;
                }
            } else if(!buf && g_verbose && !g_debug) { notify_user_clip("error accessing local clipboard"); }
            if(buf) free(buf);
            FD_ZERO(&rfds); FD_SET(s,&rfds);
            tv.tv_sec=HEARTBEAT_SEC; tv.tv_usec=0; nf=select(maxfd+1,&rfds,NULL,NULL,&tv);
            if(nf>0 && FD_ISSET(s,&rfds)){
                unsigned char sid[ID_LEN]; char *rbuf=NULL; size_t rlen=0;
                if(recv_packet(s,sid,&rbuf,&rlen)!=0){ if(rbuf) free(rbuf); notify_user_clip("connection to boardcast hub lost"); break; }
                if(rbuf && rlen>0){ if(memcmp(sid,g_id,ID_LEN)!=0){ clip_write(rbuf,rlen); if(last) free(last); last=rbuf; last_len=rlen; last_ck=checksum((const unsigned char*)last,last_len); rbuf=NULL; } }
                if(rbuf) free(rbuf);
            }
        }
        if(last) free(last); CLOSESOCK(s); s=INVALID_SOCKET; attempts++; goto reconnect_start; }
}

static int run_client_discover(void){ char ip[64]; unsigned short port=0; fprintf(stdout,"Waiting for Boardcast hub discovery on UDP %u...\n", (unsigned)DISC_PORT); fflush(stdout); if(leaf_wait_for_hub(ip,sizeof(ip),&port,60)!=0){ fprintf(stderr,"no hub discovered\n"); return 1; } fprintf(stdout,"Discovered hub at %s:%u\n", ip, (unsigned)port); return run_client(ip, port); }

/* ====== URI parsing & main ====== */
enum Mode { MODE_HUB=1, MODE_LEAF=2, MODE_LEAF_DISC=3 };

static int has_prefix(const char *s, const char *pfx){ size_t n=strlen(pfx); return strncmp(s,pfx,n)==0; }

static int parse_uri_role(const char *uri, enum Mode *mode, char *ip, size_t ipsz, unsigned short *port){
    if(has_prefix(uri,"hub://")) { *mode=MODE_HUB; return parse_hostport(uri+6, ip, ipsz, port); }
    if(has_prefix(uri,"leaf://")) { *mode=MODE_LEAF; return parse_hostport(uri+7, ip, ipsz, port); }
    /* Fallback: treat as plain host:port → leaf */
    *mode=MODE_LEAF; return parse_hostport(uri, ip, ipsz, port);
}

static void usage(const char *prog){
    fprintf(stdout,
        "Boardcast — Universal Clipboard (no encryption)\n"
        "Usage: %s [--debug/-d] [--verbose/-v] [--reconnect/-r N] [--cast/-c 0|1]\n"
        "             [ hub://IP:PORT | leaf://IP:PORT | leaf | --help/-h ]\n"
        "Examples:\n"
        "   %s\n"
        "   %s hub://0.0.0.0:33654\n"
        "   %s leaf://192.168.1.1:33654\n"
        "   %s leaf\n"
        "   %s -d -v -r 20 --cast 1\n\n",
        prog, prog, prog, prog, prog, prog);
}

int main(int argc, char **argv){ int i; int show_help=0; char *uri=NULL; char ip[256]; unsigned short port=0; enum Mode mode=MODE_HUB; char bind_ip[256]; unsigned short bind_port=0;
    if(startup_sockets()!=0){ fprintf(stderr,"socket init failed\n"); return 1; }
    gen_id();

    for(i=1;i<argc;++i){
        if(!strcmp(argv[i],"--debug") || !strcmp(argv[i],"-d")) g_debug=1;
        else if(!strcmp(argv[i],"--verbose") || !strcmp(argv[i],"-v")) g_verbose=1;
        else if(!strcmp(argv[i],"--reconnect") || !strcmp(argv[i],"-r")) { if(i+1<argc){ g_reconnect_max=atoi(argv[++i]); if(g_reconnect_max<1) g_reconnect_max=1; } }
        else if(!strcmp(argv[i],"--cast") || !strcmp(argv[i],"-c")) { if(i+1<argc){ g_cast=atoi(argv[++i])?1:0; } }
        else if(!strcmp(argv[i],"--help") || !strcmp(argv[i],"-h")) show_help=1;
        else uri=argv[i];
    }
    if(show_help){ usage(argv[0]); cleanup_sockets(); return 0; }

    if(uri==NULL){ /* default hub://0.0.0.0:0 */
        strcpy(bind_ip, "0.0.0.0"); bind_port = 0; mode = MODE_HUB;
    } else if(!strcmp(uri, "leaf")) {
        mode = MODE_LEAF_DISC;
    } else {
        if(parse_uri_role(uri, &mode, ip, sizeof(ip), &port)!=0){ fprintf(stderr,"bad address/URI. expected hub://IP:PORT or leaf://IP:PORT\n"); cleanup_sockets(); return 1; }
        if(mode==MODE_HUB){ strncpy(bind_ip, ip, sizeof(bind_ip)-1); bind_ip[sizeof(bind_ip)-1]='\0'; bind_port = port; }
    }

    if(mode==MODE_HUB){ int rc=run_server_bind_ip(bind_ip, bind_port); cleanup_sockets(); return rc; }
    if(mode==MODE_LEAF){ int rc=run_client(ip, port); cleanup_sockets(); return rc; }
    /* MODE_LEAF_DISC */
    { int rc=run_client_discover(); cleanup_sockets(); return rc; }
}
