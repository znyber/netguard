/* engine.h - backend-independent rule matching, shaping, statistics */
#ifndef NG_ENGINE_H
#define NG_ENGINE_H
#include "common.h"

#define NG_OUT 0   /* upload   (local -> remote) */
#define NG_IN  1   /* download (remote -> local) */

/* raw parse result of an IP packet (addresses are 16 bytes, IPv4 is v4-mapped) */
typedef struct {
    uint8_t  proto;
    uint8_t  src[16], dst[16];
    uint16_t sport, dport;
    uint32_t len;                 /* total IP length in bytes */
} ng_ipinfo_t;

/* what the engine judges: direction-normalised view of a packet */
typedef struct {
    uint8_t  dir;                 /* NG_OUT / NG_IN */
    uint8_t  proto;               /* 6 tcp, 17 udp, 1 icmp, 58 icmpv6 ... */
    uint8_t  loopback;            /* machine talking to itself (127.x, ::1, own LAN IP) */
    int16_t  app;                 /* id from engine_app_id(); 0 = unknown application */
    uint8_t  remote[16];          /* the other end (dst for upload, src for download) */
    uint16_t remote_port, local_port;
    uint32_t len;
} ng_pkt_t;

typedef enum { NG_PASS, NG_DROP, NG_DELAY } ng_act_t;
typedef struct {
    ng_act_t act;
    uint64_t release_ns;          /* valid for NG_DELAY: hold packet until ng_now_ns() >= this */
} ng_verdict_t;

int  ng_parse_ip(const uint8_t *d, size_t n, ng_ipinfo_t *o);          /* 0 ok, -1 not IP */
void ng_fill_pkt(const ng_ipinfo_t *ip, int dir, ng_pkt_t *p);

int  engine_load(const char *path);          /* (re)load rules; keeps old rules on error */
void engine_start_workers(void);             /* sampler + DNS resolver + config watcher  */
void engine_judge(const ng_pkt_t *p, ng_verdict_t *v);
void engine_json_stats(sb_t *o);
int  engine_json_history(int idx, sb_t *o);  /* 0 ok, -1 bad index */
void engine_json_apps(sb_t *o);
void engine_json_system(sb_t *o);           /* built-in default whitelist items + live traffic */

/* ---- per-application support (backend side) ---- */
int  engine_app_id(const char *path_utf8);   /* interns an executable path, returns id >= 1 */
void engine_set_app_support(int on);         /* backend can tell which app owns a packet */
void engine_set_self_app(int id);            /* our own process: never filtered */
void engine_set_exempt_port(int port);       /* dashboard port: loopback traffic on it is never filtered */
int  engine_wants_loopback(void);            /* some rule targets localhost -> backend must capture it */
void engine_set_loopback_active(int on);
int  engine_needs_enforcement(void);         /* 0 = nothing to enforce: backend may only watch copies (full speed) */
void engine_set_capture_mode(int enforcing); /* reported in the GUI */
void engine_set_paused(int on);              /* pause = everything passes, backend drops to monitor-only (full speed) */
int  engine_is_paused(void);

/* ---- GUI config API ---- */
int  engine_get_config(sb_t *o);
int  engine_save_config(const char *text, size_t n, char *err, size_t errn);  /* validate, apply, persist */

#endif
