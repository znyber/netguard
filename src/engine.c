/* engine.c - rules (per app / ip / domain / port), shaper, default policy, stats, config, DNS resolver */
#include "engine.h"
#include <sys/stat.h>
#include <ctype.h>
#ifndef _WIN32
  #include <netdb.h>
  #include <arpa/inet.h>
  #include <sys/socket.h>
#endif

#define MAX_RULES 256
#define MAX_NETS  32
#define MAX_DOMS  8
#define MAX_RAPPS 4
#define MAX_APPS  256
#define PATHLEN   260
#define HIST      180            /* seconds of history kept per series */

enum { A_ALLOW, A_LIMIT, A_BLOCK };
static const char *act_name[] = { "allow", "limit", "block" };

typedef struct { uint8_t a[16]; uint8_t prefix; } net_t;

typedef struct {
    char     name[40];
    int      action, enabled;
    uint8_t  proto;                       /* 0 = any */
    uint16_t port_lo, port_hi;            /* port_hi == 0 -> any port */
    net_t    nets[MAX_NETS]; int n_nets;  /* from ip=       */
    char     dom[MAX_DOMS][128]; int n_dom;
    net_t    dyn[MAX_NETS];  int n_dyn;   /* resolved from domain= */
    char     app[MAX_RAPPS][PATHLEN]; uint8_t app_is_path[MAX_RAPPS]; int n_app;  /* lowercase */
    int      loop_ok;                     /* has a loopback net -> may match localhost traffic */
    uint64_t rate[2];                     /* bytes/s per direction, 0 = unlimited */
    uint64_t next_free[2];                /* shaper virtual clock (ns) */
    uint64_t last_log_ns; uint32_t suppressed;
} rule_t;

typedef struct {
    uint64_t bytes[2], pkts[2], drops;
    uint64_t last_bytes[2];
    uint64_t hist[2][HIST];               /* bit/s per second */
} ctr_t;

typedef struct {                          /* one executable that produced traffic */
    char path[PATHLEN], lpath[PATHLEN];
    const char *base, *lbase;
    uint64_t bytes[2], last_bytes[2], rate[2], drops;
    uint64_t seen_ns, last_log_ns; uint32_t suppressed;
    uint32_t gen; uint64_t bits[MAX_RULES / 64];   /* cache: which rules' app= match this app */
} app_t;

typedef struct { uint64_t qns; int def_block, filtering; int sys_en[16]; } glob_t;

/* ---- built-in default whitelist: evaluated BEFORE any user rule, matched by protocol/port (not by app,
 *      because DHCP/DNS/time run as services inside svchost.exe). Each item can be switched off. ---- */
typedef struct { uint8_t proto; uint16_t lo, hi; } sm_t;          /* hi == 0 -> protocol only */
typedef struct {
    const char *name, *label, *detail;
    sm_t m[7]; int nm;
    int enabled;
    uint64_t bytes[2], pkts[2], last_bytes[2], rate[2];
} sys_t;

static sys_t sysr[] = {
    { .name = "sys-dhcp",   .label = "DHCP client (IPv4 address lease)",              .detail = "udp 67-68",
      .m = { {17, 67, 68} }, .nm = 1, .enabled = 1 },
    { .name = "sys-dhcpv6", .label = "DHCPv6 client",                                 .detail = "udp 546-547",
      .m = { {17, 546, 547} }, .nm = 1, .enabled = 1 },
    { .name = "sys-dns",    .label = "DNS client (name lookups)",                     .detail = "port 53, tcp + udp",
      .m = { {0, 53, 53} }, .nm = 1, .enabled = 1 },
    { .name = "sys-icmp",   .label = "Ping / ICMP (errors, path MTU)",                .detail = "icmp",
      .m = { {1, 0, 0} }, .nm = 1, .enabled = 1 },
    { .name = "sys-icmpv6", .label = "ICMPv6 (IPv6 neighbor discovery - IPv6 stops working without it)", .detail = "icmpv6",
      .m = { {58, 0, 0} }, .nm = 1, .enabled = 1 },
    { .name = "sys-ntp",    .label = "Windows Time (clock sync)",                     .detail = "udp 123",
      .m = { {17, 123, 123} }, .nm = 1, .enabled = 1 },
    { .name = "sys-ppp",    .label = "PPP / VPN tunnels (PPTP, L2TP, IPsec). PPPoE negotiation itself runs below IP and is never filtered",
      .detail = "gre, esp, tcp 1723, udp 500 / 1701 / 4500",
      .m = { {47, 0, 0}, {50, 0, 0}, {6, 1723, 1723}, {17, 500, 500}, {17, 1701, 1701}, {17, 4500, 4500} }, .nm = 6, .enabled = 1 },
};
#define NSYS ((int)(sizeof sysr / sizeof sysr[0]))

static rule_t  *rules;  static int nrules;
static ctr_t   *ctr;                      /* [0]=TOTAL [1]=unmatched [2+i]=rule i */
static app_t   *apps;   static int napps = 1;     /* apps[0] = "(unknown)" */
static ng_mutex lk;
static uint32_t rules_gen = 1;
static uint64_t max_queue_ns = 250ull * 1000000ull;
static int      default_block, filtering = 1, app_support, self_app, loopback_active, capture_enforcing = 1;
static volatile int paused;
static uint16_t exempt_port;
static int      hist_n, hist_pos;
static char     cfg_path[260];
static time_t   cfg_mtime;
static volatile int resolve_now;
static char     perr[256];                /* first error of the last parse (shown in the GUI) */

/* ------------------------------------------------------------ helpers */
static void lower_copy(char *dst, size_t n, const char *src) {
    size_t i = 0;
    for (; src[i] && i + 1 < n; i++) dst[i] = (char)tolower((unsigned char)src[i]);
    dst[i] = 0;
}
static const char *base_of(const char *p) {
    const char *b = p;
    for (; *p; p++) if (*p == '\\' || *p == '/') b = p + 1;
    return b;
}
static void json_str(sb_t *o, const char *s) {
    const char *run = s;
    sb_putn(o, "\"", 1);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\' || c < 0x20) {
            if (s > run) sb_putn(o, run, (size_t)(s - run));
            if (c < 0x20) sb_printf(o, "\\u%04x", c);
            else { char b[2]; b[0] = '\\'; b[1] = (char)c; sb_putn(o, b, 2); }
            run = s + 1;
        }
    }
    if (s > run) sb_putn(o, run, (size_t)(s - run));
    sb_putn(o, "\"", 1);
}
static int init_once(void) {
    if (rules) return 0;
    rules = calloc(MAX_RULES, sizeof *rules);
    ctr   = calloc(2 + MAX_RULES, sizeof *ctr);
    apps  = calloc(MAX_APPS, sizeof *apps);
    if (!rules || !ctr || !apps) return -1;
    ng_mutex_init(&lk);
    snprintf(apps[0].path, sizeof apps[0].path, "(unknown)");
    apps[0].base = apps[0].path; apps[0].lbase = apps[0].lpath;
    return 0;
}

/* ------------------------------------------------------------ parsing */
static int parse_rate(const char *s, uint64_t *Bps) {     /* "2M", "512k", "100" = bit/s */
    char *e; double v = strtod(s, &e);
    if (e == s || v < 0) return -1;
    switch (*e) {
        case 0: break;
        case 'k': case 'K': v *= 1e3; e++; break;
        case 'm': case 'M': v *= 1e6; e++; break;
        case 'g': case 'G': v *= 1e9; e++; break;
        default: return -1;
    }
    if (*e) return -1;
    *Bps = (uint64_t)(v / 8.0);
    return 0;
}

static int parse_net(const char *s, net_t *n) {
    char buf[64]; snprintf(buf, sizeof buf, "%s", s);
    long pfx = -1;
    char *sl = strchr(buf, '/');
    if (sl) {
        char *e; *sl = 0; pfx = strtol(sl + 1, &e, 10);
        if (*e || e == sl + 1 || pfx < 0) return -1;
    }
    struct in_addr a4; struct in6_addr a6;
    if (inet_pton(AF_INET, buf, &a4) == 1) {
        if (pfx < 0) pfx = 32;
        if (pfx > 32) return -1;
        memset(n->a, 0, 16); n->a[10] = n->a[11] = 0xff; memcpy(n->a + 12, &a4, 4);
        n->prefix = (uint8_t)(96 + pfx); return 0;
    }
    if (inet_pton(AF_INET6, buf, &a6) == 1) {
        if (pfx < 0) pfx = 128;
        if (pfx > 128) return -1;
        memcpy(n->a, &a6, 16); n->prefix = (uint8_t)pfx; return 0;
    }
    return -1;
}

static int net_match(const net_t *n, const uint8_t a[16]) {
    int full = n->prefix >> 3, rem = n->prefix & 7;
    if (memcmp(n->a, a, (size_t)full)) return 0;
    if (rem) {
        uint8_t m = (uint8_t)(0xFF << (8 - rem));
        if ((n->a[full] ^ a[full]) & m) return 0;
    }
    return 1;
}

static int net_is_loopback(const net_t *n) {
    static const uint8_t v4[16] = { 0,0,0,0,0,0,0,0,0,0,0xff,0xff,127,0,0,1 };
    static const uint8_t v6[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 };
    return net_match(n, v4) || net_match(n, v6);
}

static void addr_str(const uint8_t a[16], char *out, size_t n) {
    static const uint8_t m[12] = { 0,0,0,0,0,0,0,0,0,0,0xff,0xff };
    if (!memcmp(a, m, 12)) inet_ntop(AF_INET, a + 12, out, n);
    else                   inet_ntop(AF_INET6, a, out, n);
}

static int push_net(rule_t *r, const char *s) {
    if (r->n_nets >= MAX_NETS || parse_net(s, &r->nets[r->n_nets])) return -1;
    r->n_nets++; return 0;
}
static int add_target(rule_t *r, const char *v) {          /* ip=  value (with aliases) */
    if (!strcmp(v, "any")) return 0;                        /* all non-localhost traffic */
    if (!strcmp(v, "localhost")) return push_net(r, "127.0.0.0/8") || push_net(r, "::1/128");
    if (!strcmp(v, "lan"))
        return push_net(r, "10.0.0.0/8") || push_net(r, "172.16.0.0/12") || push_net(r, "192.168.0.0/16") ||
               push_net(r, "169.254.0.0/16") || push_net(r, "fc00::/7") || push_net(r, "fe80::/10");
    return push_net(r, v);
}

/* tokenizer: whitespace separated, double quotes group (and are removed) */
static char *next_tok(char **sp) {
    char *s = *sp;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    if (!*s) { *sp = s; return NULL; }
    char *start = s, *w = s; int q = 0;
    while (*s && (q || !(*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n'))) {
        if (*s == '"') { q = !q; s++; continue; }
        *w++ = *s++;
    }
    if (*s) s++;
    *w = 0; *sp = s;
    return start;
}
static void strip_comment(char *line) {                    /* '#' starts a comment unless quoted / mid-word */
    int q = 0;
    for (char *c = line; *c; c++) {
        if (*c == '"') q = !q;
        else if (*c == '#' && !q && (c == line || c[-1] == ' ' || c[-1] == '\t')) { *c = 0; break; }
    }
}

#define ERR(...) do { char m_[200]; snprintf(m_, sizeof m_, __VA_ARGS__);                       \
    ng_log(NG_LOG_ERROR, "%s:%d: %s", path, ln, m_);                                              \
    if (!perr[0]) snprintf(perr, sizeof perr, "line %d: %s", ln, m_);                             \
    bad = 1; goto nextline; } while (0)

static int parse_config(const char *path, rule_t *out, int *nout, glob_t *g) {
    FILE *f = fopen(path, "r");
    perr[0] = 0;
    if (!f) { ng_log(NG_LOG_ERROR, "cannot open config %s", path); snprintf(perr, sizeof perr, "cannot open config"); return -1; }
    char line[2048]; int ln = 0, n = 0, bad = 0;
    while (fgets(line, sizeof line, f)) {
        ln++;
        strip_comment(line);
        char *sp = line;
        char *tok = next_tok(&sp);
        if (!tok) continue;
        if (!strcmp(tok, "global")) {
            while ((tok = next_tok(&sp))) {
                if (!strncmp(tok, "queue_ms=", 9)) {
                    long ms = strtol(tok + 9, NULL, 10);
                    if (ms < 10 || ms > 5000) ERR("queue_ms must be 10..5000");
                    g->qns = (uint64_t)ms * 1000000ull;
                } else if (!strcmp(tok, "default=allow")) g->def_block = 0;
                else if (!strcmp(tok, "default=block"))   g->def_block = 1;
                else if (!strcmp(tok, "filtering=on"))    g->filtering = 1;
                else if (!strcmp(tok, "filtering=off"))   g->filtering = 0;
                else ERR("unknown global option '%s'", tok);
            }
            goto nextline;
        }
        if (!strcmp(tok, "system")) {                       /* system name=sys-dns enabled=no */
            char nm[48] = ""; int en = 1, found = -1;
            while ((tok = next_tok(&sp))) {
                if      (!strncmp(tok, "name=", 5))     snprintf(nm, sizeof nm, "%s", tok + 5);
                else if (!strcmp(tok, "enabled=no"))    en = 0;
                else if (!strcmp(tok, "enabled=yes"))   en = 1;
                else ERR("unknown option '%s'", tok);
            }
            for (int i = 0; i < NSYS; i++) if (!strcmp(sysr[i].name, nm)) found = i;
            if (found < 0) ERR("unknown built-in item '%s'", nm);
            g->sys_en[found] = en;
            goto nextline;
        }
        if (strcmp(tok, "rule")) ERR("expected 'rule', 'system' or 'global', got '%s'", tok);
        if (n >= MAX_RULES) ERR("too many rules (max %d)", MAX_RULES);
        rule_t *r = &out[n];
        memset(r, 0, sizeof *r); r->action = -1; r->enabled = 1;
        while ((tok = next_tok(&sp))) {
            char *eq = strchr(tok, '=');
            if (!eq) ERR("expected key=value, got '%s'", tok);
            *eq = 0;
            const char *k = tok, *v = eq + 1;
            if (!strcmp(k, "name")) {
                if (!*v || strlen(v) >= sizeof r->name) ERR("bad rule name");
                for (const char *c = v; *c; c++)
                    if (!isalnum((unsigned char)*c) && *c != '-' && *c != '_' && *c != '.')
                        ERR("rule name may only contain letters, digits, - _ .");
                for (int i = 0; i < n; i++) if (!strcmp(out[i].name, v)) ERR("duplicate rule name '%s'", v);
                snprintf(r->name, sizeof r->name, "%s", v);
            } else if (!strcmp(k, "action")) {
                if      (!strcmp(v, "allow")) r->action = A_ALLOW;
                else if (!strcmp(v, "limit")) r->action = A_LIMIT;
                else if (!strcmp(v, "block")) r->action = A_BLOCK;
                else ERR("action must be allow|limit|block");
            } else if (!strcmp(k, "enabled")) {
                if      (!strcmp(v, "yes")) r->enabled = 1;
                else if (!strcmp(v, "no"))  r->enabled = 0;
                else ERR("enabled must be yes|no");
            } else if (!strcmp(k, "app")) {
                if (r->n_app >= MAX_RAPPS || !*v || strlen(v) >= PATHLEN) ERR("bad app (max %d per rule)", MAX_RAPPS);
                if (strcmp(v, "*")) {                       /* app=* means any app */
                    lower_copy(r->app[r->n_app], PATHLEN, v);
                    r->app_is_path[r->n_app] = strchr(v, '\\') || strchr(v, '/');
                    r->n_app++;
                }
            } else if (!strcmp(k, "ip")) {
                if (add_target(r, v)) ERR("bad ip/cidr '%s'", v);
            } else if (!strcmp(k, "domain")) {
                if (strchr(v, '*')) ERR("wildcard domains need DNS sniffing (not implemented yet)");
                if (r->n_dom >= MAX_DOMS || !*v || strlen(v) >= sizeof r->dom[0]) ERR("bad domain");
                snprintf(r->dom[r->n_dom++], sizeof r->dom[0], "%s", v);
            } else if (!strcmp(k, "proto")) {
                if      (!strcmp(v, "tcp"))    r->proto = 6;
                else if (!strcmp(v, "udp"))    r->proto = 17;
                else if (!strcmp(v, "icmp"))   r->proto = 1;
                else if (!strcmp(v, "icmpv6")) r->proto = 58;
                else { int p = atoi(v); if (p < 1 || p > 255) ERR("bad proto '%s'", v); r->proto = (uint8_t)p; }
            } else if (!strcmp(k, "port")) {
                int lo, hi;
                if (sscanf(v, "%d-%d", &lo, &hi) != 2) { if (sscanf(v, "%d", &lo) != 1) ERR("bad port"); hi = lo; }
                if (lo < 1 || hi > 65535 || lo > hi) ERR("bad port range");
                r->port_lo = (uint16_t)lo; r->port_hi = (uint16_t)hi;
            } else if (!strcmp(k, "up")) {
                if (parse_rate(v, &r->rate[NG_OUT])) ERR("bad rate '%s' (use e.g. 512k, 2M)", v);
            } else if (!strcmp(k, "down")) {
                if (parse_rate(v, &r->rate[NG_IN])) ERR("bad rate '%s' (use e.g. 512k, 2M)", v);
            } else ERR("unknown key '%s'", k);
        }
        if (r->action < 0) ERR("rule needs action=allow|limit|block");
        if (!r->name[0]) snprintf(r->name, sizeof r->name, "rule%d", n + 1);
        if (r->action == A_LIMIT && !r->rate[0] && !r->rate[1]) ERR("limit rule needs up= and/or down=");
        for (int i = 0; i < r->n_nets; i++) if (net_is_loopback(&r->nets[i])) r->loop_ok = 1;
        n++;
nextline: ;
    }
    fclose(f);
    if (bad) return -1;
    *nout = n;
    return 0;
}

/* ------------------------------------------------------------- loading */
static int apply_file(const char *path) {
    rule_t *tmp = calloc(MAX_RULES, sizeof *tmp);
    if (!tmp) { snprintf(perr, sizeof perr, "out of memory"); return -1; }
    glob_t g = { max_queue_ns, default_block, filtering, { 0 } };
    for (int i = 0; i < 16; i++) g.sys_en[i] = 1;          /* absent from the file = enabled */
    int n = 0;
    if (parse_config(path, tmp, &n, &g)) { free(tmp); return -1; }
    ng_mutex_lock(&lk);
    for (int i = 0; i < n; i++)               /* keep resolved domain IPs across reloads */
        for (int j = 0; j < nrules; j++)
            if (!strcmp(tmp[i].name, rules[j].name)) {
                memcpy(tmp[i].dyn, rules[j].dyn, sizeof tmp[i].dyn);
                tmp[i].n_dyn = rules[j].n_dyn;
            }
    memset(rules, 0, MAX_RULES * sizeof *rules);
    memcpy(rules, tmp, (size_t)n * sizeof *rules);
    nrules = n; max_queue_ns = g.qns; default_block = g.def_block; filtering = g.filtering;
    for (int i = 0; i < NSYS; i++) sysr[i].enabled = g.sys_en[i];
    rules_gen++;
    memset(&ctr[2], 0, MAX_RULES * sizeof *ctr);
    ng_mutex_unlock(&lk);
    free(tmp);
    resolve_now = 1;
    return 0;
}

static void remember_mtime(void) {
    struct stat st;
    if (!stat(cfg_path, &st)) cfg_mtime = st.st_mtime;
}

int engine_load(const char *path) {
    if (init_once()) return -1;
    if (apply_file(path)) { ng_log(NG_LOG_WARN, "config not applied; keeping previous rules"); return -1; }
    if (path != cfg_path) snprintf(cfg_path, sizeof cfg_path, "%s", path);
    remember_mtime();
    ng_log(NG_LOG_INFO, "loaded %d rules from %s (default=%s, filtering=%s, queue %llu ms)", nrules, cfg_path,
           default_block ? "block" : "allow", filtering ? "on" : "OFF", (unsigned long long)(max_queue_ns / 1000000ull));
    return 0;
}

int engine_get_config(sb_t *o) {
    FILE *f = fopen(cfg_path, "rb");
    if (!f) return -1;
    char buf[4096]; size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) sb_printf(o, "%.*s", (int)n, buf);
    fclose(f);
    return 0;
}

int engine_save_config(const char *text, size_t n, char *err, size_t errn) {
    char tmp[300], bak[300];
    if (init_once() || !cfg_path[0]) { snprintf(err, errn, "engine not ready"); return -1; }
    snprintf(tmp, sizeof tmp, "%s.tmp", cfg_path);
    snprintf(bak, sizeof bak, "%s.bak", cfg_path);
    FILE *f = fopen(tmp, "wb");
    if (!f) { snprintf(err, errn, "cannot write %s", tmp); return -1; }
    fwrite(text, 1, n, f); fclose(f);
    if (apply_file(tmp)) {                    /* parse errors leave the running rules untouched */
        snprintf(err, errn, "%s", perr[0] ? perr : "invalid configuration");
        remove(tmp);
        return -1;
    }
#ifdef _WIN32
    MoveFileExA(cfg_path, bak, MOVEFILE_REPLACE_EXISTING);
    MoveFileExA(tmp, cfg_path, MOVEFILE_REPLACE_EXISTING);
#else
    rename(cfg_path, bak);
    rename(tmp, cfg_path);
#endif
    remember_mtime();
    ng_log(NG_LOG_INFO, "configuration saved from GUI: %d rules (default=%s)", nrules, default_block ? "block" : "allow");
    return 0;
}

/* ---------------------------------------------------------- applications */
int engine_app_id(const char *path) {
    if (!path || !*path || init_once()) return 0;
    char lp[PATHLEN]; lower_copy(lp, sizeof lp, path);
    ng_mutex_lock(&lk);
    for (int i = 1; i < napps; i++) if (!strcmp(apps[i].lpath, lp)) { ng_mutex_unlock(&lk); return i; }
    if (napps >= MAX_APPS) { ng_mutex_unlock(&lk); return 0; }
    app_t *a = &apps[napps];
    snprintf(a->path, sizeof a->path, "%s", path);
    memcpy(a->lpath, lp, sizeof lp);
    a->base = base_of(a->path); a->lbase = base_of(a->lpath);
    a->seen_ns = ng_now_ns();
    int id = napps++;
    ng_mutex_unlock(&lk);
    return id;
}

void engine_set_app_support(int on)      { app_support = on; }
void engine_set_self_app(int id)         { self_app = id; }
void engine_set_exempt_port(int port)    { exempt_port = (uint16_t)port; }
void engine_set_loopback_active(int on)  { loopback_active = on; }
void engine_set_capture_mode(int enforcing) { capture_enforcing = enforcing; }
void engine_set_paused(int on)  { paused = on != 0; ng_log(NG_LOG_INFO, "filtering %s", on ? "PAUSED: all traffic passes untouched" : "resumed"); }
int  engine_is_paused(void)     { return paused; }

/* Does any rule actually change a packet's fate? If not, the backend can just WATCH copies of the traffic
 * (monitor-only): the real packets are never slowed down. Allow-rules cannot change anything while the
 * default is "allow"; block / limit rules and "Block unlisted apps" can. */
int engine_needs_enforcement(void) {
    int need = 0;
    if (!rules) return 0;
    ng_mutex_lock(&lk);
    if (filtering && !paused) {
        if (default_block && app_support) need = 1;
        for (int i = 0; i < nrules && !need; i++)
            if (rules[i].enabled && rules[i].action != A_ALLOW) need = 1;
    }
    ng_mutex_unlock(&lk);
    return need;
}

int engine_wants_loopback(void) {
    int w = 0;
    if (!rules) return 0;
    ng_mutex_lock(&lk);
    for (int i = 0; i < nrules; i++) if (rules[i].enabled && rules[i].loop_ok) w = 1;
    ng_mutex_unlock(&lk);
    return w;
}

static int app_matches_rule(const app_t *a, const rule_t *r) {
    for (int k = 0; k < r->n_app; k++)
        if (!strcmp(r->app_is_path[k] ? a->lpath : a->lbase, r->app[k])) return 1;
    return 0;
}
static void app_refresh_bits(app_t *a) {                   /* lock held */
    memset(a->bits, 0, sizeof a->bits);
    for (int i = 0; i < nrules; i++)
        if (rules[i].n_app && app_matches_rule(a, &rules[i])) a->bits[i >> 6] |= 1ull << (i & 63);
    a->gen = rules_gen;
}

/* ------------------------------------------------------------ matching */
static int rule_match(const rule_t *r, const ng_pkt_t *p) {
    if (r->proto && r->proto != p->proto) return 0;
    if (r->port_hi) {
        int hit = (p->remote_port >= r->port_lo && p->remote_port <= r->port_hi) ||
                  (p->local_port  >= r->port_lo && p->local_port  <= r->port_hi);
        if (!hit) return 0;
    }
    if (!r->n_nets && !r->n_dom) return !p->loopback;   /* "all traffic" never touches localhost */
    /* a domain rule that has not resolved yet matches nothing (never "everything") */
    for (int i = 0; i < r->n_nets; i++) if (net_match(&r->nets[i], p->remote)) return 1;
    for (int i = 0; i < r->n_dyn;  i++) if (net_match(&r->dyn[i],  p->remote)) return 1;
    return 0;
}

/* ------------------------------------------------------------- judging */
static int sys_match(const ng_pkt_t *p) {                  /* lock held; index of whitelist item or -1 */
    for (int i = 0; i < NSYS; i++) {
        if (!sysr[i].enabled) continue;
        for (int k = 0; k < sysr[i].nm; k++) {
            const sm_t *m = &sysr[i].m[k];
            if (m->proto && m->proto != p->proto) continue;
            if (m->hi && !((p->remote_port >= m->lo && p->remote_port <= m->hi) ||
                           (p->local_port  >= m->lo && p->local_port  <= m->hi))) continue;
            return i;
        }
    }
    return -1;
}

void engine_judge(const ng_pkt_t *p, ng_verdict_t *v) {
    uint64_t now = ng_now_ns();
    int d = p->dir & 1, hit = -1, sys_hit = -1, kind = 0, logit = 0;
    int appid = (p->app > 0 && p->app < MAX_APPS) ? p->app : 0;
    uint32_t supp = 0; char name[48] = "", appname[64] = "";
    v->act = NG_PASS; v->release_ns = now;

    /* never filter ourselves (DNS lookups, dashboard) */
    if ((self_app > 0 && appid == self_app) ||
        (p->loopback && exempt_port && (p->remote_port == exempt_port || p->local_port == exempt_port)))
        return;

    ng_mutex_lock(&lk);
    app_t *a = &apps[appid];
    if (a->gen != rules_gen) app_refresh_bits(a);
    a->seen_ns = now;

    if (filtering && !paused) {
        if (!p->loopback) sys_hit = sys_match(p);          /* built-in default whitelist: always first */
        if (sys_hit < 0)
            for (int i = 0; i < nrules; i++) {
                const rule_t *r = &rules[i];
                if (!r->enabled) continue;
                if (r->n_app && !((a->bits[i >> 6] >> (i & 63)) & 1)) continue;
                if (rule_match(r, p)) { hit = i; break; }
            }
    }
    ctr_t *c = &ctr[hit < 0 ? 1 : 2 + hit];
    if (sys_hit >= 0) {
        /* whitelisted by a built-in default: pass untouched, no limits */
    } else if (hit >= 0) {
        rule_t *r = &rules[hit];
        if (r->action == A_BLOCK) {
            v->act = NG_DROP; kind = 1;
        } else if (r->action == A_LIMIT && r->rate[d]) {
            uint64_t tx = (uint64_t)p->len * 1000000000ull / r->rate[d];
            uint64_t nf = r->next_free[d];
            if (nf <= now)                      r->next_free[d] = now + tx;         /* line idle: send now */
            else if (nf - now > max_queue_ns) { v->act = NG_DROP; kind = 2; }     /* backlog too deep    */
            else { v->act = NG_DELAY; v->release_ns = nf; r->next_free[d] = nf + tx; }
        }
    } else if (filtering && !paused && default_block && app_support && !p->loopback) {
        v->act = NG_DROP; kind = 3;                                                /* default: block */
    }
    if (kind) {
        uint64_t *ll = kind == 3 ? &a->last_log_ns : &rules[hit].last_log_ns;
        uint32_t *sp = kind == 3 ? &a->suppressed  : &rules[hit].suppressed;
        if (now - *ll >= 2000000000ull) {
            logit = 1; supp = *sp; *sp = 0; *ll = now;
            snprintf(name, sizeof name, "%s", kind == 3 ? "(default)" : rules[hit].name);
            snprintf(appname, sizeof appname, "%s", a->base);
        } else (*sp)++;
    }
    if (v->act == NG_DROP) { c->drops++; ctr[0].drops++; a->drops++; }
    else {
        if (sys_hit >= 0) { sysr[sys_hit].bytes[d] += p->len; sysr[sys_hit].pkts[d]++; }
        else              { c->bytes[d] += p->len; c->pkts[d]++; }
        ctr[0].bytes[d] += p->len; ctr[0].pkts[d]++;
        a->bytes[d] += p->len;
    }
    ng_mutex_unlock(&lk);

    if (logit) {                    /* log outside the lock, throttled to 1 line / 2 s / rule */
        char ip[64]; addr_str(p->remote, ip, sizeof ip);
        ng_log(NG_LOG_INFO, "%s rule=%s app=%s %s proto=%u remote=%s:%u (+%u similar)",
               kind == 2 ? "QUEUE-DROP" : "BLOCK", name, appname, d == NG_OUT ? "up" : "down",
               p->proto, ip, p->remote_port, supp);
    }
}

/* --------------------------------------------------------- statistics */
static void sample(uint64_t elapsed_ns) {
    if (!elapsed_ns) return;
    ng_mutex_lock(&lk);
    for (int i = 0; i < 2 + MAX_RULES; i++)
        for (int d = 0; d < 2; d++) {
            uint64_t delta = ctr[i].bytes[d] - ctr[i].last_bytes[d];
            ctr[i].last_bytes[d] = ctr[i].bytes[d];
            ctr[i].hist[d][hist_pos] = (uint64_t)((double)delta * 8e9 / (double)elapsed_ns);
        }
    for (int i = 0; i < napps; i++)
        for (int d = 0; d < 2; d++) {
            uint64_t delta = apps[i].bytes[d] - apps[i].last_bytes[d];
            apps[i].last_bytes[d] = apps[i].bytes[d];
            apps[i].rate[d] = (uint64_t)((double)delta * 8e9 / (double)elapsed_ns);
        }
    for (int i = 0; i < NSYS; i++)
        for (int d = 0; d < 2; d++) {
            uint64_t delta = sysr[i].bytes[d] - sysr[i].last_bytes[d];
            sysr[i].last_bytes[d] = sysr[i].bytes[d];
            sysr[i].rate[d] = (uint64_t)((double)delta * 8e9 / (double)elapsed_ns);
        }
    hist_pos = (hist_pos + 1) % HIST;
    if (hist_n < HIST) hist_n++;
    ng_mutex_unlock(&lk);
}

void engine_json_system(sb_t *o) {
    ng_mutex_lock(&lk);
    sb_printf(o, "{\"items\":[");
    for (int i = 0; i < NSYS; i++) {
        const sys_t *s = &sysr[i];
        sb_printf(o, "%s{\"name\":\"%s\",\"label\":", i ? "," : "", s->name); json_str(o, s->label);
        sb_printf(o, ",\"detail\":"); json_str(o, s->detail);
        sb_printf(o, ",\"enabled\":%s,\"up_bps\":%llu,\"down_bps\":%llu,\"up_bytes\":%llu,\"down_bytes\":%llu}",
                  s->enabled ? "true" : "false",
                  (unsigned long long)s->rate[NG_OUT], (unsigned long long)s->rate[NG_IN],
                  (unsigned long long)s->bytes[NG_OUT], (unsigned long long)s->bytes[NG_IN]);
    }
    sb_printf(o, "]}");
    ng_mutex_unlock(&lk);
}

void engine_json_stats(sb_t *o) {
    int wants = 0;
    ng_mutex_lock(&lk);
    for (int i = 0; i < nrules; i++) if (rules[i].enabled && rules[i].loop_ok) wants = 1;
    int last = (hist_pos + HIST - 1) % HIST;
    sb_printf(o, "{\"queue_ms\":%llu,\"default\":\"%s\",\"filtering\":%s,\"app_support\":%s,"
                 "\"loopback_wanted\":%s,\"loopback_active\":%s,\"enforcing\":%s,\"paused\":%s,\"rules\":[",
              (unsigned long long)(max_queue_ns / 1000000ull), default_block ? "block" : "allow",
              filtering ? "true" : "false", app_support ? "true" : "false",
              wants ? "true" : "false", loopback_active ? "true" : "false", capture_enforcing ? "true" : "false",
              paused ? "true" : "false");
    for (int i = 0; i < 2 + nrules; i++) {
        const rule_t *r = i >= 2 ? &rules[i - 2] : NULL;
        const ctr_t  *c = &ctr[i];
        unsigned long long ub = hist_n ? c->hist[NG_OUT][last] : 0, db = hist_n ? c->hist[NG_IN][last] : 0;
        sb_printf(o, "%s{\"i\":%d,\"name\":\"%s\",\"action\":\"%s\",\"up_bps\":%llu,\"down_bps\":%llu,"
                     "\"up_bytes\":%llu,\"down_bytes\":%llu,\"drops\":%llu,\"limit_up\":%llu,\"limit_down\":%llu}",
                  i ? "," : "", i,
                  i == 0 ? "TOTAL" : i == 1 ? "(unmatched)" : r->name,
                  r ? act_name[r->action] : "-", ub, db,
                  (unsigned long long)c->bytes[NG_OUT], (unsigned long long)c->bytes[NG_IN],
                  (unsigned long long)c->drops,
                  (unsigned long long)(r ? r->rate[NG_OUT] * 8 : 0),
                  (unsigned long long)(r ? r->rate[NG_IN]  * 8 : 0));
    }
    sb_printf(o, "]}");
    ng_mutex_unlock(&lk);
}

void engine_json_apps(sb_t *o) {
    uint64_t now = ng_now_ns();
    ng_mutex_lock(&lk);
    sb_printf(o, "{\"apps\":[");
    int first = 1;
    for (int i = 1; i < napps; i++) {                  /* 0 = unknown, listed last */
        const app_t *a = &apps[i];
        sb_printf(o, "%s{\"id\":%d,\"name\":", first ? "" : ",", i); first = 0;
        json_str(o, a->base);
        sb_printf(o, ",\"path\":"); json_str(o, a->path);
        sb_printf(o, ",\"up_bps\":%llu,\"down_bps\":%llu,\"up_bytes\":%llu,\"down_bytes\":%llu,\"drops\":%llu,\"seen_s\":%llu}",
                  (unsigned long long)a->rate[NG_OUT], (unsigned long long)a->rate[NG_IN],
                  (unsigned long long)a->bytes[NG_OUT], (unsigned long long)a->bytes[NG_IN],
                  (unsigned long long)a->drops, (unsigned long long)((now - a->seen_ns) / 1000000000ull));
    }
    const app_t *u = &apps[0];
    sb_printf(o, "%s{\"id\":0,\"name\":\"(unknown)\",\"path\":\"\",\"up_bps\":%llu,\"down_bps\":%llu,"
                 "\"up_bytes\":%llu,\"down_bytes\":%llu,\"drops\":%llu,\"seen_s\":%llu}]}",
              first ? "" : ",", (unsigned long long)u->rate[NG_OUT], (unsigned long long)u->rate[NG_IN],
              (unsigned long long)u->bytes[NG_OUT], (unsigned long long)u->bytes[NG_IN],
              (unsigned long long)u->drops, (unsigned long long)((now - u->seen_ns) / 1000000000ull));
    ng_mutex_unlock(&lk);
}

int engine_json_history(int idx, sb_t *o) {
    ng_mutex_lock(&lk);
    if (idx < 0 || idx >= 2 + nrules) { ng_mutex_unlock(&lk); return -1; }
    int start = (hist_pos - hist_n + HIST) % HIST;
    sb_printf(o, "{\"step_s\":1,\"up\":[");
    for (int k = 0; k < hist_n; k++)
        sb_printf(o, "%s%llu", k ? "," : "", (unsigned long long)ctr[idx].hist[NG_OUT][(start + k) % HIST]);
    sb_printf(o, "],\"down\":[");
    for (int k = 0; k < hist_n; k++)
        sb_printf(o, "%s%llu", k ? "," : "", (unsigned long long)ctr[idx].hist[NG_IN][(start + k) % HIST]);
    sb_printf(o, "]}");
    ng_mutex_unlock(&lk);
    return 0;
}

/* ----------------------------------------------------- DNS resolution */
typedef struct { char name[40]; char dom[MAX_DOMS][128]; int n_dom; net_t dyn[MAX_NETS]; int n_dyn; } job_t;

static void resolver_pass(void) {
    job_t *jobs = calloc(MAX_RULES, sizeof *jobs);
    if (!jobs) return;
    int nj = 0;
    ng_mutex_lock(&lk);
    for (int i = 0; i < nrules; i++)
        if (rules[i].n_dom) {
            snprintf(jobs[nj].name, sizeof jobs[nj].name, "%s", rules[i].name);
            memcpy(jobs[nj].dom, rules[i].dom, sizeof jobs[nj].dom);
            jobs[nj].n_dom = rules[i].n_dom; nj++;
        }
    ng_mutex_unlock(&lk);

    for (int j = 0; j < nj; j++) {                  /* blocking DNS, lock NOT held */
        job_t *jb = &jobs[j];
        for (int d = 0; d < jb->n_dom; d++) {
            struct addrinfo hints, *res = NULL, *a;
            memset(&hints, 0, sizeof hints);
            hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
            if (getaddrinfo(jb->dom[d], NULL, &hints, &res)) {
                ng_log(NG_LOG_WARN, "rule %s: cannot resolve %s", jb->name, jb->dom[d]);
                continue;
            }
            for (a = res; a && jb->n_dyn < MAX_NETS; a = a->ai_next) {
                net_t n; memset(&n, 0, sizeof n);
                if (a->ai_family == AF_INET) {
                    n.a[10] = n.a[11] = 0xff;
                    memcpy(n.a + 12, &((struct sockaddr_in *)a->ai_addr)->sin_addr, 4);
                } else if (a->ai_family == AF_INET6) {
                    memcpy(n.a, &((struct sockaddr_in6 *)a->ai_addr)->sin6_addr, 16);
                } else continue;
                n.prefix = 128;
                int dup = 0;
                for (int k = 0; k < jb->n_dyn; k++) if (!memcmp(&jb->dyn[k], &n, sizeof n)) dup = 1;
                if (!dup) jb->dyn[jb->n_dyn++] = n;
            }
            freeaddrinfo(res);
        }
    }
    ng_mutex_lock(&lk);
    for (int j = 0; j < nj; j++) {
        if (!jobs[j].n_dyn) continue;               /* keep old IPs on transient DNS failure */
        for (int i = 0; i < nrules; i++)
            if (!strcmp(rules[i].name, jobs[j].name)) {
                memcpy(rules[i].dyn, jobs[j].dyn, sizeof rules[i].dyn);
                rules[i].n_dyn = jobs[j].n_dyn;
            }
    }
    ng_mutex_unlock(&lk);
    free(jobs);
}

/* ------------------------------------------------------------- workers */
static void sampler_thread(void *arg) {
    (void)arg;
    uint64_t last = ng_now_ns();
    int warned = 0;
    while (ng_running) {
        ng_sleep_ms(1000);
        uint64_t now = ng_now_ns();
        sample(now - last); last = now;
        if (default_block && !app_support && !warned) {
            ng_log(NG_LOG_WARN, "default=block is IGNORED: this backend cannot identify applications (Windows backend only)");
            warned = 1;
        } else if (!default_block) warned = 0;
        struct stat st;                              /* hot-reload when the file is edited by hand */
        if (cfg_path[0] && !stat(cfg_path, &st) && st.st_mtime != cfg_mtime) {
            char p[sizeof cfg_path];
            cfg_mtime = st.st_mtime;                 /* also set on failure: retry only after next edit */
            snprintf(p, sizeof p, "%s", cfg_path);
            ng_log(NG_LOG_INFO, "config changed, reloading");
            engine_load(p);
        }
    }
}

static void resolver_thread(void *arg) {
    (void)arg;
    unsigned waited = 0;
    while (ng_running) {
        if (resolve_now || waited >= 60000) { resolve_now = 0; waited = 0; resolver_pass(); }
        ng_sleep_ms(250); waited += 250;
    }
}

void engine_start_workers(void) {
    ng_thread_start(sampler_thread, NULL);
    ng_thread_start(resolver_thread, NULL);
}
