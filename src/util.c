/* util.c - logging with rotation, string builder, IP header parser */
#include "common.h"
#include "engine.h"
#include <stdarg.h>
#include <time.h>

/* ------------------------------------------------------------ logging */
#define LOG_MAX_BYTES (5L * 1024 * 1024)
#define LOG_KEEP      3

static FILE    *lf;
static char     lpath[260];
static int      lmin = NG_LOG_INFO;
static long     lsize;
static ng_mutex lm;
static volatile int lconsole = 1;
volatile int ng_gui_port;
void (*ng_ready_cb)(void);
char ng_last_error[600];
void ng_log_console(int on) { lconsole = on; }

static void log_rotate(void) {
    char a[300], b[300];
    fclose(lf);
    snprintf(a, sizeof a, "%s.%d", lpath, LOG_KEEP); remove(a);
    for (int i = LOG_KEEP - 1; i >= 1; i--) {
        snprintf(a, sizeof a, "%s.%d", lpath, i);
        snprintf(b, sizeof b, "%s.%d", lpath, i + 1);
        rename(a, b);
    }
    snprintf(a, sizeof a, "%s.1", lpath);
    rename(lpath, a);
    lf = fopen(lpath, "a");
    lsize = 0;
}

int ng_log_open(const char *path, int min_level) {
    ng_mutex_init(&lm);
    lmin = min_level;
    if (!path) return 0;
    snprintf(lpath, sizeof lpath, "%s", path);
    lf = fopen(lpath, "a");
    if (!lf) { fprintf(stderr, "cannot open log file %s\n", path); return -1; }
    fseek(lf, 0, SEEK_END);
    lsize = ftell(lf);
    return 0;
}

void ng_log(int level, const char *fmt, ...) {
    if (level < lmin) return;
    static const char *nm[] = { "DEBUG", "INFO", "WARN", "ERROR" };
    char msg[600];
    va_list ap; va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    time_t t = time(NULL);
    ng_mutex_lock(&lm);
    char ts[32];
    struct tm *tmv = localtime(&t);            /* protected by lm */
    strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", tmv);
    if (lconsole) { fprintf(stdout, "%s %-5s %s\n", ts, nm[level], msg); fflush(stdout); }
    if (level >= NG_LOG_ERROR) snprintf(ng_last_error, sizeof ng_last_error, "%s", msg);
    if (lf) {
        int n = fprintf(lf, "%s %-5s %s\n", ts, nm[level], msg);
        fflush(lf);
        if (n > 0) lsize += n;
        if (lsize > LOG_MAX_BYTES) log_rotate();
    }
    ng_mutex_unlock(&lm);
}

/* ------------------------------------------------------ string builder */
void sb_printf(sb_t *s, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    for (;;) {
        size_t room = s->cap - s->n;
        va_list c; va_copy(c, ap);
        int w = vsnprintf(s->p ? s->p + s->n : NULL, room, fmt, c);
        va_end(c);
        if (w < 0) break;
        if ((size_t)w < room) { s->n += (size_t)w; break; }
        size_t nc = s->cap ? s->cap * 2 : 1024;
        while (nc - s->n <= (size_t)w) nc *= 2;
        char *np = realloc(s->p, nc);
        if (!np) break;
        s->p = np; s->cap = nc;
    }
    va_end(ap);
}
void sb_putn(sb_t *s, const char *p, size_t n) {
    if (s->n + n + 1 > s->cap) {
        size_t nc = s->cap ? s->cap : 1024;
        while (nc < s->n + n + 1) nc *= 2;
        char *np = realloc(s->p, nc);
        if (!np) return;
        s->p = np; s->cap = nc;
    }
    memcpy(s->p + s->n, p, n); s->n += n; s->p[s->n] = 0;
}
void sb_free(sb_t *s) { free(s->p); s->p = NULL; s->n = s->cap = 0; }

/* ------------------------------------------------------ IP header parse */
int ng_parse_ip(const uint8_t *d, size_t n, ng_ipinfo_t *o) {
    memset(o, 0, sizeof *o);
    if (n < 20) return -1;
    int ver = d[0] >> 4;
    if (ver == 4) {
        size_t hl = (size_t)(d[0] & 15) * 4;
        if (hl < 20 || n < hl) return -1;
        o->proto = d[9];
        o->len   = (uint32_t)((d[2] << 8) | d[3]);
        o->src[10] = o->src[11] = 0xff; memcpy(o->src + 12, d + 12, 4);
        o->dst[10] = o->dst[11] = 0xff; memcpy(o->dst + 12, d + 16, 4);
        int frag = ((d[6] & 0x1f) << 8) | d[7];
        if (!frag && (o->proto == 6 || o->proto == 17) && n >= hl + 4) {
            o->sport = (uint16_t)((d[hl] << 8) | d[hl + 1]);
            o->dport = (uint16_t)((d[hl + 2] << 8) | d[hl + 3]);
        }
    } else if (ver == 6) {
        if (n < 40) return -1;
        o->proto = d[6];
        o->len   = 40u + (uint32_t)((d[4] << 8) | d[5]);
        memcpy(o->src, d + 8, 16);
        memcpy(o->dst, d + 24, 16);
        if ((o->proto == 6 || o->proto == 17) && n >= 44) {
            o->sport = (uint16_t)((d[40] << 8) | d[41]);
            o->dport = (uint16_t)((d[42] << 8) | d[43]);
        }
    } else return -1;
    if (o->len == 0) o->len = (uint32_t)n;   /* e.g. GSO/TSO super-packets */
    return 0;
}

void ng_fill_pkt(const ng_ipinfo_t *ip, int dir, ng_pkt_t *p) {
    p->dir = (uint8_t)dir; p->proto = ip->proto; p->len = ip->len;
    p->app = 0; p->loopback = 0;                 /* backends fill these in */
    memcpy(p->remote, dir == NG_OUT ? ip->dst : ip->src, 16);
    p->remote_port = dir == NG_OUT ? ip->dport : ip->sport;
    p->local_port  = dir == NG_OUT ? ip->sport : ip->dport;
}
