/* web.c - dashboard + management GUI server (127.0.0.1 only), JSON API */
#include "common.h"
#include "engine.h"
#include "web.h"
#include "index_html.h"          /* generated from web/index.html by tools/embed.py */
#include <ctype.h>
#ifndef _WIN32
  #include <sys/socket.h>
  #include <sys/select.h>
  #include <sys/time.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  typedef int sock_t;
  #define BAD_SOCK (-1)
  #define closesock close
#else
  typedef SOCKET sock_t;
  #define BAD_SOCK INVALID_SOCKET
  #define closesock closesocket
#endif

static sock_t g_srv = BAD_SOCK;
static char   g_req[140000];     /* single-threaded server: one static request buffer */

static void send_all(sock_t s, const char *p, size_t n) {
    while (n) {
        int w = (int)send(s, p, (int)n, 0);
        if (w <= 0) return;
        p += w; n -= (size_t)w;
    }
}

static const char *status_text(int c) {
    switch (c) {
        case 200: return "OK";            case 400: return "Bad Request";
        case 403: return "Forbidden";     case 404: return "Not Found";
        case 405: return "Method Not Allowed"; case 413: return "Payload Too Large";
        default:  return "Error";
    }
}

static void reply(sock_t s, int code, const char *ctype, const char *body, size_t n) {
    char h[256];
    int hl = snprintf(h, sizeof h,
        "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %lu\r\n"
        "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        code, status_text(code), ctype, (unsigned long)n);
    send_all(s, h, (size_t)hl);
    if (n) send_all(s, body, n);
}
static void reply_str(sock_t s, int code, const char *ctype, const char *body) { reply(s, code, ctype, body, strlen(body)); }

/* case-insensitive strstr (header names are case-insensitive) */
static const char *ci_find(const char *h, const char *needle) {
    size_t nl = strlen(needle);
    for (; *h; h++) {
        size_t i = 0;
        while (i < nl && h[i] && tolower((unsigned char)h[i]) == tolower((unsigned char)needle[i])) i++;
        if (i == nl) return h;
    }
    return NULL;
}

/* reads headers + body; returns body offset (>0), or -1 error, -2 too big. NUL-terminates the headers. */
static int read_request(sock_t c, int *body_len) {
    int n = 0; *body_len = 0;
    for (;;) {
        int r = (int)recv(c, g_req + n, (int)(sizeof g_req - 1 - (size_t)n), 0);
        if (r <= 0) return -1;
        n += r; g_req[n] = 0;
        char *he = strstr(g_req, "\r\n\r\n");
        if (he) {
            int hl = (int)(he - g_req) + 4;
            g_req[hl - 4] = 0;                       /* headers end here for all later searches */
            const char *p = ci_find(g_req, "\r\nContent-Length:");
            long cl = p ? strtol(p + 17, NULL, 10) : 0;
            if (cl < 0 || cl > (long)sizeof g_req - hl - 1) return -2;
            while (n < hl + cl) {
                r = (int)recv(c, g_req + n, (int)(sizeof g_req - 1 - (size_t)n), 0);
                if (r <= 0) return -1;
                n += r;
            }
            g_req[n] = 0; *body_len = (int)cl;
            return hl;
        }
        if (n >= (int)sizeof g_req - 1) return -2;
    }
}

/* value of a request header (case-insensitive name, optional spaces); 0 if absent */
static int hdr_get(const char *h, const char *name, char *out, size_t n) {
    char key[40]; snprintf(key, sizeof key, "\r\n%s:", name);
    const char *p = ci_find(h, key);
    if (!p) return 0;
    p += strlen(key);
    while (*p == ' ' || *p == '\t') p++;
    size_t i = 0;
    while (*p && *p != '\r' && *p != '\n' && i + 1 < n) out[i++] = *p++;
    while (i && (out[i - 1] == ' ' || out[i - 1] == '\t')) i--;
    out[i] = 0;
    return 1;
}

static int ci_prefix(const char *v, const char *pre) {
    for (; *pre; v++, pre++) if (tolower((unsigned char)*v) != *pre) return 0;
    return 1;
}

/* exactly "127.0.0.1" or "localhost", optionally followed by :port - never "localhost.evil.com" */
static int host_ok(const char *v) {
    const char *rest;
    if (ci_prefix(v, "127.0.0.1")) rest = v + 9;
    else if (ci_prefix(v, "localhost")) rest = v + 9;
    else return 0;
    return *rest == 0 || *rest == ':';
}

static int origin_ok(const char *hdr) {              /* browsers add Origin on cross-site POSTs */
    char o[200];
    if (!hdr_get(hdr, "Origin", o, sizeof o)) return 1;
    return ci_prefix(o, "http://") && host_ok(o + 7);
}

static void handle(sock_t c) {
    int blen, boff = read_request(c, &blen);
    if (boff == -2) { reply_str(c, 413, "text/plain", "too large"); return; }
    if (boff < 0) return;
    const char *body = g_req + boff;
    int post = !strncmp(g_req, "POST ", 5);
    if (!post && strncmp(g_req, "GET ", 4)) { reply_str(c, 405, "text/plain", "method not allowed"); return; }
    /* DNS-rebinding guard: only answer to loopback host names */
    char hv[200];
    if (!hdr_get(g_req, "Host", hv, sizeof hv) || !host_ok(hv)) { reply_str(c, 403, "text/plain", "forbidden"); return; }
    /* CSRF guard for writes: a custom header (forces a CORS preflight that we never grant) + same-site Origin.
       Must be evaluated BEFORE the request line is cut below, which would hide the headers. */
    int csrf_ok = hdr_get(g_req, "X-NetGuard", hv, sizeof hv) && !strcmp(hv, "1") && origin_ok(g_req);
    char *path = g_req + (post ? 5 : 4), *sp = strchr(path, ' ');
    if (!sp) return;
    *sp = 0;

    if (post) {
        if (!csrf_ok) { reply_str(c, 403, "text/plain", "forbidden"); return; }
        if (!strcmp(path, "/api/config")) {
            char err[300] = "";
            if (engine_save_config(body, (size_t)blen, err, sizeof err) == 0) {
                reply_str(c, 200, "application/json", "{\"ok\":true}");
            } else {
                sb_t o = { 0 };
                sb_printf(&o, "{\"ok\":false,\"error\":\"");
                for (const char *e = err; *e; e++) { if (*e == '"' || *e == '\\') sb_printf(&o, "\\"); if ((unsigned char)*e >= 0x20) sb_printf(&o, "%c", *e); }
                sb_printf(&o, "\"}");
                reply(c, 400, "application/json", o.p, o.n); sb_free(&o);
            }
        } else if (!strcmp(path, "/api/pause")) {           /* body "1" = pause, "0" = resume */
            engine_set_paused(blen > 0 && body[0] == '1');
            reply_str(c, 200, "application/json", engine_is_paused() ? "{\"ok\":true,\"paused\":true}" : "{\"ok\":true,\"paused\":false}");
        } else reply_str(c, 404, "text/plain", "not found");
        return;
    }

    if (!strcmp(path, "/")) {
        reply(c, 200, "text/html; charset=utf-8", (const char *)ng_index_html, ng_index_html_len);
    } else if (!strcmp(path, "/api/stats")) {
        sb_t o = { 0 }; engine_json_stats(&o);
        reply(c, 200, "application/json", o.p ? o.p : "{}", o.n); sb_free(&o);
    } else if (!strcmp(path, "/api/system")) {
        sb_t o = { 0 }; engine_json_system(&o);
        reply(c, 200, "application/json", o.p ? o.p : "{}", o.n); sb_free(&o);
    } else if (!strcmp(path, "/api/apps")) {
        sb_t o = { 0 }; engine_json_apps(&o);
        reply(c, 200, "application/json", o.p ? o.p : "{}", o.n); sb_free(&o);
    } else if (!strcmp(path, "/api/config")) {
        sb_t o = { 0 };
        if (!engine_get_config(&o)) reply(c, 200, "text/plain; charset=utf-8", o.p ? o.p : "", o.n);
        else reply_str(c, 404, "text/plain", "no config");
        sb_free(&o);
    } else if (!strncmp(path, "/api/history?i=", 15)) {
        sb_t o = { 0 };
        if (!engine_json_history(atoi(path + 15), &o)) reply(c, 200, "application/json", o.p, o.n);
        else reply_str(c, 404, "text/plain", "no such series");
        sb_free(&o);
    } else reply_str(c, 404, "text/plain", "not found");
}

static void serve(void *arg) {
    (void)arg;
    while (ng_running) {
        fd_set fds; FD_ZERO(&fds); FD_SET(g_srv, &fds);
        struct timeval tv = { 0, 500000 };
        if (select((int)g_srv + 1, &fds, NULL, NULL, &tv) <= 0) continue;
        sock_t c = accept(g_srv, NULL, NULL);
        if (c == BAD_SOCK) continue;
#ifdef _WIN32
        DWORD to = 2000; setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (const char *)&to, sizeof to);
#else
        struct timeval to = { 2, 0 }; setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof to);
#endif
        handle(c);
        closesock(c);
    }
    closesock(g_srv);
}

int web_start(int port) {                           /* returns the port actually used, or -1 */
    for (int p = port; p < port + 10; p++) {
        g_srv = socket(AF_INET, SOCK_STREAM, 0);
        if (g_srv == BAD_SOCK) return -1;
#ifndef _WIN32
        int one = 1; setsockopt(g_srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#endif
        struct sockaddr_in a; memset(&a, 0, sizeof a);
        a.sin_family = AF_INET; a.sin_port = htons((uint16_t)p);
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (!bind(g_srv, (struct sockaddr *)&a, sizeof a) && !listen(g_srv, 8))
            return ng_thread_start(serve, NULL) ? -1 : p;
        closesock(g_srv); g_srv = BAD_SOCK;               /* port busy: try the next one */
    }
    return -1;
}
