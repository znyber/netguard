/* backend_win.c - WinDivert backend with per-application attribution (Windows 10/11).
 *
 *  NETWORK handle : captures every packet; engine decides PASS / DROP / DELAY
 *  FLOW handle    : sniffs "flow established/deleted" events, which carry the owning process id
 *                   -> flow table (5-tuple -> application)
 *  iphlpapi tables: snapshot every 2 s: connections that existed before we started, listening
 *                   ports (inbound SYNs arrive before any flow event) and a port->app fallback
 *
 * Needs Administrator, WinDivert.dll + WinDivert64.sys (or 32) next to the exe.
 */
#include "common.h"
#include "engine.h"
#include "backend.h"
#include "delayq.h"
#include <windivert.h>
#include <mmsystem.h>     /* timeBeginPeriod; links with winmm */
#include <iphlpapi.h>     /* GetExtendedTcpTable; links with iphlpapi */

static HANDLE g_h  = INVALID_HANDLE_VALUE;    /* NETWORK layer */
static HANDLE g_hf = INVALID_HANDLE_VALUE;    /* FLOW layer    */

/* ------------------------------------------------ pid -> application id */
typedef struct { DWORD pid; int app; uint64_t ts; } pc_t;
static pc_t     pcache[128];
static ng_mutex pc_lock;

static int app_from_pid(DWORD pid) {
    uint64_t now = ng_now_ns();
    pc_t *e = &pcache[pid & 127];
    ng_mutex_lock(&pc_lock);
    if (e->ts && e->pid == pid && now - e->ts < 5000000000ull) { int a = e->app; ng_mutex_unlock(&pc_lock); return a; }
    ng_mutex_unlock(&pc_lock);

    char path8[1100]; path8[0] = 0;
    if (pid == 4) snprintf(path8, sizeof path8, "System");
    else if (pid != 0) {
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (h) {
            WCHAR w[1024]; DWORD n = 1024;
            if (QueryFullProcessImageNameW(h, 0, w, &n)) {
                int k = WideCharToMultiByte(CP_UTF8, 0, w, (int)n, path8, (int)sizeof path8 - 1, NULL, NULL);
                path8[k > 0 ? k : 0] = 0;
            }
            CloseHandle(h);
        }
    }
    int app = path8[0] ? engine_app_id(path8) : 0;       /* short-lived / inaccessible process -> unknown */
    ng_mutex_lock(&pc_lock);
    e->pid = pid; e->app = app; e->ts = now;
    ng_mutex_unlock(&pc_lock);
    return app;
}

/* ------------------------------------------------------------ flow table */
typedef struct { uint8_t proto; uint16_t lport, rport; uint8_t laddr[16], raddr[16]; } fkey_t;
typedef struct { fkey_t k; uint8_t used; int16_t app; uint64_t expire_ns, last_ns; } fent_t;   /* used: 0 empty, 1 live */
#define FT_SIZE 32768                                    /* power of two */
static fent_t  *ft;
static int      ft_live;
static ng_mutex ft_lock;
static int16_t  g_port_tcp[65536], g_port_udp[65536];    /* local port -> app (fallback)  */

static uint32_t fhash(const fkey_t *k) {
    const uint8_t *p = (const uint8_t *)k; uint32_t h = 2166136261u;
    for (size_t i = 0; i < sizeof *k; i++) { h ^= p[i]; h *= 16777619u; }
    return h;
}
static void ft_insert_nolock(const fkey_t *k, int app, uint64_t expire, uint64_t now) {
    uint32_t i = fhash(k) & (FT_SIZE - 1);
    for (uint32_t n = 0; n < FT_SIZE; n++, i = (i + 1) & (FT_SIZE - 1)) {
        fent_t *e = &ft[i];
        if (!e->used) {
            if (ft_live >= FT_SIZE / 2) return;           /* table too full: drop (sweep will free space) */
            e->k = *k; e->used = 1; e->app = (int16_t)app; e->expire_ns = expire; e->last_ns = now; ft_live++;
            return;
        }
        if (!memcmp(&e->k, k, sizeof *k)) { e->app = (int16_t)app; e->expire_ns = expire; e->last_ns = now; return; }
    }
}
static void ft_put(const fkey_t *k, int app, uint64_t expire) {
    uint64_t now = ng_now_ns();
    ng_mutex_lock(&ft_lock); ft_insert_nolock(k, app, expire, now); ng_mutex_unlock(&ft_lock);
}
static int ft_get(const fkey_t *k) {                      /* -1 = not found */
    int app = -1; uint32_t i = fhash(k) & (FT_SIZE - 1);
    ng_mutex_lock(&ft_lock);
    for (uint32_t n = 0; n < FT_SIZE; n++, i = (i + 1) & (FT_SIZE - 1)) {
        fent_t *e = &ft[i];
        if (!e->used) break;
        if (!memcmp(&e->k, k, sizeof *k)) { app = e->app; e->last_ns = ng_now_ns(); break; }
    }
    ng_mutex_unlock(&ft_lock);
    return app;
}
static void ft_expire(const fkey_t *k, uint64_t when) {   /* keep a closing flow around briefly (FIN/ACK tail) */
    uint32_t i = fhash(k) & (FT_SIZE - 1);
    ng_mutex_lock(&ft_lock);
    for (uint32_t n = 0; n < FT_SIZE; n++, i = (i + 1) & (FT_SIZE - 1)) {
        fent_t *e = &ft[i];
        if (!e->used) break;
        if (!memcmp(&e->k, k, sizeof *k)) { e->expire_ns = when; break; }
    }
    ng_mutex_unlock(&ft_lock);
}
static void ft_sweep(void) {                              /* rebuild the table without expired / idle entries */
    static fent_t *tmp;
    if (!tmp && !(tmp = malloc(FT_SIZE * sizeof *tmp))) return;
    uint64_t now = ng_now_ns(); size_t n = 0;
    ng_mutex_lock(&ft_lock);
    for (uint32_t i = 0; i < FT_SIZE; i++) {
        const fent_t *e = &ft[i];
        if (!e->used) continue;
        if ((e->expire_ns && now > e->expire_ns) || now - e->last_ns > 600000000000ull) continue;
        tmp[n++] = *e;
    }
    memset(ft, 0, FT_SIZE * sizeof *ft); ft_live = 0;
    for (size_t j = 0; j < n; j++) ft_insert_nolock(&tmp[j].k, tmp[j].app, tmp[j].expire_ns, tmp[j].last_ns);
    ng_mutex_unlock(&ft_lock);
}

/* WinDivert flow addresses: 4 x UINT32 in host order, last word = first 4 bytes; IPv4 is ::ffff:a.b.c.d */
static void flow_addr(const UINT32 a[4], uint8_t out[16]) {
    for (int k = 0; k < 4; k++) {
        UINT32 w = a[3 - k];
        out[4 * k] = (uint8_t)(w >> 24); out[4 * k + 1] = (uint8_t)(w >> 16);
        out[4 * k + 2] = (uint8_t)(w >> 8); out[4 * k + 3] = (uint8_t)w;
    }
}

static void flow_thread(void *arg) {
    (void)arg;
    WINDIVERT_ADDRESS a; int dbg = 0;
    while (ng_running) {
        if (!WinDivertRecv(g_hf, NULL, 0, NULL, &a)) {
            if (!ng_running || GetLastError() == ERROR_NO_DATA) break;
            ng_sleep_ms(10); continue;
        }
        fkey_t k; memset(&k, 0, sizeof k);
        k.proto = a.Flow.Protocol; k.lport = a.Flow.LocalPort; k.rport = a.Flow.RemotePort;
        flow_addr(a.Flow.LocalAddr, k.laddr); flow_addr(a.Flow.RemoteAddr, k.raddr);
        if (a.Event == WINDIVERT_EVENT_FLOW_ESTABLISHED) {
            int app = app_from_pid(a.Flow.ProcessId);
            ft_put(&k, app, 0);
            if (app > 0) { if (k.proto == 6) g_port_tcp[k.lport] = (int16_t)app; else if (k.proto == 17) g_port_udp[k.lport] = (int16_t)app; }
            if (dbg < 10) { dbg++; ng_log(NG_LOG_DEBUG, "flow pid=%lu proto=%u %u -> %u app=%d", (unsigned long)a.Flow.ProcessId, k.proto, k.lport, k.rport, app); }
        } else if (a.Event == WINDIVERT_EVENT_FLOW_DELETED) {
            ft_expire(&k, ng_now_ns() + 3000000000ull);
        }
    }
}

/* -------------------------------------- snapshot of Windows' own tables */
static void snapshot(void) {
    static int16_t ntcp[65536], nudp[65536];
    memset(ntcp, 0, sizeof ntcp); memset(nudp, 0, sizeof nudp);
    uint64_t exp = ng_now_ns() + 30000000000ull;
    DWORD sz; void *buf;

    sz = 0; GetExtendedTcpTable(NULL, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (sz && (buf = malloc(sz))) {
        PMIB_TCPTABLE_OWNER_PID t = buf;
        if (GetExtendedTcpTable(t, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
            for (DWORD i = 0; i < t->dwNumEntries; i++) {
                const MIB_TCPROW_OWNER_PID *r = &t->table[i];
                int app = app_from_pid(r->dwOwningPid); if (!app) continue;
                uint16_t lp = ntohs((u_short)r->dwLocalPort);
                ntcp[lp] = (int16_t)app;
                if (r->dwState != MIB_TCP_STATE_LISTEN && r->dwRemoteAddr) {
                    fkey_t k; memset(&k, 0, sizeof k);
                    k.proto = 6; k.lport = lp; k.rport = ntohs((u_short)r->dwRemotePort);
                    k.laddr[10] = k.laddr[11] = 0xff; memcpy(k.laddr + 12, &r->dwLocalAddr, 4);
                    k.raddr[10] = k.raddr[11] = 0xff; memcpy(k.raddr + 12, &r->dwRemoteAddr, 4);
                    ft_put(&k, app, exp);
                }
            }
        free(buf);
    }
    sz = 0; GetExtendedTcpTable(NULL, &sz, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    if (sz && (buf = malloc(sz))) {
        PMIB_TCP6TABLE_OWNER_PID t = buf;
        if (GetExtendedTcpTable(t, &sz, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
            for (DWORD i = 0; i < t->dwNumEntries; i++) {
                const MIB_TCP6ROW_OWNER_PID *r = &t->table[i];
                int app = app_from_pid(r->dwOwningPid); if (!app) continue;
                uint16_t lp = ntohs((u_short)r->dwLocalPort);
                ntcp[lp] = (int16_t)app;
                if (r->dwState != MIB_TCP_STATE_LISTEN) {
                    fkey_t k; memset(&k, 0, sizeof k);
                    k.proto = 6; k.lport = lp; k.rport = ntohs((u_short)r->dwRemotePort);
                    memcpy(k.laddr, r->ucLocalAddr, 16); memcpy(k.raddr, r->ucRemoteAddr, 16);
                    ft_put(&k, app, exp);
                }
            }
        free(buf);
    }
    sz = 0; GetExtendedUdpTable(NULL, &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (sz && (buf = malloc(sz))) {
        PMIB_UDPTABLE_OWNER_PID t = buf;
        if (GetExtendedUdpTable(t, &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR)
            for (DWORD i = 0; i < t->dwNumEntries; i++) {
                int app = app_from_pid(t->table[i].dwOwningPid);
                if (app) nudp[ntohs((u_short)t->table[i].dwLocalPort)] = (int16_t)app;
            }
        free(buf);
    }
    sz = 0; GetExtendedUdpTable(NULL, &sz, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    if (sz && (buf = malloc(sz))) {
        PMIB_UDP6TABLE_OWNER_PID t = buf;
        if (GetExtendedUdpTable(t, &sz, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == NO_ERROR)
            for (DWORD i = 0; i < t->dwNumEntries; i++) {
                int app = app_from_pid(t->table[i].dwOwningPid);
                if (app) nudp[ntohs((u_short)t->table[i].dwLocalPort)] = (int16_t)app;
            }
        free(buf);
    }
    memcpy(g_port_tcp, ntcp, sizeof ntcp); memcpy(g_port_udp, nudp, sizeof nudp);
}

static void snapshot_thread(void *arg) {
    (void)arg;
    while (ng_running) {
        for (int i = 0; i < 8 && ng_running; i++) ng_sleep_ms(250);     /* every 2 s */
        snapshot(); ft_sweep();
    }
}

/* ---------------------------------------------- packet -> application */
static int resolve_app(const ng_ipinfo_t *ip, int outbound) {
    fkey_t k; memset(&k, 0, sizeof k);
    k.proto = ip->proto;
    k.lport = outbound ? ip->sport : ip->dport;  k.rport = outbound ? ip->dport : ip->sport;
    memcpy(k.laddr, outbound ? ip->src : ip->dst, 16);
    memcpy(k.raddr, outbound ? ip->dst : ip->src, 16);
    int app = ft_get(&k);
    if (app >= 0) return app;
    if (ip->proto != 6 && ip->proto != 17) return 0;          /* ICMP etc.: no ports -> unknown */
    fkey_t k0 = k; memset(k0.raddr, 0, 16); k0.rport = 0;      /* unconnected UDP socket */
    if ((app = ft_get(&k0)) >= 0) return app;
    app = ip->proto == 6 ? g_port_tcp[k.lport] : g_port_udp[k.lport];
    if (app > 0) return app;
    if (outbound)                                              /* the flow event may be a few microseconds behind */
        for (int i = 0; i < 3; i++) { SwitchToThread(); if ((app = ft_get(&k)) >= 0) return app; }
    return 0;
}

/* ------------------------------------------------------------- packets */
typedef struct { WINDIVERT_ADDRESS addr; UINT len; uint8_t data[]; } held_t;

static int          g_apps_ok;
static volatile int g_mode_enf = -1, g_mode_loop = -1;     /* what the open handle was opened for */

void backend_release(void *cookie) {
    held_t *h = cookie;
    HANDLE hd = g_h;
    if (hd != INVALID_HANDLE_VALUE) WinDivertSend(hd, h->data, h->len, NULL, &h->addr);
    free(h);
}

void backend_stop(void) {
    if (g_h  != INVALID_HANDLE_VALUE) WinDivertShutdown(g_h,  WINDIVERT_SHUTDOWN_BOTH);
    if (g_hf != INVALID_HANDLE_VALUE) WinDivertShutdown(g_hf, WINDIVERT_SHUTDOWN_BOTH);
}
void backend_cleanup(void) {
    if (g_h  != INVALID_HANDLE_VALUE) { WinDivertClose(g_h);  g_h  = INVALID_HANDLE_VALUE; }
    if (g_hf != INVALID_HANDLE_VALUE) { WinDivertClose(g_hf); g_hf = INVALID_HANDLE_VALUE; }
}

static const char *open_err(DWORD e) {
    return e == 5 ? "run as Administrator" : e == 2 ? "WinDivert driver .sys not found next to exe" :
           e == 577 ? "driver signature rejected (Windows 7 needs the SHA-2 update)" :
           e == 1275 ? "driver blocked by security software" : "see WinDivert docs";
}

/* ---- pipelined batches --------------------------------------------------------------------------
 * Receiving (and judging) runs on the capture thread, re-injecting on a second "sender" thread, so the two
 * kernel round trips overlap instead of taking turns. A ring of RING batches of up to BATCH_PKTS packets
 * connects them (single producer, single consumer, strict FIFO, so packet order is preserved).
 * One WinDivertRecvEx / WinDivertSendEx call moves a whole batch instead of one packet. */
#define BATCH_PKTS  64
#define BATCH_BYTES (256 * 1024)
#define RING        8
typedef struct { uint8_t *buf; WINDIVERT_ADDRESS addr[BATCH_PKTS]; UINT len, count; } slot_t;
static slot_t        g_slot[RING];
static HANDLE        g_sem_free, g_sem_full, g_sender;
static volatile LONG g_sender_stop;
static UINT          g_widx, g_ridx;

static DWORD WINAPI sender_thread(LPVOID arg) {
    (void)arg;
    for (;;) {
        WaitForSingleObject(g_sem_full, INFINITE);
        if (g_sender_stop) break;
        slot_t *s = &g_slot[g_ridx];
        g_ridx = (g_ridx + 1) % RING;
        HANDLE h = g_h;
        if (h != INVALID_HANDLE_VALUE)
            WinDivertSendEx(h, s->buf, s->len, NULL, 0, s->addr, s->count * (UINT)sizeof(WINDIVERT_ADDRESS), NULL);
        ReleaseSemaphore(g_sem_free, 1, NULL);
    }
    return 0;
}
static int ring_init(void) {
    for (int i = 0; i < RING; i++) { g_slot[i].buf = malloc(BATCH_BYTES); if (!g_slot[i].buf) return -1; }
    g_sem_free = CreateSemaphoreW(NULL, RING, RING, NULL);
    g_sem_full = CreateSemaphoreW(NULL, 0, RING, NULL);
    if (!g_sem_free || !g_sem_full) return -1;
    g_sender = CreateThread(NULL, 0, sender_thread, NULL, 0, NULL);
    return g_sender ? 0 : -1;
}
static void ring_flush(void) {                            /* every queued batch sent; capture thread must be idle */
    for (int i = 0; i < RING; i++) WaitForSingleObject(g_sem_free, INFINITE);
    ReleaseSemaphore(g_sem_free, RING, NULL);
}
static void ring_close(void) {
    InterlockedExchange(&g_sender_stop, 1);
    ReleaseSemaphore(g_sem_full, 1, NULL);
    if (g_sender) { WaitForSingleObject(g_sender, 3000); CloseHandle(g_sender); g_sender = NULL; }
}

static void packet_loop(int enforce) {
    uint64_t last_err_log = 0;
    for (;;) {
        WaitForSingleObject(g_sem_free, INFINITE);               /* a free batch buffer (back-pressure) */
        slot_t *sl = &g_slot[g_widx];
        UINT rl = 0, alen = (UINT)sizeof sl->addr;
        if (!WinDivertRecvEx(g_h, sl->buf, BATCH_BYTES, &rl, 0, sl->addr, &alen, NULL)) {
            ReleaseSemaphore(g_sem_free, 1, NULL);
            DWORD e = GetLastError();
            if (!ng_running || e == ERROR_NO_DATA) return;       /* shut down (exit or mode switch) */
            uint64_t now = ng_now_ns();
            if (now - last_err_log > 5000000000ull) { last_err_log = now; ng_log(NG_LOG_WARN, "WinDivertRecvEx error %lu", (unsigned long)e); }
            ng_sleep_ms(2);
            continue;
        }
        UINT n = alen / (UINT)sizeof(WINDIVERT_ADDRESS);
        uint8_t *p = sl->buf, *w = sl->buf;
        UINT left = rl, keep = 0;
        for (UINT i = 0; i < n && left > 0; i++) {
            PVOID next = NULL; UINT nextlen = 0;
            if (!WinDivertHelperParsePacket(p, left, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &next, &nextlen)) {
                next = NULL; nextlen = 0;                              /* malformed: treat the rest as one packet */
            }
            UINT plen = left - nextlen;
            WINDIVERT_ADDRESS *a = &sl->addr[i];
            ng_verdict_t v; v.act = NG_PASS; v.release_ns = 0;
            ng_ipinfo_t ip;
            if (ng_parse_ip(p, plen, &ip) == 0) {
                ng_pkt_t pkt;
                ng_fill_pkt(&ip, a->Outbound ? NG_OUT : NG_IN, &pkt);   /* loopback packets are always "outbound" */
                pkt.loopback = (uint8_t)a->Loopback;
                pkt.app = g_apps_ok ? (int16_t)resolve_app(&ip, a->Outbound) : 0;
                engine_judge(&pkt, &v);
            }
            if (enforce) {
                if (v.act == NG_DROP) {
                    /* not forwarded */
                } else if (v.act == NG_DELAY) {
                    held_t *h = malloc(sizeof *h + plen);
                    if (h) {
                        h->addr = *a; h->len = plen; memcpy(h->data, p, plen);
                        if (delayq_push(v.release_ns, h) < 0) free(h);   /* queue full -> drop */
                    }
                } else {
                    if (w != p) memmove(w, p, plen);                   /* compact kept packets in place */
                    w += plen; sl->addr[keep++] = *a;
                }
            }
            p = (uint8_t *)next; left = nextlen;
        }
        if (enforce && keep) {                                         /* hand the batch to the sender thread */
            sl->len = (UINT)(w - sl->buf); sl->count = keep;
            g_widx = (g_widx + 1) % RING;
            ReleaseSemaphore(g_sem_full, 1, NULL);
        } else {
            ReleaseSemaphore(g_sem_free, 1, NULL);                     /* nothing to send: give the buffer back */
        }
    }
}

/* If the rules change so that enforcement is (no longer) needed, or localhost capture is needed, wake the
 * capture loop so it reopens the handle in the right mode. No restart required. */
static void mode_thread(void *arg) {
    (void)arg;
    while (ng_running) {
        ng_sleep_ms(500);
        int enf = engine_needs_enforcement(), loop = engine_wants_loopback();
        if ((enf != g_mode_enf || loop != g_mode_loop) && g_h != INVALID_HANDLE_VALUE)
            WinDivertShutdown(g_h, WINDIVERT_SHUTDOWN_RECV);
    }
}

int backend_run(const ng_backend_opts_t *o) {
    (void)o;
    timeBeginPeriod(1);                                    /* 1 ms timer resolution for the shaper */
    ng_mutex_init(&ft_lock); ng_mutex_init(&pc_lock);
    ft = calloc(FT_SIZE, sizeof *ft);
    if (!ft) return -1;

    /* flow handle first, so no connection is missed between snapshot and capture */
    g_hf = WinDivertOpen("true", WINDIVERT_LAYER_FLOW, 0, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
    g_apps_ok = g_hf != INVALID_HANDLE_VALUE;
    if (g_apps_ok) {
        engine_set_self_app(app_from_pid(GetCurrentProcessId()));
        snapshot();                                        /* connections that already exist */
        engine_set_app_support(1);
        ng_thread_start(flow_thread, NULL);
        ng_thread_start(snapshot_thread, NULL);
    } else {
        DWORD e = GetLastError();
        ng_log(NG_LOG_WARN, "flow layer unavailable (%lu: %s) - per-application rules are DISABLED", (unsigned long)e, open_err(e));
    }

    if (ring_init()) { ng_log(NG_LOG_ERROR, "out of memory (packet ring)"); return -1; }
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);   /* don't get starved by busy apps */
    ng_thread_start(mode_thread, NULL);

    while (ng_running) {
        int enf = engine_needs_enforcement();
        int loop = engine_wants_loopback();                /* capture localhost only if a rule needs it */
        /* monitor-only = SNIFF: we get COPIES, the real packets are never held up */
        UINT64 flags = enf ? 0 : (WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
        g_h = WinDivertOpen(loop ? "true" : "!loopback", WINDIVERT_LAYER_NETWORK, 0, flags);
        if (g_h == INVALID_HANDLE_VALUE) {
            DWORD e = GetLastError();
            ng_log(NG_LOG_ERROR, "WinDivertOpen failed (%lu): %s", (unsigned long)e, open_err(e));
            return -1;
        }
        WinDivertSetParam(g_h, WINDIVERT_PARAM_QUEUE_LENGTH, 16384);
        WinDivertSetParam(g_h, WINDIVERT_PARAM_QUEUE_TIME, 250);            /* default 2 s = seconds of lag when overloaded */
        WinDivertSetParam(g_h, WINDIVERT_PARAM_QUEUE_SIZE, 32 * 1024 * 1024);
        g_mode_enf = enf; g_mode_loop = loop;
        engine_set_capture_mode(enf); engine_set_loopback_active(loop);
        ng_log(NG_LOG_INFO, "WinDivert %s (per-app: %s, localhost capture: %s)",
               enf ? "ENFORCING: every packet passes through NetGuard" : "MONITOR-ONLY: copies only, traffic is not slowed",
               g_apps_ok ? "on" : "off", loop ? "on" : "off");

        packet_loop(enf);

        ring_flush();                                      /* finish sending queued batches, then held (delayed) packets, */
        delayq_drain();                                    /* all while the handle is still valid */
        HANDLE h = g_h; g_h = INVALID_HANDLE_VALUE;
        WinDivertClose(h);
    }
    ring_close();
    return 0;
}
