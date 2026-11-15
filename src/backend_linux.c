/* backend_linux.c - NFQUEUE (libnetfilter_queue) packet backend. Needs root + iptables/ip6tables.
 *
 * host mode   : INPUT/OUTPUT are queued; direction comes from the netfilter hook.
 * gateway mode: FORWARD is queued; packets arriving on --gateway IF are "upload", the rest "download".
 */
#include "common.h"
#include "engine.h"
#include "backend.h"
#include "delayq.h"
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <stdarg.h>

static struct nfq_handle   *g_h;
static struct nfq_q_handle *g_qh;
static ng_mutex g_vlock;               /* serialises verdicts (callback thread vs. delay thread) */
static unsigned g_lan_ifindex;
static int      g_gateway, g_qnum;

static void verdict(uint32_t id, uint32_t v) {
    ng_mutex_lock(&g_vlock);
    nfq_set_verdict(g_qh, id, v, 0, NULL);
    ng_mutex_unlock(&g_vlock);
}

void backend_release(void *cookie) { verdict((uint32_t)(uintptr_t)cookie, NF_ACCEPT); }

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    (void)qh; (void)nfmsg; (void)data;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) return 0;
    uint32_t id = ntohl(ph->packet_id);
    unsigned char *pl; int n = nfq_get_payload(nfa, &pl);
    ng_ipinfo_t ip; ng_pkt_t pkt; ng_verdict_t v;
    if (n < 20 || ng_parse_ip(pl, (size_t)n, &ip) < 0) { verdict(id, NF_ACCEPT); return 0; }
    int dir = g_gateway ? (nfq_get_indev(nfa) == g_lan_ifindex ? NG_OUT : NG_IN)
                        : (ph->hook == NF_INET_LOCAL_OUT ? NG_OUT : NG_IN);
    ng_fill_pkt(&ip, dir, &pkt);
    engine_judge(&pkt, &v);
    switch (v.act) {
        case NG_DROP:  verdict(id, NF_DROP); break;
        case NG_DELAY: if (delayq_push(v.release_ns, (void *)(uintptr_t)id) < 0) verdict(id, NF_DROP); break;
        default:       verdict(id, NF_ACCEPT); break;
    }
    return 0;
}

static void sh(const char *fmt, ...) {
    char cmd[256]; va_list ap; va_start(ap, fmt); vsnprintf(cmd, sizeof cmd, fmt, ap); va_end(ap);
    ng_log(NG_LOG_DEBUG, "exec: %s", cmd);
    if (system(cmd)) ng_log(NG_LOG_DEBUG, "command failed: %s", cmd);
}

static void fw(char op) {   /* 'I' install, 'D' delete */
    const char *bins[2] = { "iptables", "ip6tables" };
    for (int b = 0; b < 2; b++) {
        const char *x = bins[b];
        const char *pos = op == 'I' ? " 1" : "";
        if (g_gateway) {
            sh("%s -%c FORWARD%s -j NFQUEUE --queue-num %d --queue-bypass", x, op, pos, g_qnum);
        } else {
            sh("%s -%c OUTPUT%s ! -o lo -j NFQUEUE --queue-num %d --queue-bypass", x, op, pos, g_qnum);
            sh("%s -%c INPUT%s ! -i lo -j NFQUEUE --queue-num %d --queue-bypass", x, op, pos, g_qnum);
        }
    }
}

void backend_stop(void) {}
void backend_cleanup(void) { fw('D'); if (g_qh) nfq_destroy_queue(g_qh); if (g_h) nfq_close(g_h); }

int backend_run(const ng_backend_opts_t *o) {
    ng_mutex_init(&g_vlock);
    g_qnum = o->queue_num;
    if (o->lan_if) {
        g_gateway = 1; g_lan_ifindex = if_nametoindex(o->lan_if);
        if (!g_lan_ifindex) { ng_log(NG_LOG_ERROR, "unknown interface %s", o->lan_if); return -1; }
    }
    g_h = nfq_open();
    if (!g_h) { ng_log(NG_LOG_ERROR, "nfq_open failed"); return -1; }
    g_qh = nfq_create_queue(g_h, (uint16_t)g_qnum, &cb, NULL);
    if (!g_qh) { ng_log(NG_LOG_ERROR, "cannot bind NFQUEUE %d (in use? missing nfnetlink_queue?)", g_qnum); return -1; }
    nfq_set_mode(g_qh, NFQNL_COPY_PACKET, 128);        /* headers are enough */
    nfq_set_queue_maxlen(g_qh, 65536);                 /* room for delayed packets */
    int fd = nfq_fd(g_h);
    int rb = 8 * 1024 * 1024;                          /* big socket buffer; FORCE works as root */
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &rb, sizeof rb))
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rb, sizeof rb);

    fw('I');
    ng_log(NG_LOG_INFO, "NFQUEUE %d active (%s mode)", g_qnum, g_gateway ? "gateway" : "host");

    static char buf[70000] __attribute__((aligned(8)));
    while (ng_running) {
        struct pollfd pfd = { fd, POLLIN, 0 };
        if (poll(&pfd, 1, 500) <= 0) continue;
        ssize_t n = recv(fd, buf, sizeof buf, 0);
        if (n >= 0) nfq_handle_packet(g_h, buf, (int)n);
        else if (errno == ENOBUFS) ng_log(NG_LOG_WARN, "kernel queue overflow - some packets bypassed");
        else if (errno != EINTR) { ng_log(NG_LOG_ERROR, "recv: %s", strerror(errno)); break; }
    }
    return 0;
}
