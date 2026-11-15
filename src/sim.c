/* sim.c - synthetic traffic with fake applications, to try rules / GUI without root or driver */
#include "common.h"
#include "engine.h"
#include "backend.h"
#include "delayq.h"
#ifndef _WIN32
  #include <arpa/inet.h>
#endif

typedef struct { const char *app, *ip; double mbps; int dir; unsigned port; uint8_t proto; int loopback; } flow_t;
static const flow_t flows[] = {
    { "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "93.184.216.34", 30.0, NG_IN,  443,  6, 0 },
    { "C:\\Games\\torrent.exe",                                     "10.0.0.5",      40.0, NG_IN, 6881,  6, 0 },
    { "C:\\Tools\\updater.exe",                                     "203.0.113.7",    5.0, NG_IN,   80,  6, 0 },
    { "C:\\Windows\\System32\\svchost.exe",                         "8.8.8.8",        0.2, NG_OUT,  53, 17, 0 },   /* DNS client   */
    { "C:\\Windows\\System32\\svchost.exe",                         "255.255.255.255",0.05,NG_OUT,  67, 17, 0 },   /* DHCP client  */
    { "C:\\Windows\\System32\\svchost.exe",                         "20.190.159.4",   5.0, NG_IN,  443,  6, 0 },   /* Windows Update */
    { NULL,                                                         "8.8.4.4",        0.05,NG_OUT,   0,  1, 0 },   /* ping, app unknown */
    { "C:\\Tools\\backup.exe",                                      "192.168.1.9",   10.0, NG_OUT, 445,  6, 0 },
    { "C:\\db\\postgres.exe",                                       "127.0.0.1",      8.0, NG_OUT, 5432, 6, 1 },
};
#define NFLOWS (int)(sizeof flows / sizeof flows[0])

void sim_release(void *cookie) { (void)cookie; }   /* nothing to re-inject in simulation */

int sim_run(void) {
    double credit[NFLOWS] = { 0 };
    uint8_t addr[NFLOWS][16]; int appid[NFLOWS];
    engine_set_app_support(1);
    for (int i = 0; i < NFLOWS; i++) {
        struct in_addr a;
        inet_pton(AF_INET, flows[i].ip, &a);
        memset(addr[i], 0, 16); addr[i][10] = addr[i][11] = 0xff; memcpy(addr[i] + 12, &a, 4);
        appid[i] = flows[i].app ? engine_app_id(flows[i].app) : 0;
    }
    engine_set_loopback_active(1);
    ng_log(NG_LOG_INFO, "simulation running: %d synthetic flows from %d fake apps (no real traffic is touched)", NFLOWS, NFLOWS);
    uint64_t last = ng_now_ns();
    while (ng_running) {
        ng_sleep_ms(1);
        uint64_t now = ng_now_ns();
        double dt = (double)(now - last) / 1e9; last = now;
        for (int i = 0; i < NFLOWS; i++) {
            credit[i] += flows[i].mbps * 1e6 / 8.0 * dt;
            while (credit[i] >= 1000.0) {
                credit[i] -= 1000.0;
                ng_pkt_t p; memset(&p, 0, sizeof p);
                p.dir = (uint8_t)flows[i].dir; p.proto = flows[i].proto; p.len = 1000;
                p.app = (int16_t)appid[i]; p.loopback = (uint8_t)flows[i].loopback;
                memcpy(p.remote, addr[i], 16);
                p.remote_port = (uint16_t)flows[i].port; p.local_port = 50000;
                ng_verdict_t v; engine_judge(&p, &v);
                if (v.act == NG_DELAY) delayq_push(v.release_ns, NULL);
            }
        }
    }
    return 0;
}
