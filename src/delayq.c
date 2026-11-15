/* delayq.c - holds delayed packets in a min-heap and releases them on time */
#include "delayq.h"

#define CAP 65536
typedef struct { uint64_t t; void *c; } ent_t;

static ent_t   *heap;
static size_t   hn;
static ng_mutex lk;
static delayq_fn rel;
static volatile int stopping;

static void swap(size_t a, size_t b) { ent_t t = heap[a]; heap[a] = heap[b]; heap[b] = t; }
static void sift_up(size_t i) {
    while (i) { size_t p = (i - 1) / 2; if (heap[p].t <= heap[i].t) break; swap(p, i); i = p; }
}
static void sift_down(size_t i) {
    for (;;) {
        size_t l = 2 * i + 1, r = l + 1, m = i;
        if (l < hn && heap[l].t < heap[m].t) m = l;
        if (r < hn && heap[r].t < heap[m].t) m = r;
        if (m == i) break;
        swap(m, i); i = m;
    }
}

int delayq_push(uint64_t t, void *c) {
    ng_mutex_lock(&lk);
    if (hn >= CAP) { ng_mutex_unlock(&lk); return -1; }
    heap[hn].t = t; heap[hn].c = c;
    sift_up(hn++);
    ng_mutex_unlock(&lk);
    return 0;
}

static void loop(void *arg) {
    (void)arg;
    while (!stopping) {
        ng_mutex_lock(&lk);
        if (!hn) { ng_mutex_unlock(&lk); ng_sleep_us(1000); continue; }
        uint64_t now = ng_now_ns(), t = heap[0].t;
        if (t <= now) {
            void *c = heap[0].c;
            heap[0] = heap[--hn];
            sift_down(0);
            ng_mutex_unlock(&lk);
            rel(c);
            continue;
        }
        ng_mutex_unlock(&lk);
        uint64_t w = (t - now) / 1000;
        ng_sleep_us(w > 1000 ? 1000u : (unsigned)w + 1u);
    }
}

int delayq_start(delayq_fn release) {
    heap = malloc(sizeof(ent_t) * CAP);
    if (!heap) return -1;
    ng_mutex_init(&lk);
    rel = release;
    return ng_thread_start(loop, NULL);
}

void delayq_drain(void) {
    ng_mutex_lock(&lk);
    while (hn) {                       /* don't lose packets */
        void *c = heap[0].c;
        heap[0] = heap[--hn];
        sift_down(0);
        ng_mutex_unlock(&lk);
        rel(c);
        ng_mutex_lock(&lk);
    }
    ng_mutex_unlock(&lk);
}

void delayq_stop(void) {
    stopping = 1;
    ng_sleep_ms(20);
    delayq_drain();
}
