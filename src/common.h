/* common.h - tiny portability layer (threads, mutex, clock, sockets) */
#ifndef NG_COMMON_H
#define NG_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  typedef CRITICAL_SECTION ng_mutex;
  static inline void ng_mutex_init(ng_mutex *m)   { InitializeCriticalSection(m); }
  static inline void ng_mutex_lock(ng_mutex *m)   { EnterCriticalSection(m); }
  static inline void ng_mutex_unlock(ng_mutex *m) { LeaveCriticalSection(m); }
  static inline void ng_sleep_ms(unsigned ms)     { Sleep(ms); }
  static inline void ng_sleep_us(unsigned us)     { Sleep((us + 999) / 1000); } /* needs timeBeginPeriod(1) */
  static inline uint64_t ng_now_ns(void) {
      static LARGE_INTEGER f; LARGE_INTEGER c;
      if (!f.QuadPart) QueryPerformanceFrequency(&f);
      QueryPerformanceCounter(&c);
      /* split to avoid 64-bit overflow / double precision loss */
      return (uint64_t)(c.QuadPart / f.QuadPart) * 1000000000ull +
             (uint64_t)(c.QuadPart % f.QuadPart) * 1000000000ull / (uint64_t)f.QuadPart;
  }
#else
  #include <pthread.h>
  #include <unistd.h>
  #include <time.h>
  typedef pthread_mutex_t ng_mutex;
  static inline void ng_mutex_init(ng_mutex *m)   { pthread_mutex_init(m, NULL); }
  static inline void ng_mutex_lock(ng_mutex *m)   { pthread_mutex_lock(m); }
  static inline void ng_mutex_unlock(ng_mutex *m) { pthread_mutex_unlock(m); }
  static inline void ng_sleep_ms(unsigned ms)     { usleep(ms * 1000u); }
  static inline void ng_sleep_us(unsigned us)     { usleep(us); }
  static inline uint64_t ng_now_ns(void) {
      struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
      return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
  }
#endif

/* ---- threads ---- */
typedef void (*ng_thread_fn)(void *);
typedef struct { ng_thread_fn fn; void *arg; } ng_tramp;
#ifdef _WIN32
static DWORD WINAPI ng_tramp_run(LPVOID p) { ng_tramp t = *(ng_tramp *)p; free(p); t.fn(t.arg); return 0; }
static inline int ng_thread_start(ng_thread_fn fn, void *arg) {
    ng_tramp *t = malloc(sizeof *t); if (!t) return -1;
    t->fn = fn; t->arg = arg;
    HANDLE h = CreateThread(NULL, 0, ng_tramp_run, t, 0, NULL);
    if (!h) { free(t); return -1; }
    CloseHandle(h); return 0;
}
#else
static void *ng_tramp_run(void *p) { ng_tramp t = *(ng_tramp *)p; free(p); t.fn(t.arg); return NULL; }
static inline int ng_thread_start(ng_thread_fn fn, void *arg) {
    ng_tramp *t = malloc(sizeof *t); if (!t) return -1;
    t->fn = fn; t->arg = arg;
    pthread_t th;
    if (pthread_create(&th, NULL, ng_tramp_run, t)) { free(t); return -1; }
    pthread_detach(th); return 0;
}
#endif

/* ---- globals / logging / string builder (util.c) ---- */
extern volatile int ng_running;

enum { NG_LOG_DEBUG, NG_LOG_INFO, NG_LOG_WARN, NG_LOG_ERROR };
int  ng_log_open(const char *path, int min_level);   /* path may be NULL (stderr only) */
#ifdef __GNUC__
void ng_log(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
#else
void ng_log(int level, const char *fmt, ...);
#endif

typedef struct { char *p; size_t n, cap; } sb_t;
void sb_printf(sb_t *s, const char *fmt, ...);
void sb_putn(sb_t *s, const char *p, size_t n);      /* fast append of n raw bytes */
void sb_free(sb_t *s);

/* ---- process-wide state shared between modules ---- */
extern volatile int ng_gui_port;                     /* port the GUI/API listens on (0 = not started) */
extern void (*ng_ready_cb)(void);                    /* called once the engine is up (service uses it) */
extern char ng_last_error[600];                      /* last ERROR log line, for message boxes */
void ng_log_console(int on);                         /* 1 = also print log lines to stdout (cmd), 0 = file only */

#endif
