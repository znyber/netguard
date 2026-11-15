#ifndef NG_BACKEND_H
#define NG_BACKEND_H
#include "common.h"

typedef struct {
    int         queue_num;    /* Linux: NFQUEUE number                         */
    const char *lan_if;       /* Linux gateway mode: LAN-side interface name   */
} ng_backend_opts_t;

int  backend_run(const ng_backend_opts_t *o); /* blocks until ng_running == 0   */
void backend_stop(void);                      /* wake backend_run (may be no-op) */
void backend_cleanup(void);                   /* remove firewall hooks etc.      */
void backend_release(void *cookie);           /* delayq callback                 */

int  sim_run(void);                           /* synthetic traffic for testing   */
void sim_release(void *cookie);
#endif
