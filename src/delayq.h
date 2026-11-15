#ifndef NG_DELAYQ_H
#define NG_DELAYQ_H
#include "common.h"
typedef void (*delayq_fn)(void *cookie);   /* called when a held packet is due */
int  delayq_start(delayq_fn release);
int  delayq_push(uint64_t release_ns, void *cookie);   /* 0 ok, -1 queue full */
void delayq_stop(void);                    /* releases everything still held */
void delayq_drain(void);                   /* release everything held right now (e.g. before swapping capture handle) */
#endif
