/* used when built with -DNG_SIM_ONLY=ON (no packet interception, simulator + web only) */
#include "backend.h"
int  backend_run(const ng_backend_opts_t *o) { (void)o; ng_log(NG_LOG_ERROR, "built without OS backend; use --simulate"); return -1; }
void backend_stop(void) {}
void backend_cleanup(void) {}
void backend_release(void *c) { (void)c; }
