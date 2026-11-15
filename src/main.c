/* main.c - NetGuard entry point.
 *
 * Run modes (Windows):
 *   --service            engine as a Windows service (installer): no console, log file only
 *   --tray               tray icon + GUI launcher (UI only, talks to the engine); no console
 *   (no args, started from cmd / PowerShell)  engine in the foreground, logs on stdout, Ctrl+C stops
 *   (no args, started from Start menu / Explorer)  tray icon
 *   --console            force foreground engine with a console
 *   --install-service / --remove-service / --start-service / --stop-service   (ask for admin)
 */
#include "common.h"
#include "engine.h"
#include "delayq.h"
#include "backend.h"
#include "web.h"
#include "default_conf.h"
#include <signal.h>
#ifdef _WIN32
  #include <shellapi.h>
  #include "winutil.h"
#endif

volatile int ng_running = 1;

typedef struct {
    const char *cfg, *logf, *datadir;
    int port, simulate, open_gui;
    ng_backend_opts_t bo;
} run_t;

#ifdef _WIN32
static BOOL WINAPI on_ctrl(DWORD t) { (void)t; ng_running = 0; backend_stop(); return TRUE; }
#else
static void on_sig(int s) { (void)s; ng_running = 0; }
#endif

static void usage(const char *a0) {
    fprintf(stderr,
        "usage: %s [options]\n"
        "  -c FILE       rules file\n"
        "  -l FILE       log file\n"
        "  -w PORT       GUI port (default 8080; tries the next 9 if busy; 127.0.0.1 only)\n"
        "  -v            verbose log\n"
        "  --simulate    synthetic traffic, no root/driver needed\n"
#ifdef _WIN32
        "  --service | --tray | --console | --quiet | --open\n"
        "  --install-service | --remove-service | --start-service | --stop-service\n"
        "  --tray-autorun-on | --tray-autorun-off   show the tray icon at logon (per user)\n"
#else
        "  --gateway IF  router mode: shape forwarded traffic; IF = LAN-side interface\n"
        "  --queue N     NFQUEUE number (default 100)\n"
#endif
        , a0);
}

/* first run: write the built-in default rules file */
static void ensure_config(const char *path) {
    FILE *f = fopen(path, "r");
    if (f) { fclose(f); return; }
    f = fopen(path, "wb");
    if (f) { fwrite(ng_default_conf, 1, ng_default_conf_len, f); fclose(f); }
}

/* the engine proper: load rules, start workers + GUI server, capture packets until stopped */
static int run_core(void *arg) {
    run_t *r = arg;
    ensure_config(r->cfg);
    if (engine_load(r->cfg)) return 1;
    if (delayq_start(r->simulate ? sim_release : backend_release)) { ng_log(NG_LOG_ERROR, "delay queue failed"); return 1; }
    engine_start_workers();
    int port = web_start(r->port);
    if (port < 0) ng_log(NG_LOG_WARN, "GUI not started (ports %d-%d busy?)", r->port, r->port + 9);
    else {
        ng_gui_port = port;
        engine_set_exempt_port(port);
        ng_log(NG_LOG_INFO, "GUI: http://127.0.0.1:%d/", port);
#ifdef _WIN32
        if (r->datadir && r->datadir[0]) win_write_port(r->datadir, port);   /* the tray finds the GUI through this */
        if (r->open_gui) { char url[64]; snprintf(url, sizeof url, "http://127.0.0.1:%d/", port); win_open_url(url); }
#else
        (void)r->open_gui;
#endif
    }
    if (ng_ready_cb) ng_ready_cb();
    int rc = r->simulate ? sim_run() : backend_run(&r->bo);
    ng_running = 0;
    delayq_stop();
    if (!r->simulate) backend_cleanup();
    ng_log(NG_LOG_INFO, "stopped");
    return rc ? 1 : 0;
}

#ifdef _WIN32
static int file_exists(const char *p) { return GetFileAttributesA(p) != INVALID_FILE_ATTRIBUTES; }

/* portable: files next to the exe if netguard.conf is there; installed: %ProgramData%\NetGuard */
static void default_paths(char *cfg, char *logf, char *dir, size_t n) {
    char exe[MAX_PATH];
    GetModuleFileNameA(NULL, exe, MAX_PATH);
    char *sl = strrchr(exe, '\\'); if (sl) *sl = 0;
    snprintf(cfg, n, "%s\\netguard.conf", exe);
    if (file_exists(cfg)) { snprintf(logf, n, "%s\\netguard.log", exe); snprintf(dir, n, "%s", exe); return; }
    const char *pd = getenv("ProgramData");
    snprintf(dir, n, "%s\\NetGuard", pd ? pd : "C:\\ProgramData");
    CreateDirectoryA(dir, NULL);
    snprintf(cfg, n, "%s\\netguard.conf", dir);
    snprintf(logf, n, "%s\\netguard.log", dir);
}
#endif

int main(int argc, char **argv) {
    run_t r; memset(&r, 0, sizeof r);
    r.port = 8080; r.bo.queue_num = 100;
    int verbose = 0, quiet = 0;
    char cfg[400] = "netguard.conf", logf[400] = "netguard.log", dir[400] = "";
#ifdef _WIN32
    enum { M_AUTO, M_SERVICE, M_TRAY, M_FG } mode = M_AUTO;
    int admin_cmd = 0;
    default_paths(cfg, logf, dir, sizeof cfg);
#endif

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if      (!strcmp(a, "-c") && i + 1 < argc) snprintf(cfg, sizeof cfg, "%s", argv[++i]);
        else if (!strcmp(a, "-l") && i + 1 < argc) snprintf(logf, sizeof logf, "%s", argv[++i]);
        else if (!strcmp(a, "-w") && i + 1 < argc) r.port = atoi(argv[++i]);
        else if (!strcmp(a, "-v")) verbose = 1;
        else if (!strcmp(a, "--simulate")) r.simulate = 1;
        else if (!strcmp(a, "--open")) r.open_gui = 1;
        else if (!strcmp(a, "--quiet")) quiet = 1;
        else if (!strcmp(a, "--gateway") && i + 1 < argc) r.bo.lan_if = argv[++i];
        else if (!strcmp(a, "--queue") && i + 1 < argc) r.bo.queue_num = atoi(argv[++i]);
#ifdef _WIN32
        else if (!strcmp(a, "--service")) mode = M_SERVICE;
        else if (!strcmp(a, "--tray"))    mode = M_TRAY;
        else if (!strcmp(a, "--console")) mode = M_FG;
        else if (!strcmp(a, "--install-service")) admin_cmd = 1;
        else if (!strcmp(a, "--remove-service"))  admin_cmd = 2;
        else if (!strcmp(a, "--start-service"))   admin_cmd = 3;
        else if (!strcmp(a, "--stop-service"))    admin_cmd = 4;
        else if (!strcmp(a, "--tray-autorun-on"))  admin_cmd = 5;
        else if (!strcmp(a, "--tray-autorun-off")) admin_cmd = 6;
#endif
        else { usage(argv[0]); return 2; }
    }
    r.cfg = cfg; r.logf = logf; r.datadir = dir;

#ifdef _WIN32
    /* ---- service management: needs admin, so ask for it (UAC) when started normally ---- */
    if (admin_cmd >= 5) return win_autorun_set(admin_cmd == 5) == 0 ? 0 : 1;   /* per-user, no admin needed */
    if (admin_cmd) {
        if (!win_is_elevated()) return win_relaunch_elevated(NULL) == 0 ? 0 : 1;
        int rc = admin_cmd == 1 ? win_service_install() : admin_cmd == 2 ? win_service_remove()
               : admin_cmd == 3 ? win_service_start()   : win_service_stop();
        return rc ? 1 : 0;
    }

    /* ---- decide the run mode ---- */
    int console = 0;
#ifdef NG_CONSOLE_BUILD
    console = 1;                                         /* netguardc.exe: always a console program */
    if (mode == M_AUTO) mode = M_FG;
#else
    if (mode == M_FG || (mode == M_AUTO && r.simulate)) {
        console = win_console_attach();
        if (!console && AllocConsole()) {                /* started without a console: make one */
            freopen("CONOUT$", "w", stdout); freopen("CONOUT$", "w", stderr); console = 1;
        }
    } else if (mode == M_AUTO) {
        console = win_console_attach();                  /* started from cmd/PowerShell -> behave like a console tool */
        mode = console ? M_FG : M_TRAY;                  /* started from Start menu / Explorer -> tray icon */
    }
    if (mode == M_AUTO) mode = M_FG;
#endif
    ng_log_console(console && mode == M_FG);             /* service and tray never write to a console */
    if (mode == M_TRAY) {
        ng_log_open(NULL, NG_LOG_WARN);
        if (!win_tray_lock()) {                          /* a tray icon already exists */
            if (!quiet) {                                /* started by hand (shortcut): open the GUI; at logon (--quiet): stay silent */
                char url[64]; int p = win_read_port(dir);
                snprintf(url, sizeof url, "http://127.0.0.1:%d/", p ? p : 8080);
                win_open_url(url);
            }
            return 0;
        }
        tray_cfg_t tc; tc.data_dir = dir; tc.log_path = logf; tc.quiet = quiet;
        return tray_main(&tc);
    }
    ng_log_open(logf, verbose ? NG_LOG_DEBUG : NG_LOG_INFO);
    { WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa); }
    if (!win_engine_lock()) {
        ng_log(NG_LOG_ERROR, "another NetGuard engine is already running (the service?). Stop it first: net stop NetGuard");
        return 1;
    }
    if (mode == M_SERVICE) {
        int rc = win_service_dispatch(run_core, &r);
        if (rc < 0) ng_log(NG_LOG_ERROR, "--service must be started by the Windows service manager");
        return rc ? 1 : 0;
    }
    SetConsoleCtrlHandler(on_ctrl, TRUE);
    return run_core(&r);
#else
    (void)quiet;
    ng_log_open(logf, verbose ? NG_LOG_DEBUG : NG_LOG_INFO);
    signal(SIGINT, on_sig); signal(SIGTERM, on_sig); signal(SIGPIPE, SIG_IGN);
    if (!r.simulate && geteuid() != 0) { fprintf(stderr, "need root (or use --simulate)\n"); return 1; }
    return run_core(&r);
#endif
}
