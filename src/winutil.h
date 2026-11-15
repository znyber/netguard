/* winutil.h - Windows-only helpers: elevation, single instance, browser, autostart, console, service, tray */
#ifndef NG_WINUTIL_H
#define NG_WINUTIL_H
#ifdef _WIN32
#include "common.h"

int  win_is_elevated(void);
int  win_relaunch_elevated(const wchar_t *args);     /* UAC prompt; args NULL = same arguments; 0 = started */
int  win_engine_lock(void);                          /* 1 = we own it; 0 = another engine (service?) already runs */
int  win_tray_lock(void);                            /* 1 = first tray icon; 0 = a tray is already running */
void win_open_url(const char *url);                  /* default browser */
int  win_read_port(const char *data_dir);            /* GUI port written by the engine, 0 if unknown */
void win_write_port(const char *data_dir, int port);
int  win_autorun_get(void);                          /* tray icon starts at logon (HKCU\...\Run) */
int  win_autorun_set(int on);
int  win_console_attach(void);                       /* attach to the parent console (cmd, PowerShell); 1 if attached */

/* ---- Windows service (winsvc.c) ---- */
int  win_service_install(void);                      /* create (auto-start, restart on failure) and start */
int  win_service_remove(void);
int  win_service_start(void);
int  win_service_stop(void);
int  win_service_state(void);                        /* 0 not installed, 1 stopped, 2 running, 3 changing */
int  win_service_dispatch(int (*run)(void *), void *arg);   /* run as the service; blocks until stopped */

/* ---- tray icon client (tray_win.c): UI only, the engine lives in the service ---- */
typedef struct { const char *data_dir, *log_path; int quiet; } tray_cfg_t;
int  tray_main(const tray_cfg_t *c);
#endif
#endif
