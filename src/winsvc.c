/* winsvc.c - NetGuard as a Windows service (engine runs at boot, as SYSTEM, no console, no UAC prompts) */
#include "common.h"
#include "winutil.h"
#include "backend.h"
#include <winsvc.h>

#define SVC_NAME L"NetGuard"

static SERVICE_STATUS_HANDLE g_ssh;
static SERVICE_STATUS        g_ss;
static int  (*g_run)(void *);
static void  *g_arg;
static int    g_rc;
static DWORD  g_check;

static void report(DWORD state, DWORD code, DWORD wait) {
    g_ss.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ss.dwCurrentState = state;
    g_ss.dwControlsAccepted = state == SERVICE_START_PENDING ? 0 : (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
    g_ss.dwWin32ExitCode = code ? ERROR_SERVICE_SPECIFIC_ERROR : NO_ERROR;
    g_ss.dwServiceSpecificExitCode = code;
    g_ss.dwWaitHint = wait;
    g_ss.dwCheckPoint = (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : ++g_check;
    SetServiceStatus(g_ssh, &g_ss);
}

static void WINAPI svc_handler(DWORD ctl) {
    if (ctl == SERVICE_CONTROL_STOP || ctl == SERVICE_CONTROL_SHUTDOWN) {
        report(SERVICE_STOP_PENDING, 0, 15000);
        ng_running = 0;
        backend_stop();                                  /* wakes the capture loop */
    }
}
static void on_ready(void) { report(SERVICE_RUNNING, 0, 0); }

static void WINAPI svc_main(DWORD argc, LPWSTR *argv) {
    (void)argc; (void)argv;
    g_ssh = RegisterServiceCtrlHandlerW(SVC_NAME, svc_handler);
    if (!g_ssh) return;
    report(SERVICE_START_PENDING, 0, 20000);
    ng_ready_cb = on_ready;
    g_rc = g_run(g_arg);
    report(SERVICE_STOPPED, g_rc ? 1 : 0, 0);
}

int win_service_dispatch(int (*run)(void *), void *arg) {
    SERVICE_TABLE_ENTRYW t[2];
    g_run = run; g_arg = arg;
    t[0].lpServiceName = (LPWSTR)SVC_NAME; t[0].lpServiceProc = svc_main;
    t[1].lpServiceName = NULL;               t[1].lpServiceProc = NULL;
    if (!StartServiceCtrlDispatcherW(t)) return -1;     /* not started by the service manager */
    return g_rc;
}

/* ------------------------------------------------------------ control */
int win_service_install(void) {
    SC_HANDLE m = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!m) return -1;
    wchar_t exe[MAX_PATH], cmd[MAX_PATH + 20];
    GetModuleFileNameW(NULL, exe, MAX_PATH);
    _snwprintf(cmd, sizeof cmd / sizeof cmd[0], L"\"%ls\" --service", exe);
    cmd[sizeof cmd / sizeof cmd[0] - 1] = 0;
    SC_HANDLE s = CreateServiceW(m, SVC_NAME, L"NetGuard firewall and bandwidth manager", SERVICE_ALL_ACCESS,
                                 SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                                 cmd, NULL, NULL, NULL, NULL, NULL);
    if (!s && GetLastError() == ERROR_SERVICE_EXISTS) {          /* upgrade: point it at this exe */
        s = OpenServiceW(m, SVC_NAME, SERVICE_ALL_ACCESS);
        if (s) ChangeServiceConfigW(s, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_NO_CHANGE, cmd,
                                    NULL, NULL, NULL, NULL, NULL, NULL);
    }
    if (!s) { CloseServiceHandle(m); return -1; }
    SERVICE_DESCRIPTIONW d; d.lpDescription = (LPWSTR)L"Per-application firewall and bandwidth limiter (NetGuard). Control it from the tray icon or http://127.0.0.1:8080/";
    ChangeServiceConfig2W(s, SERVICE_CONFIG_DESCRIPTION, &d);
    SC_ACTION acts[3];                                              /* restart after a crash: 5 s, 5 s, 5 s */
    for (int i = 0; i < 3; i++) { acts[i].Type = SC_ACTION_RESTART; acts[i].Delay = 5000; }
    SERVICE_FAILURE_ACTIONSW fa;
    memset(&fa, 0, sizeof fa);
    fa.dwResetPeriod = 86400; fa.cActions = 3; fa.lpsaActions = acts;
    ChangeServiceConfig2W(s, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);
    CloseServiceHandle(s); CloseServiceHandle(m);
    return win_service_start();
}

static SC_HANDLE open_svc(DWORD access, SC_HANDLE *mgr) {
    *mgr = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    return *mgr ? OpenServiceW(*mgr, SVC_NAME, access) : NULL;
}

int win_service_state(void) {
    SC_HANDLE m, s = open_svc(SERVICE_QUERY_STATUS, &m);
    if (!s) { if (m) CloseServiceHandle(m); return 0; }
    SERVICE_STATUS st; int r = 1;
    if (QueryServiceStatus(s, &st)) r = st.dwCurrentState == SERVICE_RUNNING ? 2 : st.dwCurrentState == SERVICE_STOPPED ? 1 : 3;
    CloseServiceHandle(s); CloseServiceHandle(m);
    return r;
}

static int wait_state(SC_HANDLE s, DWORD want) {                 /* up to ~15 s */
    SERVICE_STATUS st;
    for (int i = 0; i < 60; i++) {
        if (QueryServiceStatus(s, &st) && st.dwCurrentState == want) return 0;
        Sleep(250);
    }
    return -1;
}

int win_service_start(void) {
    SC_HANDLE m, s = open_svc(SERVICE_START | SERVICE_QUERY_STATUS, &m);
    if (!s) { if (m) CloseServiceHandle(m); return -1; }
    int rc = 0;
    if (!StartServiceW(s, 0, NULL) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) rc = -1;
    if (!rc) rc = wait_state(s, SERVICE_RUNNING);
    CloseServiceHandle(s); CloseServiceHandle(m);
    return rc;
}

int win_service_stop(void) {
    SC_HANDLE m, s = open_svc(SERVICE_STOP | SERVICE_QUERY_STATUS, &m);
    if (!s) { if (m) CloseServiceHandle(m); return 0; }          /* not installed: nothing to stop */
    SERVICE_STATUS st; int rc = 0;
    if (!ControlService(s, SERVICE_CONTROL_STOP, &st) && GetLastError() != ERROR_SERVICE_NOT_ACTIVE) rc = -1;
    if (!rc) wait_state(s, SERVICE_STOPPED);
    CloseServiceHandle(s); CloseServiceHandle(m);
    return rc;
}

int win_service_remove(void) {
    win_service_stop();
    SC_HANDLE m, s = open_svc(DELETE, &m);
    if (!s) { if (m) CloseServiceHandle(m); return 0; }
    int rc = DeleteService(s) ? 0 : -1;
    CloseServiceHandle(s); CloseServiceHandle(m);
    return rc;
}
