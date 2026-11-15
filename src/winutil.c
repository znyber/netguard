/* winutil.c - Windows helpers shared by the engine and the tray client */
#include "common.h"
#include "winutil.h"
#include <shellapi.h>

int win_is_elevated(void) {
    HANDLE t = NULL; TOKEN_ELEVATION e; DWORD n = 0; int r = 0;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) {
        if (GetTokenInformation(t, TokenElevation, &e, sizeof e, &n)) r = e.TokenIsElevated != 0;
        CloseHandle(t);
    }
    return r;
}

int win_relaunch_elevated(const wchar_t *args) {
    wchar_t exe[MAX_PATH];
    GetModuleFileNameW(NULL, exe, MAX_PATH);
    if (!args) {                                        /* same arguments: skip our own program name */
        const wchar_t *cl = GetCommandLineW();
        if (*cl == L'"') { cl++; while (*cl && *cl != L'"') cl++; if (*cl) cl++; }
        else while (*cl && *cl != L' ') cl++;
        while (*cl == L' ') cl++;
        args = *cl ? cl : NULL;
    }
    return (INT_PTR)ShellExecuteW(NULL, L"runas", exe, args, NULL, SW_HIDE) > 32 ? 0 : -1;
}

static int take_mutex(const wchar_t *name) {            /* 1 = created by us (first), 0 = exists already */
    HANDLE h = CreateMutexW(NULL, FALSE, name);         /* the handle stays open for the whole process life */
    DWORD e = GetLastError();
    if (!h) return e == ERROR_ACCESS_DENIED ? 0 : 1;    /* exists but belongs to an elevated/system process */
    if (e == ERROR_ALREADY_EXISTS) { CloseHandle(h); return 0; }
    return 1;
}
int win_engine_lock(void) { return take_mutex(L"Global\\NetGuardEngine"); }
int win_tray_lock(void)   { return take_mutex(L"Local\\NetGuardTray"); }

void win_open_url(const char *url) {
    wchar_t w[300];
    MultiByteToWideChar(CP_UTF8, 0, url, -1, w, 300);
    ShellExecuteW(NULL, L"open", w, NULL, NULL, SW_SHOWNORMAL);
}

int win_read_port(const char *dir) {
    char p[400]; int port = 0;
    snprintf(p, sizeof p, "%s\\gui.port", dir ? dir : ".");
    FILE *f = fopen(p, "r");
    if (f) { if (fscanf(f, "%d", &port) != 1) port = 0; fclose(f); }
    return port > 0 && port < 65536 ? port : 0;
}
void win_write_port(const char *dir, int port) {
    char p[400];
    snprintf(p, sizeof p, "%s\\gui.port", dir);
    FILE *f = fopen(p, "w");
    if (f) { fprintf(f, "%d\n", port); fclose(f); }
}

#define RUN_KEY  L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define RUN_NAME L"NetGuardTray"
int win_autorun_get(void) {
    HKEY k; int ok = 0;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, RUN_KEY, 0, KEY_READ, &k) == ERROR_SUCCESS) {
        ok = RegQueryValueExW(k, RUN_NAME, NULL, NULL, NULL, NULL) == ERROR_SUCCESS;
        RegCloseKey(k);
    }
    return ok;
}
int win_autorun_set(int on) {
    HKEY k; int rc = -1;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, RUN_KEY, 0, KEY_SET_VALUE, &k) != ERROR_SUCCESS) return -1;
    if (on) {
        wchar_t exe[MAX_PATH], cmd[MAX_PATH + 40];
        GetModuleFileNameW(NULL, exe, MAX_PATH);
        _snwprintf(cmd, sizeof cmd / sizeof cmd[0], L"\"%ls\" --tray --quiet", exe);
        cmd[sizeof cmd / sizeof cmd[0] - 1] = 0;
        rc = RegSetValueExW(k, RUN_NAME, 0, REG_SZ, (const BYTE *)cmd, (DWORD)((wcslen(cmd) + 1) * sizeof(wchar_t))) == ERROR_SUCCESS ? 0 : -1;
    } else {
        LONG r = RegDeleteValueW(k, RUN_NAME);
        rc = (r == ERROR_SUCCESS || r == ERROR_FILE_NOT_FOUND) ? 0 : -1;
    }
    RegCloseKey(k);
    return rc;
}

int win_console_attach(void) {
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) return 0;   /* started from Explorer / service / task: no console */
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
    freopen("CONIN$", "r", stdin);
    return 1;
}
