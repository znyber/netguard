/* tray_win.c - system tray icon (UI only; the engine runs as the NetGuard service).
 * Double-click / "Open NetGuard" opens the GUI in the default browser. Runs without admin rights. */
#include "common.h"
#include "winutil.h"
#include <shellapi.h>

#define WM_TRAY      (WM_APP + 1)
#define TIMER_POLL   1
enum { ID_OPEN = 1001, ID_PAUSE, ID_AUTORUN, ID_LOG, ID_FOLDER, ID_SVCSTART, ID_SVCSTOP, ID_EXIT };
enum { ST_DOWN, ST_ACTIVE, ST_PAUSED };

static tray_cfg_t  g_cfg;
static HWND        g_hwnd;
static NOTIFYICONDATAW g_nid;
static HICON       g_ico_on, g_ico_off;
static UINT        g_wm_taskbar;
static int         g_state = ST_DOWN, g_enforcing, g_autorun, g_warned;
static double      g_up_mbps, g_down_mbps;

static int gui_port(void) { int p = win_read_port(g_cfg.data_dir); return p ? p : 8080; }

/* ---- tiny HTTP client for the local API ---- */
static int http_call(const char *method, const char *path, const char *body, char *out, size_t outn) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return -1;
    DWORD to = 700;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&to, sizeof to);
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&to, sizeof to);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    int port = gui_port();
    a.sin_family = AF_INET; a.sin_port = htons((u_short)port); a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(s, (struct sockaddr *)&a, sizeof a)) { closesocket(s); return -1; }
    char req[600];
    int bl = body ? (int)strlen(body) : 0;
    int n = snprintf(req, sizeof req,
        "%s %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nX-NetGuard: 1\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
        method, path, port, bl, body ? body : "");
    size_t got = 0;
    if (send(s, req, n, 0) > 0 && out && outn > 1) {
        int r;
        while (got + 1 < outn && (r = recv(s, out + got, (int)(outn - 1 - got), 0)) > 0) got += (size_t)r;
        out[got] = 0;
    }
    closesocket(s);
    return (out && got == 0) ? -1 : 0;
}

static void poll_engine(void) {
    char b[4096];
    g_state = ST_DOWN;
    if (http_call("GET", "/api/stats", NULL, b, sizeof b) == 0 && strstr(b, "\"rules\"")) {
        g_state = strstr(b, "\"paused\":true") ? ST_PAUSED : ST_ACTIVE;
        g_enforcing = strstr(b, "\"enforcing\":true") != NULL;
        const char *t = strstr(b, "\"name\":\"TOTAL\"");                 /* first rule entry = all traffic */
        const char *u = t ? strstr(t, "\"up_bps\":") : NULL, *d = t ? strstr(t, "\"down_bps\":") : NULL;
        g_up_mbps   = u ? strtod(u + 9, NULL) / 1e6 : 0;
        g_down_mbps = d ? strtod(d + 11, NULL) / 1e6 : 0;
    }
}

static void refresh_icon(void) {
    g_nid.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;
    g_nid.hIcon = g_state == ST_ACTIVE ? g_ico_on : g_ico_off;
    if (g_state == ST_DOWN)        _snwprintf(g_nid.szTip, 127, L"NetGuard: engine not running");
    else if (g_state == ST_PAUSED) _snwprintf(g_nid.szTip, 127, L"NetGuard: PAUSED (all traffic passes)");
    else _snwprintf(g_nid.szTip, 127, L"NetGuard: %ls\ndown %.1f / up %.1f Mbit/s",
                    g_enforcing ? L"enforcing" : L"monitor-only", g_down_mbps, g_up_mbps);
    g_nid.szTip[127] = 0;
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}

static void balloon(const wchar_t *title, const wchar_t *text) {
    NOTIFYICONDATAW n = g_nid;
    n.uFlags = NIF_INFO;
    n.dwInfoFlags = NIIF_INFO;
    _snwprintf(n.szInfoTitle, 63, L"%ls", title);
    _snwprintf(n.szInfo, 255, L"%ls", text);
    Shell_NotifyIconW(NIM_MODIFY, &n);
}

static void open_gui(void) {
    char url[64];
    snprintf(url, sizeof url, "http://127.0.0.1:%d/", gui_port());
    win_open_url(url);
}

static void open_path(const char *p) {
    wchar_t w[400];
    MultiByteToWideChar(CP_UTF8, 0, p, -1, w, 400);
    ShellExecuteW(NULL, L"open", w, NULL, NULL, SW_SHOWNORMAL);
}

static void show_menu(void) {
    int svc = win_service_state();
    HMENU m = CreatePopupMenu();
    AppendMenuW(m, MF_STRING, ID_OPEN, L"Open NetGuard");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING | (g_state == ST_PAUSED ? MF_CHECKED : 0) | (g_state == ST_DOWN ? MF_GRAYED : 0),
                ID_PAUSE, L"Pause filtering (full speed)");
    AppendMenuW(m, MF_STRING | (g_autorun ? MF_CHECKED : 0), ID_AUTORUN, L"Show this icon at logon");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING, ID_LOG, L"View log");
    AppendMenuW(m, MF_STRING, ID_FOLDER, L"Open data folder");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    if (svc == 2) AppendMenuW(m, MF_STRING, ID_SVCSTOP,  L"Stop NetGuard service (asks for admin)");
    else          AppendMenuW(m, MF_STRING | (svc == 0 ? MF_GRAYED : 0), ID_SVCSTART, L"Start NetGuard service (asks for admin)");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING, ID_EXIT, L"Close tray icon (service keeps running)");
    SetMenuDefaultItem(m, ID_OPEN, FALSE);
    POINT pt; GetCursorPos(&pt);
    SetForegroundWindow(g_hwnd);                         /* required so the menu closes when clicking elsewhere */
    TrackPopupMenu(m, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, pt.x, pt.y, 0, g_hwnd, NULL);
    PostMessageW(g_hwnd, WM_NULL, 0, 0);
    DestroyMenu(m);
}

static LRESULT CALLBACK wndproc(HWND h, UINT msg, WPARAM w, LPARAM l) {
    if (msg == WM_TRAY) {
        if (LOWORD(l) == WM_LBUTTONDBLCLK) open_gui();
        else if (LOWORD(l) == WM_RBUTTONUP) show_menu();
        return 0;
    }
    if (msg == g_wm_taskbar && g_wm_taskbar) {           /* Explorer restarted: put the icon back */
        g_nid.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;
        Shell_NotifyIconW(NIM_ADD, &g_nid);
        refresh_icon();
        return 0;
    }
    switch (msg) {
    case WM_TIMER:
        if (w == TIMER_POLL) {
            int before = g_state;
            poll_engine(); refresh_icon();
            if (g_state == ST_DOWN && before != ST_DOWN && !g_cfg.quiet)
                balloon(L"NetGuard", L"The NetGuard engine stopped. Use the tray menu to start the service.");
        }
        return 0;
    case WM_COMMAND:
        switch (LOWORD(w)) {
        case ID_OPEN:    open_gui(); break;
        case ID_PAUSE:   http_call("POST", "/api/pause", g_state == ST_PAUSED ? "0" : "1", NULL, 0); poll_engine(); refresh_icon(); break;
        case ID_AUTORUN: if (win_autorun_set(!g_autorun) == 0) g_autorun = !g_autorun; break;
        case ID_LOG:     open_path(g_cfg.log_path); break;
        case ID_FOLDER:  open_path(g_cfg.data_dir); break;
        case ID_SVCSTART: win_relaunch_elevated(L"--start-service"); break;
        case ID_SVCSTOP:  win_relaunch_elevated(L"--stop-service"); break;
        case ID_EXIT:    DestroyWindow(h); break;
        }
        return 0;
    case WM_DESTROY:
        KillTimer(h, TIMER_POLL);
        Shell_NotifyIconW(NIM_DELETE, &g_nid);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, msg, w, l);
}

static HICON load_icon(int id, LPCWSTR fallback) {
    HICON i = (HICON)LoadImageW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(id), IMAGE_ICON,
                                GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0);
    return i ? i : LoadIconW(NULL, fallback);
}

int tray_main(const tray_cfg_t *c) {
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
    g_cfg = *c;
    g_autorun = win_autorun_get();
    g_ico_on  = load_icon(1, IDI_APPLICATION);
    g_ico_off = load_icon(2, IDI_WARNING);
    g_wm_taskbar = RegisterWindowMessageW(L"TaskbarCreated");

    WNDCLASSEXW wc; memset(&wc, 0, sizeof wc);
    wc.cbSize = sizeof wc; wc.lpfnWndProc = wndproc; wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"NetGuardTrayWindow";
    RegisterClassExW(&wc);
    g_hwnd = CreateWindowExW(0, wc.lpszClassName, L"NetGuard", WS_OVERLAPPED, 0, 0, 0, 0, NULL, NULL, wc.hInstance, NULL);
    if (!g_hwnd) return 1;

    memset(&g_nid, 0, sizeof g_nid);
    g_nid.cbSize = sizeof g_nid; g_nid.hWnd = g_hwnd; g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;
    g_nid.uCallbackMessage = WM_TRAY; g_nid.hIcon = g_ico_off;
    _snwprintf(g_nid.szTip, 127, L"NetGuard");
    Shell_NotifyIconW(NIM_ADD, &g_nid);

    poll_engine(); refresh_icon();
    if (!g_cfg.quiet) {
        if (g_state == ST_DOWN) balloon(L"NetGuard", L"The engine is not running. Right-click the icon to start the service.");
        else balloon(L"NetGuard is protecting this PC", L"Double-click the tray icon to open the control panel.");
    }
    SetTimer(g_hwnd, TIMER_POLL, 2000, NULL);

    MSG m;
    while (GetMessageW(&m, NULL, 0, 0) > 0) { TranslateMessage(&m); DispatchMessageW(&m); }
    return 0;
}
