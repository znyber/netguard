# NetGuard - per-application firewall + bandwidth limiter in C (Windows 10/11, Linux)

Block, whitelist or speed-limit **applications**, IPs, domains, ports, localhost, or all traffic - from a GUI in your browser.

## Install (Windows)
Run `NetGuard-Setup-1.1.0.exe` (build it with `build-installer.bat`, see below). It installs:
* **NetGuard service** - the engine. Starts with Windows, runs in the background as SYSTEM, **no console window and
  nothing printed**; logs go to `C:\ProgramData\NetGuard\netguard.log`. Restarts itself after a crash.
* **Tray icon** (`netguard.exe`) - shows at logon (optional). **Double-click** it, or right-click > *Open NetGuard*,
  to open the control panel in your default browser (`http://127.0.0.1:8080/`). Green shield = filtering,
  grey = paused / engine not running; the tooltip shows live speed and the mode.
* Tray menu: Open NetGuard, **Pause filtering (full speed)**, Show icon at logon, View log, Open data folder,
  Start/Stop service (asks for admin), Close tray icon (the service keeps running).
* Rules, logs, `gui.port`: `C:\ProgramData\NetGuard\`. Uninstall asks whether to delete them.

## Run modes - who prints what
| How it is started | Mode | Console output |
|---|---|---|
| Windows service / installer / tray / Start menu / logon | engine as service, or tray UI | **none** (log file only) |
| `netguardc.exe` in cmd / PowerShell | engine in the foreground, Ctrl+C stops | **logs on stdout** |
| `netguard.exe` typed in cmd / PowerShell (no args) | same, foreground | **logs on stdout** (cmd returns the prompt at once; use `start /wait` or `netguardc.exe`) |
| `netguard.exe --console` / `--tray` / `--service` | force foreground / tray / service | console only in foreground |
| `netguard.exe --install-service` `--remove-service` `--start-service` `--stop-service` | service control (UAC prompt) | none |
Run only one engine at a time (service *or* foreground); a second one refuses to start. To debug with logs:
`net stop NetGuard`, then `netguardc.exe -v` in an Administrator prompt; `net start NetGuard` when done.
Portable use: put `netguard.conf` next to the exe and all files stay there.

## Build
```
# MSYS2 UCRT64 shell
cmake -B build -G Ninja -DWINDIVERT_DIR=C:/WinDivert-2.2.2-A -DCMAKE_EXE_LINKER_FLAGS=-static
cmake --build build                      # -> build\netguard.exe (tray/service) + build\netguardc.exe (console)
build-installer.bat C:\WinDivert-2.2.2-A # needs Inno Setup 6.3+ -> installer\Output\NetGuard-Setup-1.1.0.exe
```
If the icon/manifest step fails, add `-DNG_NO_RESOURCES=ON` (works, only the icon becomes generic).
Trying it without driver/admin: `netguardc --simulate` feeds fake apps through the engine.
Linux: `cmake -B build && cmake --build build` (needs libnetfilter-queue-dev), run with sudo, see `--gateway`.

## The GUI
| Tab | What it does |
|---|---|
| Overview | live table + graph per rule (click a row), built-in whitelist listed below the rules |
| Applications | every program that sent traffic; **Allow / Limit / Block / Reset** per app |
| Rules | add / edit / reorder / enable / delete, *Quick rules* (LAN, localhost, all traffic) |
| Defaults | the built-in default whitelist with live traffic and an on/off tick per item |
| Config | the raw rules file; saving validates first, nothing changes on error |
Header: **Unlisted apps: Allow / Block**, **Pause / Resume**, Filtering on/off and the capture mode.
Tables have search, filters and click-to-sort headers (remembered by the browser). Every change is validated, applied
at once and saved to `netguard.conf` (previous copy: `netguard.conf.bak`).

## "Block everything by default" workflow
1. Leave *Unlisted apps: Allow* for a while and watch the Applications tab.
2. Set each program you need to **Allow** (or **Limit**).
3. Switch *Unlisted apps* to **Block**. DHCP, DNS, ping, time sync and VPN/PPP protocols stay allowed (Defaults tab).
Locked out? NetGuard and its GUI are never filtered; press **Pause**, or edit `netguard.conf` (`default=allow`).

## Built-in default whitelist
Checked **before** every rule and before *Unlisted apps: Block*, matched by protocol/port (DHCP/DNS/time run as
services inside `svchost.exe`, so they cannot be told apart by program): DHCP (udp 67-68), DHCPv6 (546-547), DNS (53),
ICMP, ICMPv6 (IPv6 needs it), Windows Time (udp 123), PPP/VPN tunnels (GRE, ESP, tcp 1723, udp 500/1701/4500).
PPPoE negotiation itself runs below IP and is never filtered. Untick items in the Defaults tab.

## Rule semantics
* **First matching rule wins.** No match -> default policy (allow, or block when *Unlisted apps: Block*).
* `app=` program name (`chrome.exe`) or full path (quote it if it has spaces); `ip=` address, CIDR, `localhost`, `lan`,
  `any`; `domain=` (resolved every 60 s); `proto=`; `port=` (either end); `up=` / `down=` in bit/s (`512k`, `2M`).
* A rule with no ip/domain ("all traffic") never touches localhost; add `ip=localhost` for that. The default policy never
  applies to localhost either.
* One shaper per rule: a rule for one app limits that app in total; a rule without app limits all it matches together.

## Performance (Windows)
* **MONITOR-ONLY**: when no enabled rule can change a packet's fate (Pause, Filtering off, or default Allow with only
  Allow rules) NetGuard watches *copies* - the real traffic is never held up, so there is no speed loss.
* **ENFORCING** (any Block/Limit rule or *Block unlisted apps*): every packet goes through user mode. Packets are handled
  in batches of up to 64 per call, receiving and re-injecting run on two overlapping threads (a ring of 8 batches,
  strict FIFO), the WinDivert queue is limited to 250 ms (a 2 s backlog feels like lag) and the capture thread runs above
  normal priority. The mode switches live when you edit rules.
* The GUI does no work while its browser tab is hidden. Typical engine cost: ~70 ns per packet per core (measured).
* Reaching 10-100 Gbit/s needs another data path (kernel filtering with WFP, a driver, or Linux XDP/eBPF).

## Status
| Part | State |
|---|---|
| Engine, rules, default whitelist, GUI, API, logging, pause, port fallback, run modes, batching logic, sender pipeline protocol | built and tested on Linux (simulator + unit harnesses) |
| Windows service, tray, installer script, WinDivert capture loop, per-app flow tracking | written; compiled only against stub headers - **needs your first real build and run** |
| Linux NFQUEUE backend | no per-app support (kernel cannot say which app); `default=block` ignored there |

## Known limits
* All services inside `svchost.exe` share one app entry.
* The GUI/API is reachable by any process on this PC (127.0.0.1 only; web pages on other sites are blocked by
  Host/Origin/header checks). Don't use it on a shared multi-user machine without adding a token.
* Wildcard domains (`*.example.com`) need DNS sniffing - not implemented.
* Protection starts when the service starts (early at boot), not before.

## Layout
`src/engine.c` rules/shaper/stats/config | `src/backend_win.c` / `backend_linux.c` | `src/winsvc.c` service |
`src/tray_win.c` tray | `src/web.c` HTTP API | `web/index.html` GUI (embedded by `python3 tools/embed.py`) |
`res/` icons + manifest (`python3 tools/make_icons.py`) | `installer/netguard.iss` Inno Setup script.
