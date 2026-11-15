; NetGuard installer - compile with Inno Setup 6.3 or newer (https://jrsoftware.org/isinfo.php):
;   iscc installer\netguard.iss /DWinDivertDir=C:\WinDivert-2.2.2-A\x64
; Expects the build output in ..\build (netguard.exe, netguardc.exe).
#define MyAppName    "NetGuard"
#define MyAppVersion "1.1.0"
#ifndef BuildDir
  #define BuildDir "..\build"
#endif
#ifndef WinDivertDir
  #define WinDivertDir "C:\WinDivert-2.2.2-A\x64"
#endif

[Setup]
AppId={{B6F6C1E0-5C3A-4B7E-9E1D-6A0E3D6C2F11}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=NetGuard
DefaultDirName={autopf}\NetGuard
DefaultGroupName=NetGuard
DisableProgramGroupPage=yes
OutputDir=Output
OutputBaseFilename=NetGuard-Setup-{#MyAppVersion}
SetupIconFile=..\res\netguard.ico
UninstallDisplayIcon={app}\netguard.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
CloseApplications=no

[Tasks]
Name: "trayautostart"; Description: "Show the NetGuard tray icon when I sign in to Windows"; GroupDescription: "Startup:"; Flags: checkedonce
Name: "desktopicon";   Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: unchecked

[Dirs]
Name: "{commonappdata}\NetGuard"

[Files]
Source: "{#BuildDir}\netguard.exe";  DestDir: "{app}"; Flags: ignoreversion
Source: "{#BuildDir}\netguardc.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#WinDivertDir}\WinDivert.dll";   DestDir: "{app}"; Flags: ignoreversion
Source: "{#WinDivertDir}\WinDivert64.sys"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#WinDivertDir}\..\LICENSE"; DestDir: "{app}\licenses"; DestName: "WinDivert-LICENSE.txt"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\README.md";     DestDir: "{app}"; Flags: ignoreversion
; NOT installed as netguard.conf next to the exe: that would switch NetGuard into "portable" mode.
; The real rules file lives in %ProgramData%\NetGuard and is created on first start.
Source: "..\netguard.conf"; DestDir: "{app}"; DestName: "netguard.default.conf"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\NetGuard"; Filename: "{app}\netguard.exe"; Parameters: "--tray"; Comment: "Open the NetGuard control panel"
Name: "{autoprograms}\Uninstall NetGuard"; Filename: "{uninstallexe}"
Name: "{autodesktop}\NetGuard"; Filename: "{app}\netguard.exe"; Parameters: "--tray"; Tasks: desktopicon

[Run]
; 1) the engine: a Windows service (starts at boot, no console, restarts itself after a crash)
Filename: "{app}\netguard.exe"; Parameters: "--install-service"; Flags: runhidden waituntilterminated; StatusMsg: "Installing and starting the NetGuard service..."
; 2) tray icon at logon, for the user who is installing (runs un-elevated)
Filename: "{app}\netguard.exe"; Parameters: "--tray-autorun-on"; Flags: runhidden waituntilterminated runasoriginaluser; Tasks: trayautostart
; 3) show the tray icon now
Filename: "{app}\netguard.exe"; Parameters: "--tray"; Description: "Show the NetGuard tray icon now"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
Filename: "{app}\netguard.exe"; Parameters: "--remove-service"; Flags: runhidden waituntilterminated; RunOnceId: "NgRemoveService"
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM netguard.exe"; Flags: runhidden waituntilterminated; RunOnceId: "NgKillTray"
Filename: "{sys}\sc.exe"; Parameters: "stop WinDivert";   Flags: runhidden waituntilterminated; RunOnceId: "NgStopDriver"
Filename: "{sys}\sc.exe"; Parameters: "delete WinDivert"; Flags: runhidden waituntilterminated; RunOnceId: "NgDelDriver"

[Code]
// Stop a running NetGuard (service, tray, console) and the WinDivert driver so files can be replaced.
procedure StopRunning();
var rc: Integer;
begin
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop NetGuard', '', SW_HIDE, ewWaitUntilTerminated, rc);
  Sleep(2500);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM netguard.exe',  '', SW_HIDE, ewWaitUntilTerminated, rc);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM netguardc.exe', '', SW_HIDE, ewWaitUntilTerminated, rc);
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop WinDivert', '', SW_HIDE, ewWaitUntilTerminated, rc);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopRunning();
  Result := '';
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    RegDeleteValue(HKEY_CURRENT_USER, 'Software\Microsoft\Windows\CurrentVersion\Run', 'NetGuardTray');
    if not UninstallSilent then
      if MsgBox('Also delete your NetGuard rules and logs?', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        DelTree(ExpandConstant('{commonappdata}\NetGuard'), True, True, True);
  end;
end;
