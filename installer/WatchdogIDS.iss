#define MyAppName "Watchdog IDS"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Watchdog IDS"
#define MyAppExeName "WatchdogIDS.exe"

[Setup]
AppId={{A9C34E13-4E6F-4F1D-9C75-2B4C62A1D8E7}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={localappdata}\Programs\Watchdog IDS
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
OutputDir=..\installer-output
OutputBaseFilename=WatchdogIDS-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "..\dist\WatchdogIDS\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Watchdog IDS"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\Watchdog IDS"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Watchdog IDS"; Flags: postinstall nowait skipifsilent
