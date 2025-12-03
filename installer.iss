; Inno Setup Script for CustosEye
; This script creates a professional Windows installer
; Version will be passed via command line: iscc /DAppVersion="x.y.z" installer.iss

#ifndef AppVersion
  #define AppVersion "0.2.0"
#endif

#define AppName "CustosEye"
#define AppPublisher "CustosEye"
#define AppURL "https://github.com/yourusername/CustosEye"
#define AppExeName "CustosEye.exe"
#define AppId "{{CustosEye-2025-01-01}}"

[Setup]
; App identification
AppId={#AppId}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
AllowNoIcons=yes
LicenseFile=LICENSE.md
OutputDir=installer_output
OutputBaseFilename=CustosEye-Setup
SetupIconFile=dashboard\static\assets\favicon.ico
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppName} - Local system visibility and monitoring
VersionInfoCopyright=© 2025 CustosEye. All Rights Reserved.
VersionInfoProductName={#AppName}
VersionInfoProductVersion={#AppVersion}
UninstallDisplayIcon={app}\{#AppExeName}
UninstallDisplayName={#AppName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "quicklaunchicon"; Description: "{cm:CreateQuickLaunchIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked; OnlyBelowVersion: 6.1; Check: not IsAdminInstallMode
Name: "startmenu"; Description: "Create Start Menu shortcut"; GroupDescription: "Shortcuts"; Flags: checkedonce
Name: "launchafterinstall"; Description: "Launch CustosEye after installation"; GroupDescription: "Options"; Flags: checkedonce

[Files]
; Main executable (will be installed as CustosEye.exe in the folder)
Source: "dist\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion
; Version and hash files
Source: "dist\VERSION.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\CUSTOSEYE_SHA256.txt"; DestDir: "{app}"; Flags: ignoreversion
; Data directory
Source: "release\data\*"; DestDir: "{app}\data"; Flags: ignoreversion recursesubdirs createallsubdirs
; Assets directory
Source: "release\assets\*"; DestDir: "{app}\assets"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon; WorkingDir: "{app}"
Name: "{userappdata}\Microsoft\Internet Explorer\Quick Launch\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: quicklaunchicon; WorkingDir: "{app}"

[Run]
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(AppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent; Tasks: launchafterinstall

