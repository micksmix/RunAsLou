{
BSD 2-Clause License

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are
   met:

   * Redistributions of source code must retain the above copyright
	 notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
	 copyright notice, this list of conditions and the following disclaimer
	 in the documentation and/or other materials provided with the
	 distribution.
   * Neither the name of the  nor the names of its
	 contributors may be used to endorse or promote products derived from
	 this software without specific prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
}

unit uWtsUtils;

{$WARN SYMBOL_PLATFORM OFF}

interface

uses
  Windows,
  TLHelp32,
  SysUtils;

const
  wtsapi                      = 'wtsapi32.dll';
  advapi32                    = 'advapi32.dll';
  userenvlib                  = 'userenv.dll';
  TOKEN_ADJUST_SESSIONID      = $0100;
  SE_DEBUG_NAME               = 'SeDebugPrivilege';
  WTS_CURRENT_SERVER_HANDLE   = 0;

type

  _WTS_CONNECTSTATE_CLASS = (
    WTSActive, // User logged on to WinStation
    WTSConnected, // WinStation connected to client
    WTSConnectQuery, // In the process of connecting to client
    WTSShadow, // Shadowing another WinStation
    WTSDisconnected, // WinStation logged on without client
    WTSIdle, // Waiting for client to connect
    WTSListen, // WinStation is listening for connection
    WTSReset, // WinStation is being reset
    WTSDown, // WinStation is down due to error
    WTSInit); // WinStation in initialization

  WTS_CONNECTSTATE_CLASS = _WTS_CONNECTSTATE_CLASS;
  TWtsConnectStateClass = WTS_CONNECTSTATE_CLASS;

  PWTS_SESSION_INFOA = ^WTS_SESSION_INFOA;

  _WTS_SESSION_INFOA = record
    SessionId: DWORD;
    pWinStationName: LPSTR; // WinStation name to which this session is connected
    State: WTS_CONNECTSTATE_CLASS; // connection state
  end;

  WTS_SESSION_INFOA = _WTS_SESSION_INFOA;

  TWtsSessionInfoA = WTS_SESSION_INFOA;
  PWtsSessionInfoA = PWTS_SESSION_INFOA;

  _WTS_PROCESS_INFO = record
    SessionId: DWORD;
    ProcessId: DWORD;
    pProcessName: LPTSTR;
    pUserSid: PSID;
  end;

  WTS_PROCESS_INFO = _WTS_PROCESS_INFO;
  PWTS_PROCESS_INFO = ^WTS_PROCESS_INFO;

  _TOKEN_INFORMATION_CLASS = (
    TokenInfoClassPad0,
    TokenUser,
    TokenGroups,
    TokenPrivileges,
    TokenOwner,
    TokenPrimaryGroup,
    TokenDefaultDacl,
    TokenSource,
    TokenType,
    TokenImpersonationLevel,
    TokenStatistics,
    TokenRestrictedSids,
    TokenSessionId,
    TokenGroupsAndPrivileges,
    TokenSessionReference,
    TokenSandBoxInert,
    TokenAuditPolicy,
    TokenOrigin);

  //kernel32
  TWTSGetActiveConsoleSessionId = function: DWORD; stdcall;

  TProcessIdToSessionId = function(
    dwProcessId: DWORD;
    var pSessionId: DWORD): BOOL; stdcall;

  //wtsapi
  TWTSQueryUserToken = function(
    SessionId: ULONG;
    var phToken: THANDLE): BOOL; stdcall;

  TWTSFreeMemory = procedure(pMemory: Pointer); stdcall;

  TWTSEnumerateSessions = function(
    hServer: THandle;
    Reserved: DWORD;
    Version: DWORD;
    var ppSessionInfo: Pointer;
    var pCount: DWORD): bool; stdcall;

  //http://msdn.microsoft.com/en-us/library/aa383842%28VS.85%29.aspx
  TWTSSendMessage = function(
    hServer: THandle;
    SessionId: DWORD;
    pTitle: PWideChar;
    TitleLength: DWORD;
    pMessage: PWideChar;
    MessageLength: DWORD;
    Style: DWORD;
    Timeout: DWORD;
    var pResponse: DWORD;
    bWait: bool): bool; stdcall;

  //advapi32
  TSetTokenInformation = function(
    TokenHandle: THANDLE;
    TokenInformationClass: _TOKEN_INFORMATION_CLASS;
    TokenInformation: Pointer;
    TokenInformationLength:
    DWORD): BOOL; stdcall;

  TAdjustTokenPrivileges = function(
    TokenHandle: THANDLE;
    DisableAllPrivileges: BOOL;
    NewState: Pointer;
    BufferLength: DWORD;
    PreviousState: Pointer;
    ReturnLength: LPDWORD): BOOL; stdcall;

  //userenvlib
  TCreateEnvironmentBlock = function(
    var lpEnvironment: Pointer;
    hToken: THandle;
    bInherit: BOOL): BOOL; stdcall;

var
  WTSGetActiveConsoleSessionId: TWTSGetActiveConsoleSessionId = nil;
  ProcessIdToSessionId        : TProcessIdToSessionId = nil;
  WTSQueryUserToken           : TWTSQueryUserToken = nil;
  SetTokenInformation         : TSetTokenInformation = nil;
  AdjustTokenPrivileges       : TAdjustTokenPrivileges = nil;
  CreateEnvironmentBlock      : TCreateEnvironmentBlock = nil;
  WTSSendMessage              : TWTSSendMessage = nil;
  WTSEnumerateSessions        : TWTSEnumerateSessions = nil;
  WTSFreeMemory               : TWTSFreeMemory = nil;

  //function SetDebugPrivilege(var hProc: THandle): Boolean;
  //
function mgSessionNumber: Integer;
function mgActiveConsole: Integer;
function mgGetProcessID(strProcess: string; iSessionID: Integer = -1): DWORD;
function mgStartProcess(strProcess: string; bLocalSystem: Boolean = True; iSessionID:
  Integer = -1): Boolean;
function mgImpersonateLoggedOnUser: Boolean;
function mgRevertToSelf: Boolean;
//
procedure LogMessage(sMsg: string; bConsole: boolean = False);

implementation

var
  LibsLoaded                  : integer = 0;
  FhUserTokenDup              : THandle;

procedure LogMessage(sMsg: string; bConsole: boolean = False);
begin
 // bConsole := True;
  if not bConsole then
  begin
    OutputDebugString(PChar('*** RunAsLou: ' + sMsg));
  end
  else
  begin
    WriteLn('*** RunAsLou: ' + sMsg);
  end;

end;

function GetProcedureAddress(var P: Pointer; const ModuleName, ProcName: string):
  boolean;
var
  ModuleHandle                : HMODULE;
begin
  if not Assigned(P) then
  begin
    ModuleHandle := GetModuleHandle(PChar(ModuleName));
    if ModuleHandle = 0 then
      ModuleHandle := LoadLibrary(PChar(ModuleName));
    if ModuleHandle <> 0 then
      P := Pointer(GetProcAddress(ModuleHandle, PChar(ProcName)));
    Result := Assigned(P);
  end
  else
    Result := True;
end;

function InitProcLibs: boolean;
begin
  if LibsLoaded > 0 then
    Result := True
  else if LibsLoaded < 0 then
    Result := False
  else
  begin
    LibsLoaded := -1;
    if GetProcedureAddress(@WTSGetActiveConsoleSessionId, kernel32,
      'WTSGetActiveConsoleSessionId')
      and
      GetProcedureAddress(@ProcessIdToSessionId, kernel32, 'ProcessIdToSessionId') and
      GetProcedureAddress(@WTSQueryUserToken, wtsapi, 'WTSQueryUserToken') and
      GetProcedureAddress(@WTSSendMessage, wtsapi, 'WTSSendMessageW') and
      GetProcedureAddress(@SetTokenInformation, advapi32, 'SetTokenInformation') and
      GetProcedureAddress(@AdjustTokenPrivileges, advapi32, 'AdjustTokenPrivileges') and
      GetProcedureAddress(@WTSEnumerateSessions, wtsapi, 'WTSEnumerateSessionsA') and
      GetProcedureAddress(@WTSFreeMemory, wtsapi, 'WTSFreeMemory') and
      GetProcedureAddress(@CreateEnvironmentBlock, userenvlib, 'CreateEnvironmentBlock')
        then
      LibsLoaded := 1;
    Result := LibsLoaded = 1;
  end;
end;

function mgSessionNumber: Integer;
var
  dwSessionID                 : DWord;
begin
  Result := 0;

  if not InitProcLibs then
  begin
    LogMessage('could not load required libraries.');
    Exit;
  end;

  ProcessIdToSessionId(GetCurrentProcessId(), dwSessionID);
  Result := dwSessionID;
end;

function mgActiveConsole: Integer;
begin
  Result := 0;
  if not InitProcLibs then
  begin
    LogMessage('could not load required libraries.');
    Exit;
  end;

  Result := WTSGetActiveConsoleSessionId;
end;

function mgGetActiveWtsSession(): Integer;
var
  info                        : PWtsSessionInfoA;
  cnt, idx                    : Cardinal;
  sWtsState                   : string;
begin

  if WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, Pointer(info), cnt) then
  begin
    for idx := 0 to cnt - 1 do
    begin

      sWtsState := '-';
      case info^.State of
        WTSActive: sWtsState := 'WTSActive';
        WTSConnected: sWtsState := 'WTSConnected';
        WTSConnectQuery: sWtsState := 'WTSConnectQuery';
        WTSShadow: sWtsState := 'WTSShadow';
        WTSDisconnected: sWtsState := 'WTSDisconnected';
        WTSIdle: sWtsState := 'WTSIdle';
        WTSListen: sWtsState := 'WTSListen';
        WTSReset: sWtsState := 'WTSReset';
        WTSDown: sWtsState := 'WTSDown';
        WTSInit: sWtsState := 'WTSInit';
      end;

      if info^.State <> WTSActive then
      begin
        Inc(info);
        Continue;
      end;

      LogMessage(IntToStr(info^.SessionId) + ' - ' + info^.pWinStationName + ' - ' +
        sWtsState);

      Result := info^.SessionId;
      //Inc(info);
    end;

    WTSFreeMemory(info);
  end;
end;

function mgGetProcessID(strProcess: string; iSessionID: Integer = -1): DWORD;
var
  dwSessionId, winlogonSessId : DWord;
  hsnap                       : THandle;
  procEntry                   : TProcessEntry32;
  myPID                       : Cardinal;
begin
  Result := 0;

  if not InitProcLibs then
  begin
    LogMessage('could not load required libraries.');
    Exit;
  end;

  { check running processes and return ID of process in current session... }
  if iSessionID = -1 then
  begin
    dwSessionId := WTSGetActiveConsoleSessionId
  end
  else
  begin
    dwSessionId := iSessionID;
  end;

  if dwSessionId < 1 then
  begin
    dwSessionId := mgGetActiveWtsSession();
  end;

  hSnap := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnap = INVALID_HANDLE_VALUE) then
  begin
    LogMessage('CreateToolhelp32Snapshot failed - ' + (SysErrorMessage(GetLastError)));
    Exit;
  end;

  strProcess := UpperCase(ExtractFileName(strProcess));
  myPID := GetCurrentProcessId;
  procEntry.dwSize := sizeof(TProcessEntry32);

  if (not Process32First(hSnap, procEntry)) then
  begin
    LogMessage('Process32First failed - ' + (SysErrorMessage(GetLastError)));
    Exit;
  end;

  repeat
    if (procEntry.th32ProcessID <> myPID) and ((UpperCase(procEntry.szExeFile) =
      strProcess) or
      (UpperCase(ExtractFileName(procEntry.szExeFile)) = strProcess)) then
    begin
      winlogonSessId := 0;
      if (ProcessIdToSessionId(procEntry.th32ProcessID, winlogonSessId) and
        (winlogonSessId = dwSessionId)) then
      begin
        Result := procEntry.th32ProcessID;
        break;
      end;
    end;
  until (not Process32Next(hSnap, procEntry));
end;

function mgStartProcess(strProcess: string; bLocalSystem: Boolean = True; iSessionID:
  Integer = -1): Boolean;
var
  pi                          : PROCESS_INFORMATION;
  si                          : STARTUPINFO;
  winlogonPid                 : DWORD;
  dwSessionId                 : DWORD;
  hUserTokenDup, hPToken, hProcess: THANDLE;
  dwCreationFlags             : DWORD;
  tp                          : TOKEN_PRIVILEGES;
  lpenv                       : pointer;
  bError                      : Boolean;
  strClone                    : string;
begin
  //start process as elevated by cloning existing process
  Result := True;
  bError := False;

  if not InitProcLibs then
  begin
    LogMessage('could not load required libraries.');
    Exit;
  end;

  if bLocalSystem then
  begin
    strClone := 'winlogon.exe';
  end
  else
  begin
    strClone := 'explorer.exe';
  end;

  winlogonPid := mgGetProcessID(strClone, iSessionID);
  LogMessage('cloned process = ' + IntToStr(winlogonPid));
  try
    //get user token for winlogon and duplicate it... (this gives us admin rights)
    dwSessionId := WTSGetActiveConsoleSessionId();
    //WTSQueryUserToken(dwSessionId, hUserToken);
    dwCreationFlags := NORMAL_PRIORITY_CLASS or CREATE_NEW_CONSOLE;
    ZeroMemory(@si, sizeof(STARTUPINFO));
    si.cb := sizeof(STARTUPINFO);
    si.lpDesktop := PChar('Winsta0\Default');
    ZeroMemory(@pi, sizeof(pi));
    hProcess := OpenProcess(MAXIMUM_ALLOWED, FALSE, winlogonPid);

    if hProcess < 1 then
    begin
      LogMessage('OpenProcess failed - ' + (SysErrorMessage(GetLastError)));
      bError := True;
      Exit;
    end;

    //SetDebugPrivilege(hProcess);

    if (not OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY or
      TOKEN_DUPLICATE or TOKEN_ASSIGN_PRIMARY or TOKEN_ADJUST_SESSIONID or TOKEN_READ or
      TOKEN_WRITE, hPToken)) then
    begin
      LogMessage('OpenProcessToken failed - ' + (SysErrorMessage(GetLastError)));
      bError := True;
      Exit;
    end;

    if (not LookupPrivilegeValue(nil, SE_DEBUG_NAME, tp.Privileges[0].Luid)) then
    begin
      LogMessage('LookupPrivilegeValue failed. - ' + (SysErrorMessage(GetLastError)));
      bError := True;
      Exit;
    end;

    tp.PrivilegeCount := 1;
    tp.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;
    DuplicateTokenEx(hPToken, MAXIMUM_ALLOWED, nil, SecurityIdentification, TokenPrimary,
      hUserTokenDup);
    
	//adjust token privilege
    SetTokenInformation(hUserTokenDup, TokenSessionId, pointer(dwSessionId),
      sizeof(DWORD));

    if (not AdjustTokenPrivileges(hUserTokenDup, FALSE, @tp, sizeof(TOKEN_PRIVILEGES),
      nil, nil)) then
    begin
      LogMessage('AdjustTokenPrivileges failed. - ' + (SysErrorMessage(GetLastError)));
      bError := True;
    end;

    lpEnv := nil;
    if (CreateEnvironmentBlock(lpEnv, hUserTokenDup, True)) then
    begin
      dwCreationFlags := dwCreationFlags or CREATE_UNICODE_ENVIRONMENT;
    end
    else
    begin
      lpEnv := nil;
    end;

    //launch the process in the client's logon session
    if not CreateProcessAsUser(hUserTokenDup, nil, PChar(strProcess), nil, nil, FALSE,
      dwCreationFlags, lpEnv, PChar(ExtractFilePath(strProcess)), si, pi) then
      bError := True;
	  
    try
      CloseHandle(hProcess);
      //CloseHandle(hUserToken);
      CloseHandle(hUserTokenDup);
      CloseHandle(hPToken);
    except
      //
    end;
  except on E: Exception do
    begin
      bError := True;
      LogMessage(E.ClassName + ': ' + E.Message);
    end;
  end;
  Result := not bError;
end;

function mgImpersonateLoggedOnUser: Boolean;
var
  pi                          : PROCESS_INFORMATION;
  si                          : STARTUPINFO;
  winlogonPid, dwSessionId    : DWord;
  //hUserToken        : THandle;
  hPToken, hProcess           : THandle;
  tp                          : TOKEN_PRIVILEGES;
  bError                      : Boolean;
  strClone                    : string;
begin
  { start process as elevated by cloning existing process, as we're running as admin... }
  Result := True;
  bError := False;

  if not InitProcLibs then
  begin
    LogMessage('could not load required libraries.');
    Exit;
  end;

  strClone := 'explorer.exe';
  winlogonPid := mgGetProcessID(strClone);
  try
    { get user token for winlogon and duplicate it... (this gives us admin rights) }
    dwSessionId := WTSGetActiveConsoleSessionId();
    //WTSQueryUserToken(dwSessionId, hUserToken);
    ZeroMemory(@si, sizeof(STARTUPINFO));
    si.cb := sizeof(STARTUPINFO);
    si.lpDesktop := PChar('Winsta0\Default');
    ZeroMemory(@pi, sizeof(pi));
    hProcess := OpenProcess(MAXIMUM_ALLOWED, FALSE, winlogonPid);

    //SetDebugPrivilege(hProcess);
	
    if (not OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY or
      TOKEN_DUPLICATE or TOKEN_ASSIGN_PRIMARY or TOKEN_ADJUST_SESSIONID or TOKEN_READ or
      TOKEN_WRITE, hPToken)) then
    begin
      LogMessage('OpenProcessToken failed. - ' + (SysErrorMessage(GetLastError)));
      bError := True;
    end;

    if (not LookupPrivilegeValue(nil, SE_DEBUG_NAME, tp.Privileges[0].Luid)) then
    begin
      LogMessage('LookupPrivilegeValue failed. - ' + (SysErrorMessage(GetLastError)));
      bError := True;
    end;

    tp.PrivilegeCount := 1;
    tp.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;
    DuplicateTokenEx(hPToken, MAXIMUM_ALLOWED, nil, SecurityIdentification, TokenPrimary,
      FhUserTokenDup);
    
    SetTokenInformation(FhUserTokenDup, TokenSessionId, pointer(dwSessionId),
      sizeof(DWORD));

    if (not AdjustTokenPrivileges(FhUserTokenDup, FALSE, @tp, sizeof(TOKEN_PRIVILEGES),
      nil, nil)) then
    begin
      LogMessage('AdjustTokenPrivileges failed. - ' + (SysErrorMessage(GetLastError)));
      bError := True;
    end;

    if (GetLastError() = ERROR_NOT_ALL_ASSIGNED) then
    begin
      bError := True;
    end;
    
    ImpersonateLoggedOnUser(FhUserTokenDup);

    //close handles
    try
      CloseHandle(hProcess);
      //CloseHandle(hUserToken);
      CloseHandle(hPToken);
    except
      {}
    end;
  except on E: Exception do
    begin
      bError := True;
      LogMessage(E.ClassName + ': ' + E.Message);
    end;
  end;
  Result := not bError;
end;

function mgRevertToSelf: Boolean;
begin
  RevertToSelf;
  Result := CloseHandle(FhUserTokenDup);
end;

{
function SetDebugPrivilege(var hProc: THandle): Boolean;
var
hToken                      : THandle;
TP                          : TTokenPrivileges;
lpLuid                      : TLargeInteger;
dwReturnLength              : DWORD;
begin
Result := False;
if OpenProcessToken(hProc, TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, hToken) then
begin
  if LookupPrivilegeValue(nil, 'SeDebugPrivilege', lpLuid) then
  begin
    TP.PrivilegeCount := 1;
    TP.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;
    TP.Privileges[0].Luid := lpLuid;
    Result := Windows.AdjustTokenPrivileges(hToken, False, TP, sizeof(TP), nil,
      dwReturnLength);
  end;
  CloseHandle(hToken);
end;
end;
}
end.

