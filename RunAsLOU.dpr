program RunAsLOU;

{$APPTYPE CONSOLE}
{$R *.res}

uses
  SysUtils,
  Windows,
  uWtsUtils in 'uWtsUtils.pas';

function FileExists(FileName: string): Boolean;
var
  hFile                       : THandle;
  lpFindFileData              : TWin32FindData;
begin
  Result := False;
  hFile := FindFirstFile(PChar(FileName), lpFindFileData);
  if hFile <> INVALID_HANDLE_VALUE then
  begin
    FindClose(hFile);
    Result := True;
  end;
end;

var
  sPath                       : string;
begin
  try
    WriteLn(ExtractFileName(ParamStr(0)) + ' [v1.0.0]' + #13#10);

    if ParamCount < 1 then
    begin
      Writeln('*** error: you must supply the full local path to the program to run as the logged on user!');
      Exit;
    end;

    sPath := ParamStr(1);

    if not FileExists(sPath) then
    begin
      WriteLn('*** error: <' + sPath + '> was not found.');
      Exit;
    end;

    if mgStartProcess(sPath, False) then
    begin
      WriteLn('process started successfully!');
    end
    else
    begin
      WriteLn('process did not start.');
    end;
  except
    on E: Exception do
      LogMessage(E.Classname + ': ' + E.Message);
  end;
end.

