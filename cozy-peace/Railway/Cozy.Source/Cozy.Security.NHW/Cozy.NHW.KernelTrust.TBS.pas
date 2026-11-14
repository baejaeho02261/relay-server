unit Cozy.NHW.KernelTrust.TBS;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils;

type
  TTpmDeviceInfo = packed record
    StructVersion: Cardinal;
    TpmVersion: Cardinal;
    TpmInterfaceType: Cardinal;
    TpmImpRevision: Cardinal;
  end;

function CaptureMeasuredBootLog(out DeviceInfo: TTpmDeviceInfo;
  out LogData: TBytes): Boolean;

implementation

uses
  Cozy.NHW.WinPointers;

const
  TBS_SUCCESS = 0;
  TBS_TCGLOG_SRTM_CURRENT = 0;
  MAX_TCG_LOG_BYTES = 16 * 1024 * 1024;

type
  TTbsiGetDeviceInfo = function(Size: Cardinal; Info: Pointer): Cardinal; stdcall;
  TTbsiGetTCGLogEx = function(LogType: Cardinal; Output: Pointer;
    InOutBytes: PCardinal): Cardinal; stdcall;

function CaptureMeasuredBootLog(out DeviceInfo: TTpmDeviceInfo;
  out LogData: TBytes): Boolean;
var
  M: HMODULE;
  GetInfo: TTbsiGetDeviceInfo;
  GetLog: TTbsiGetTCGLogEx;
  Needed: Cardinal;
  Status: Cardinal;
begin
  Result := False;
  DeviceInfo := Default(TTpmDeviceInfo);
  LogData := nil;
  M := WinLoadLibrary('tbs.dll');
  if M = 0 then Exit;
  try
    GetInfo := TTbsiGetDeviceInfo(WinExport(M, 'Tbsi_GetDeviceInfo'));
    GetLog := TTbsiGetTCGLogEx(WinExport(M, 'Tbsi_Get_TCG_Log_Ex'));
    if not Assigned(GetInfo) or not Assigned(GetLog) then Exit;
    if GetInfo(SizeOf(DeviceInfo), @DeviceInfo) <> TBS_SUCCESS then Exit;

    Needed := 0;
    GetLog(TBS_TCGLOG_SRTM_CURRENT, nil, @Needed);
    if (Needed = 0) or (Needed > MAX_TCG_LOG_BYTES) then Exit;
    SetLength(LogData, Needed);
    Status := GetLog(TBS_TCGLOG_SRTM_CURRENT, @LogData[0], @Needed);
    if (Status <> TBS_SUCCESS) or (Needed = 0) or
      (Needed > Cardinal(Length(LogData))) then Exit;
    if Needed < Cardinal(Length(LogData)) then
      FillChar(LogData[Needed], Length(LogData) - Integer(Needed), 0);
    SetLength(LogData, Needed);
    Result := True;
  finally
    if not Result then
    begin
      if Length(LogData) <> 0 then FillChar(LogData[0], Length(LogData), 0);
      LogData := nil;
      DeviceInfo := Default(TTpmDeviceInfo);
    end;
    WinFreeLibrary(M);
  end;
end;

end.
