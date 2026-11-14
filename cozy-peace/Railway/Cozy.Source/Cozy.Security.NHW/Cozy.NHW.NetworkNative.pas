unit Cozy.NHW.NetworkNative;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes;

// Read-only snapshots. False means incomplete/unknown; outputs are then empty.
// The three WFP enumerators are separate OS snapshots, not an atomic global view.
function TakeWFPSnapshots(Filters, Callouts, Providers: TStringList): Boolean;
function TakeDefaultRouteSnapshot(Routes: TStringList): Boolean;
function TakeProxySnapshot(ProxyState: TStringList): Boolean;

{$IFDEF NHW_NATIVE5_TESTS}
function TestNetworkNativeHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  System.SyncObjs,
  Cozy.NHW.WinPointers,
  Cozy.NHW.NetworkSnapshot.Decoders;

const
  RPC_C_AUTHN_WINNT_VALUE = 10;
  WFP_PAGE_COUNT = 256;
  WFP_MAX_ITEMS = 20000;
  MIB_MAX_BYTES = 2 * 1024 * 1024;
  NETWORK_MAX_RETRIES = 4;
  REG_MAX_VALUE_BYTES = 65536;
  ERROR_INSUFFICIENT_BUFFER_VALUE = 122;
  ERROR_MORE_DATA_VALUE = 234;
  ERROR_NO_DATA_VALUE = 232;
  ERROR_FILE_NOT_FOUND_VALUE = 2;
  REG_DWORD_VALUE = 4;
  REG_SZ_VALUE = 1;
  REG_EXPAND_SZ_VALUE = 2;
  KEY_QUERY_VALUE_RIGHT = 1;

type
  TGuidPtr = ^TGUID;
  TFWPMEngineOpen0 = function(ServerName: PWideChar; AuthService: Cardinal;
    AuthIdentity: Pointer; Session: Pointer; var Engine: THandle): Cardinal; stdcall;
  TFWPMEngineClose0 = function(Engine: THandle): Cardinal; stdcall;
  TFWPMCreateEnum = function(Engine: THandle; Template: Pointer;
    var EnumHandle: THandle): Cardinal; stdcall;
  TFWPMEnum = function(Engine, EnumHandle: THandle; Requested: Cardinal;
    var Entries: Pointer; var Returned: Cardinal): Cardinal; stdcall;
  TFWPMDestroyEnum = function(Engine, EnumHandle: THandle): Cardinal; stdcall;
  TFWPMFreeMemory = procedure(var P: Pointer); stdcall;
  TGetIPv4Routes = function(Table: Pointer; var Size: Cardinal;
    Ordered: BOOL): Cardinal; stdcall;
  TRegOpenKeyExW = function(Key: THandle; SubKey: PWideChar;
    Options, DesiredAccess: Cardinal; var KeyOut: THandle): LongInt; stdcall;
  TRegQueryValueExW = function(Key: THandle; ValueName: PWideChar;
    Reserved: Pointer; ValueType: PCardinal; Buffer: Pointer;
    BufferSize: PCardinal): LongInt; stdcall;
  TRegCloseKey = function(Key: THandle): LongInt; stdcall;
  TNetworkAPI = record
    EngineOpen: TFWPMEngineOpen0;
    EngineClose: TFWPMEngineClose0;
    FilterCreate, CalloutCreate, ProviderCreate: TFWPMCreateEnum;
    FilterEnum, CalloutEnum, ProviderEnum: TFWPMEnum;
    FilterDestroy, CalloutDestroy, ProviderDestroy: TFWPMDestroyEnum;
    WfpFree: TFWPMFreeMemory;
    IPv4Routes: TGetIPv4Routes;
    RegOpen: TRegOpenKeyExW;
    RegQuery: TRegQueryValueExW;
    RegClose: TRegCloseKey;
  end;

var
  NetworkLock: TCriticalSection;
  APIs: TNetworkAPI;
  WfpModule, IpModule, RegModule: HMODULE;

function HasWFP(const A: TNetworkAPI): Boolean;
begin
  Result := Assigned(A.EngineOpen) and Assigned(A.EngineClose) and
    Assigned(A.FilterCreate) and Assigned(A.FilterEnum) and Assigned(A.FilterDestroy) and
    Assigned(A.CalloutCreate) and Assigned(A.CalloutEnum) and Assigned(A.CalloutDestroy) and
    Assigned(A.ProviderCreate) and Assigned(A.ProviderEnum) and Assigned(A.ProviderDestroy) and
    Assigned(A.WfpFree);
end;

function HasRegistry(const A: TNetworkAPI): Boolean;
begin
  Result := Assigned(A.RegOpen) and Assigned(A.RegQuery) and Assigned(A.RegClose);
end;

procedure LoadNetworkModule(const Name: string; var M: HMODULE);
begin
  if M <> 0 then Exit;
  // Own one loader reference, including when another component loaded it first.
  // GetModuleHandle alone would only borrow a potentially unloadable handle.
  M := WinLoadLibrary(Name);
  // Process-lifetime reference: never unload while a call may be active.
end;

procedure NetworkAPI(out A: TNetworkAPI);
var
  Candidate: TNetworkAPI;

  procedure ResolveWFPFamily;
  begin
    if not HasWFP(Candidate) then
    begin
      LoadNetworkModule('fwpuclnt.dll', WfpModule);
      if WfpModule <> 0 then
      begin
        Candidate.EngineOpen := TFWPMEngineOpen0(WinExport(WfpModule, 'FwpmEngineOpen0'));
        Candidate.EngineClose := TFWPMEngineClose0(WinExport(WfpModule, 'FwpmEngineClose0'));
        Candidate.FilterCreate := TFWPMCreateEnum(WinExport(WfpModule, 'FwpmFilterCreateEnumHandle0'));
        Candidate.FilterEnum := TFWPMEnum(WinExport(WfpModule, 'FwpmFilterEnum0'));
        Candidate.FilterDestroy := TFWPMDestroyEnum(WinExport(WfpModule, 'FwpmFilterDestroyEnumHandle0'));
        Candidate.CalloutCreate := TFWPMCreateEnum(WinExport(WfpModule, 'FwpmCalloutCreateEnumHandle0'));
        Candidate.CalloutEnum := TFWPMEnum(WinExport(WfpModule, 'FwpmCalloutEnum0'));
        Candidate.CalloutDestroy := TFWPMDestroyEnum(WinExport(WfpModule, 'FwpmCalloutDestroyEnumHandle0'));
        Candidate.ProviderCreate := TFWPMCreateEnum(WinExport(WfpModule, 'FwpmProviderCreateEnumHandle0'));
        Candidate.ProviderEnum := TFWPMEnum(WinExport(WfpModule, 'FwpmProviderEnum0'));
        Candidate.ProviderDestroy := TFWPMDestroyEnum(WinExport(WfpModule, 'FwpmProviderDestroyEnumHandle0'));
        Candidate.WfpFree := TFWPMFreeMemory(WinExport(WfpModule, 'FwpmFreeMemory0'));
      end;
    end;
  end;

  procedure ResolveRouteFamily;
  begin
    if not Assigned(Candidate.IPv4Routes) then
    begin
      LoadNetworkModule('iphlpapi.dll', IpModule);
      Candidate.IPv4Routes := TGetIPv4Routes(WinExport(IpModule, 'GetIpForwardTable'));
    end;
  end;

  procedure ResolveProxyFamily;
  begin
    if not HasRegistry(Candidate) then
    begin
      LoadNetworkModule('advapi32.dll', RegModule);
      Candidate.RegOpen := TRegOpenKeyExW(WinExport(RegModule, 'RegOpenKeyExW'));
      Candidate.RegQuery := TRegQueryValueExW(WinExport(RegModule, 'RegQueryValueExW'));
      Candidate.RegClose := TRegCloseKey(WinExport(RegModule, 'RegCloseKey'));
    end;
  end;

begin
  NetworkLock.Acquire;
  try
    Candidate := APIs;
    ResolveWFPFamily;
    ResolveRouteFamily;
    ResolveProxyFamily;
    APIs := Candidate;
    A := Candidate; // Each operation uses its own immutable pointer snapshot.
  finally
    NetworkLock.Release;
  end;
end;

function ReadWFPKeys(const A: TNetworkAPI; Engine: THandle;
  MakeEnum: TFWPMCreateEnum; NextPage: TFWPMEnum;
  FreeEnum: TFWPMDestroyEnum; Keys: TStringList): Boolean;
var
  EnumHandle: THandle;
  Entries, Item: Pointer;
  Returned, I, Total: Cardinal;
  P: ^Pointer;
begin
  Result := False;
  Keys.Clear;
  EnumHandle := 0;
  try
    if MakeEnum(Engine, nil, EnumHandle) <> 0 then Exit;
    if EnumHandle = 0 then Exit;
    Total := 0;
    repeat
      Entries := nil;
      Returned := 0;
      try
        if NextPage(Engine, EnumHandle, WFP_PAGE_COUNT, Entries, Returned) <> 0 then Exit;
        if Returned > WFP_PAGE_COUNT then Exit;
        if Returned > WFP_MAX_ITEMS - Total then Exit;
        if (Returned <> 0) and (Entries = nil) then Exit;
        if Returned <> 0 then
          for I := 0 to Returned - 1 do
          begin
            P := Pointer(NativeUInt(Entries) + NativeUInt(I) * SizeOf(Pointer));
            Item := P^;
            if Item = nil then Exit;
            Keys.Add(GUIDToString(TGuidPtr(Item)^));
          end;
        Inc(Total, Returned);
      finally
        if Entries <> nil then A.WfpFree(Entries);
      end;
    until Returned < WFP_PAGE_COUNT;
    Result := True;
  finally
    if EnumHandle <> 0 then FreeEnum(Engine, EnumHandle);
    if not Result then Keys.Clear;
  end;
end;

function TakeWFPSnapshots(Filters, Callouts, Providers: TStringList): Boolean;
var
  A: TNetworkAPI;
  Engine: THandle;
  F, C, P: TStringList;
begin
  Result := False;
  if Filters <> nil then Filters.Clear;
  if Callouts <> nil then Callouts.Clear;
  if Providers <> nil then Providers.Clear;
  if (Filters = nil) or (Callouts = nil) or (Providers = nil) then Exit;
  if (Filters = Callouts) or (Filters = Providers) or (Callouts = Providers) then Exit;
  NetworkAPI(A);
  if not HasWFP(A) then Exit;
  Engine := 0;
  F := nil; C := nil; P := nil;
  try
    if A.EngineOpen(nil, RPC_C_AUTHN_WINNT_VALUE, nil, nil, Engine) <> 0 then Exit;
    if Engine = 0 then Exit;
    F := TStringList.Create;
    C := TStringList.Create;
    P := TStringList.Create;
    if not ReadWFPKeys(A, Engine, A.FilterCreate, A.FilterEnum, A.FilterDestroy, F) then Exit;
    if not ReadWFPKeys(A, Engine, A.CalloutCreate, A.CalloutEnum, A.CalloutDestroy, C) then Exit;
    if not ReadWFPKeys(A, Engine, A.ProviderCreate, A.ProviderEnum, A.ProviderDestroy, P) then Exit;
    Filters.Assign(F); Callouts.Assign(C); Providers.Assign(P);
    Result := True;
  finally
    P.Free; C.Free; F.Free;
    if Engine <> 0 then A.EngineClose(Engine);
    if not Result then
    begin
      Filters.Clear; Callouts.Clear; Providers.Clear;
    end;
  end;
end;

function TakeDefaultRouteSnapshot(Routes: TStringList): Boolean;
var
  A: TNetworkAPI;
  Data: TBytes;
  Needed, Status, Capacity: Cardinal;
  Attempt: Integer;
begin
  Result := False;
  if Routes = nil then Exit;
  Routes.Clear;
  NetworkAPI(A);
  if not Assigned(A.IPv4Routes) then Exit;
  Needed := 0;
  Status := A.IPv4Routes(nil, Needed, False);
  if Status = ERROR_NO_DATA_VALUE then Exit(True);
  if (Status <> ERROR_INSUFFICIENT_BUFFER_VALUE) and
     (Status <> ERROR_MORE_DATA_VALUE) then Exit;
  for Attempt := 1 to NETWORK_MAX_RETRIES do
  begin
    if (Needed < SizeOf(Cardinal)) or (Needed > MIB_MAX_BYTES) then Exit;
    Capacity := Needed;
    SetLength(Data, Integer(Capacity));
    FillChar(Data[0], Length(Data), 0);
    Status := A.IPv4Routes(@Data[0], Needed, False);
    if Status = ERROR_NO_DATA_VALUE then Exit(True);
    if Status = 0 then Exit(ParseDefaultRoutes(Data, Needed, Routes));
    if (Status <> ERROR_INSUFFICIENT_BUFFER_VALUE) and
       (Status <> ERROR_MORE_DATA_VALUE) then Exit;
    // Repeated non-growing requirements are not retried indefinitely.
    if Needed <= Capacity then Exit;
  end;
end;

function ReadRegDWORD(const A: TNetworkAPI; Key: THandle; const Name: string;
  out Value: Cardinal): Boolean;
var
  N, Kind, Candidate: Cardinal;
begin
  Result := False;
  Value := 0;
  Candidate := 0;
  N := SizeOf(Candidate);
  Kind := 0;
  if A.RegQuery(Key, PWideChar(Name), nil, @Kind, @Candidate, @N) <> 0 then Exit;
  if (Kind <> REG_DWORD_VALUE) or (N <> SizeOf(Candidate)) then Exit;
  Value := Candidate;
  Result := True;
end;

function ReadRegString(const A: TNetworkAPI; Key: THandle; const Name: string;
  out Value: string): Boolean;
var
  Data: TBytes;
  N, Kind, Capacity: Cardinal;
  Status: LongInt;
  Attempt: Integer;
begin
  Result := False;
  Value := '';
  N := 0; Kind := 0;
  Status := A.RegQuery(Key, PWideChar(Name), nil, @Kind, nil, @N);
  if Status = ERROR_FILE_NOT_FOUND_VALUE then Exit(True);
  if (Status <> 0) and (Status <> ERROR_MORE_DATA_VALUE) then Exit;
  for Attempt := 1 to NETWORK_MAX_RETRIES do
  begin
    if (Kind <> REG_SZ_VALUE) and (Kind <> REG_EXPAND_SZ_VALUE) then Exit;
    if (N > REG_MAX_VALUE_BYTES) or ((N and 1) <> 0) then Exit;
    Capacity := N;
    if Capacity = 0 then Capacity := SizeOf(WideChar);
    SetLength(Data, Integer(Capacity));
    FillChar(Data[0], Length(Data), 0);
    N := Capacity;
    Status := A.RegQuery(Key, PWideChar(Name), nil, @Kind, @Data[0], @N);
    if Status = ERROR_FILE_NOT_FOUND_VALUE then Exit(True);
    if Status = 0 then
    begin
      if (Kind <> REG_SZ_VALUE) and (Kind <> REG_EXPAND_SZ_VALUE) then Exit;
      Exit(DecodeRegString(Data, N, Value));
    end;
    if (Status <> ERROR_MORE_DATA_VALUE) or (N <= Capacity) then Exit;
  end;
end;

function TakeProxySnapshot(ProxyState: TStringList): Boolean;
const
  PATH = 'Software\Microsoft\Windows\CurrentVersion\Internet Settings';
var
  A: TNetworkAPI;
  Key: THandle;
  Enabled: Cardinal;
  ServerName, AutoURL: string;
begin
  Result := False;
  if ProxyState = nil then Exit;
  ProxyState.Clear;
  NetworkAPI(A);
  if not HasRegistry(A) then Exit;
  Key := 0;
  try
    if A.RegOpen(HKEY_CURRENT_USER, PWideChar(string(PATH)), 0,
      KEY_QUERY_VALUE_RIGHT, Key) <> 0 then Exit;
    if Key = 0 then Exit;
    if not ReadRegDWORD(A, Key, 'ProxyEnable', Enabled) then Exit;
    if not ReadRegString(A, Key, 'AutoConfigURL', AutoURL) then Exit;
    if Enabled <> 0 then
    begin
      if not ReadRegString(A, Key, 'ProxyServer', ServerName) then Exit;
    end
    else ServerName := '';
    ProxyState.Add(IntToStr(Enabled) + #1 + ServerName + #1 + AutoURL);
    Result := True;
  finally
    if Key <> 0 then A.RegClose(Key);
    if not Result then ProxyState.Clear;
  end;
end;

{$IFDEF NHW_NATIVE5_TESTS}
  {$I Cozy.NHW.Native5.Network.inc}
{$ENDIF}
initialization
  NetworkLock := TCriticalSection.Create;
finalization
  NetworkLock.Free;
end.
