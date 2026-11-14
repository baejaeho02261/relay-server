unit Cozy.NHW.PathNative;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes;

// Bounded, read-only snapshots; never infer packet interception from state.
// All process-level calls use resolved Win32 pointers; all returned pointers
// are inspected within their owning response buffers only.
function TakeAdapterSnapshots(DNSServers, Interfaces: TStringList): Boolean;
function TakeNRPTSnapshot(Policies: TStringList): Boolean;
function TakeWinsockCatalogSnapshot(Providers: TStringList): Boolean;

{$IFDEF NHW_NATIVE10N_TESTS}
function TestPathNative10N(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  Cozy.NHW.WinPointers, System.SyncObjs, Cozy.NHW.PathSnapshot.Decoders;

const
  AF_UNSPEC_VALUE = 0;
  GAA_FLAGS_VALUE = $0001 or $0002 or $0004 or $0020 or $0100;
  ERROR_BUFFER_OVERFLOW_VALUE = 111;
  ERROR_MORE_DATA_VALUE = 234;
  ERROR_FILE_NOT_FOUND_VALUE = 2;
  ERROR_NO_MORE_ITEMS_VALUE = 259;
  WSAENOBUFS_VALUE = 10055;
  REG_ACCESS_READ = $00020019;
  MAX_ADAPTER_BYTES = 2 * 1024 * 1024;
  MAX_CATALOG_BYTES = 1024 * 1024;
  MAX_REG_RULES = 256;
  MAX_REG_VALUES = 64;
  MAX_POLICY_CHARS = 1024 * 1024;

  NRPT_SERVICE_PATH = 'SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig';
  NRPT_POLICY_PATH = 'SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig';

type
  TGetAdaptersAddresses = function(Family, Flags: Cardinal; Reserved,
    AdapterAddresses: Pointer; var Size: Cardinal): Cardinal; stdcall;

  TRegOpen = function(Key: HKEY; SubKey: PWideChar; Options,
    Access: Cardinal; var Opened: HKEY): LongInt; stdcall;
  TRegEnumKey = function(Key: HKEY; Index: Cardinal; Name: PWideChar;
    var NameChars: Cardinal; Reserved: Pointer; ClassName: PWideChar;
    ClassLength: PCardinal; LastWritten: PFileTime): LongInt; stdcall;
  TRegEnumValue = function(Key: HKEY; Index: Cardinal; Name: PWideChar;
    var NameChars: Cardinal; Reserved: Pointer; ValueType: PCardinal;
    ValueData: Pointer; var DataLength: Cardinal): LongInt; stdcall;
  TRegClose = function(Key: HKEY): LongInt; stdcall;

  TWSAStartup = function(Version: Word; Data: Pointer): LongInt; stdcall;
  TWSACleanup = function: LongInt; stdcall;
  TWSCEnumProtocols = function(Protocols, Buffer: Pointer;
    var BufferLength: Cardinal; var ErrorCode: LongInt): LongInt; stdcall;

var
  AdaptersAPI: TGetAdaptersAddresses = nil;
  RegOpenAPI: TRegOpen = nil;
  RegEnumKeyAPI: TRegEnumKey = nil;
  RegEnumValueAPI: TRegEnumValue = nil;
  RegCloseAPI: TRegClose = nil;
  WSStart: TWSAStartup = nil;
  WSClean: TWSACleanup = nil;
  WSCEnum: TWSCEnumProtocols = nil;
  Resolved: Boolean = False;
  ResolveLock: TCriticalSection;

procedure ResolveAdapterAPI;
var
  M: HMODULE;
begin
  M := WinModule('iphlpapi.dll');
  if M = 0 then M := WinLoadLibrary('iphlpapi.dll');
  if M <> 0 then
    AdaptersAPI := TGetAdaptersAddresses(WinExport(M, 'GetAdaptersAddresses'));
end;

procedure ResolvePolicyAPIs;
var
  M: HMODULE;
begin
  M := WinModule('advapi32.dll');
  if M = 0 then M := WinLoadLibrary('advapi32.dll');
  if M <> 0 then
  begin
    RegOpenAPI := TRegOpen(WinExport(M, 'RegOpenKeyExW'));
    RegEnumKeyAPI := TRegEnumKey(WinExport(M, 'RegEnumKeyExW'));
    RegEnumValueAPI := TRegEnumValue(WinExport(M, 'RegEnumValueW'));
    RegCloseAPI := TRegClose(WinExport(M, 'RegCloseKey'));
  end;
end;

procedure ResolveCatalogAPIs;
var
  M: HMODULE;
begin
  M := WinModule('ws2_32.dll');
  if M = 0 then M := WinLoadLibrary('ws2_32.dll');
  if M <> 0 then
  begin
    WSStart := TWSAStartup(WinExport(M, 'WSAStartup'));
    WSClean := TWSACleanup(WinExport(M, 'WSACleanup'));
    WSCEnum := TWSCEnumProtocols(WinExport(M, 'WSCEnumProtocols'));
  end;
end;

procedure ResolvePathAPIs;
begin
  // Every caller crosses the same acquire/release boundary. No early flag
  // may expose half-published API pointers to another sampling thread.
  ResolveLock.Acquire;
  try
    if Resolved then Exit;
    ResolveAdapterAPI;
    ResolvePolicyAPIs;
    ResolveCatalogAPIs;
    Resolved := True;
  finally
    ResolveLock.Release;
  end;
end;

function CollectAdapterSnapshots(DNSServers, Interfaces: TStringList): Boolean;
var
  Data: TBytes;
  Size, Status: Cardinal;
  Attempt: Integer;
begin
  Result := False;
  DNSServers.Clear;
  Interfaces.Clear;
  ResolvePathAPIs;
  if not Assigned(AdaptersAPI) then Exit;
  if (SizeOf(TAdapterPrefix) <> 112) or (SizeOf(TDnsNode) <> 32) then Exit;
  Size := 32 * 1024;
  for Attempt := 1 to 4 do
  begin
    if (Size < 1024) or (Size > MAX_ADAPTER_BYTES) then Exit;
    SetLength(Data, Integer(Size));
    Status := AdaptersAPI(AF_UNSPEC_VALUE, GAA_FLAGS_VALUE, nil,
      @Data[0], Size);
    if Status = 0 then Break;
    if Status <> ERROR_BUFFER_OVERFLOW_VALUE then Exit;
    if Size > MAX_ADAPTER_BYTES then Exit;
  end;
  if Status <> 0 then Exit;
  if (Length(Data) < SizeOf(TAdapterPrefix)) or (Size > Cardinal(Length(Data))) then Exit;

  Result := ParseAdapterSnapshots(Data, DNSServers, Interfaces);
end;

function AddPolicyLine(Output: TStringList; const Line: string;
  var Budget: Integer): Boolean;
begin
  Result := Length(Line) <= MAX_POLICY_CHARS - Budget;
  if Result then
  begin
    Inc(Budget, Length(Line));
    Output.Add(Line);
  end;
end;

function RegistryValues(Key: HKEY; const Prefix: string;
  Output: TStringList; var Budget: Integer): Boolean;
var
  I: Cardinal;
  NameChars, Bytes, Typ: Cardinal;
  NameBuf: array[0..255] of WideChar;
  DataBuf: array[0..4095] of Byte;
  Status: LongInt;
  ValueName: string;
begin
  Result := False;
  for I := 0 to MAX_REG_VALUES do
  begin
    if I = MAX_REG_VALUES then Exit;
    NameChars := Length(NameBuf);
    Bytes := SizeOf(DataBuf);
    Typ := 0;
    Status := RegEnumValueAPI(Key, I, @NameBuf[0], NameChars, nil,
      @Typ, @DataBuf[0], Bytes);
    if Status = ERROR_NO_MORE_ITEMS_VALUE then Exit(True);
    if (Status <> 0) or (NameChars >= Cardinal(Length(NameBuf))) or
       (Bytes > SizeOf(DataBuf)) then Exit;
    SetString(ValueName, PWideChar(@NameBuf[0]), Integer(NameChars));
    // No logging: data is compared in-memory only, with bounded value sizes.
    if not AddPolicyLine(Output, Prefix + '/' + ValueName + ':' +
      IntToStr(Typ) + ':' + IntToStr(Bytes) + ':' +
      HexAt(@DataBuf[0], Integer(Bytes)), Budget) then Exit;
  end;
end;

function RegistrySubkeys(Key: HKEY; const Prefix: string;
  Output: TStringList; var Budget: Integer): Boolean;
var
  I: Cardinal;
  NameChars: Cardinal;
  NameBuf: array[0..255] of WideChar;
  Status: LongInt;
  Name: string;
  Sub: HKEY;
begin
  Result := False;
  for I := 0 to MAX_REG_RULES do
  begin
    if I = MAX_REG_RULES then Exit;
    NameChars := Length(NameBuf);
    Status := RegEnumKeyAPI(Key, I, @NameBuf[0], NameChars,
      nil, nil, nil, nil);
    if Status = ERROR_NO_MORE_ITEMS_VALUE then Exit(True);
    if (Status <> 0) or (NameChars >= Cardinal(Length(NameBuf))) then Exit;
    SetString(Name, PWideChar(@NameBuf[0]), Integer(NameChars));
    if not AddPolicyLine(Output, Prefix + '/' + Name + ':PRESENT',
      Budget) then Exit;
    Sub := 0;
    if RegOpenAPI(Key, PWideChar(Name), 0, REG_ACCESS_READ, Sub) <> 0 then Exit;
    try
      if not RegistryValues(Sub, Prefix + '/' + Name, Output, Budget) then Exit;
    finally
      RegCloseAPI(Sub);
    end;
  end;
end;

function RegistryRoot(Hive: HKEY; const KeyPath, LabelName: string;
  Output: TStringList; var Budget: Integer): Boolean;
var
  Opened: HKEY;
  Code: LongInt;
begin
  Result := False;
  Opened := 0;
  Code := RegOpenAPI(Hive, PWideChar(KeyPath), 0, REG_ACCESS_READ, Opened);
  if Code = ERROR_FILE_NOT_FOUND_VALUE then
  begin
    Exit(AddPolicyLine(Output, LabelName + ':ABSENT', Budget));
  end;
  if Code <> 0 then Exit;
  try
    if not AddPolicyLine(Output, LabelName + ':PRESENT', Budget) then Exit;
    // Incomplete enumeration and oversized policies cannot form a change signal.
    if not RegistryValues(Opened, LabelName, Output, Budget) then Exit;
    Result := RegistrySubkeys(Opened, LabelName, Output, Budget);
  finally
    RegCloseAPI(Opened);
  end;
end;

function CollectNRPTSnapshot(Policies: TStringList): Boolean;
var Budget: Integer;
begin
  Budget := 0;
  Policies.Clear;
  ResolvePathAPIs;
  Result := False;
  if not Assigned(RegOpenAPI) or not Assigned(RegEnumKeyAPI) or
     not Assigned(RegEnumValueAPI) or not Assigned(RegCloseAPI) then Exit;
  Result := RegistryRoot(HKEY_LOCAL_MACHINE, NRPT_SERVICE_PATH,
      'NRPT_SYSTEM', Policies, Budget) and
    RegistryRoot(HKEY_LOCAL_MACHINE, NRPT_POLICY_PATH,
      'NRPT_MACHINE_POLICY', Policies, Budget) and
    RegistryRoot(HKEY_CURRENT_USER, NRPT_POLICY_PATH,
      'NRPT_USER_POLICY', Policies, Budget);
end;

function CollectWinsockCatalogSnapshot(Providers: TStringList): Boolean;
var
  WSAData: array[0..1023] of Byte;
  Data: TBytes;
  Wanted: Cardinal;
  Status, ErrorCode: LongInt;
  Attempt: Integer;
  Allocated: Cardinal;
begin
  Result := False;
  Providers.Clear;
  ResolvePathAPIs;
  if not Assigned(WSStart) or not Assigned(WSClean) or not Assigned(WSCEnum) then Exit;
  if SizeOf(TProtocolInfo) <> 628 then Exit;
  FillChar(WSAData, SizeOf(WSAData), 0);
  if WSStart($0202, @WSAData[0]) <> 0 then Exit;
  try
    Wanted := 32768;
    for Attempt := 1 to 4 do
    begin
      if (Wanted > MAX_CATALOG_BYTES) or (Wanted < SizeOf(TProtocolInfo)) then Exit;
      Allocated := Wanted;
      SetLength(Data, Integer(Allocated));
      ErrorCode := 0;
      Status := WSCEnum(nil, @Data[0], Wanted, ErrorCode);
      if Status >= 0 then Break;
      if (ErrorCode <> WSAENOBUFS_VALUE) or
         (Wanted > MAX_CATALOG_BYTES) then Exit;
      if Wanted <= Allocated then
      begin
        if Allocated > MAX_CATALOG_BYTES div 2 then Exit;
        Wanted := Allocated * 2;
      end;
    end;
    Result := ParseWinsockCatalog(Data, Status, Providers);
  finally
    WSClean();
  end;
end;

function TakeAdapterSnapshots(DNSServers, Interfaces: TStringList): Boolean;
begin
  Result := False;
  if DNSServers <> nil then DNSServers.Clear;
  if Interfaces <> nil then Interfaces.Clear;
  if (DNSServers = nil) or (Interfaces = nil) or
     (DNSServers = Interfaces) then Exit;
  try
    Result := CollectAdapterSnapshots(DNSServers, Interfaces);
  finally
    if not Result then
    begin
      DNSServers.Clear;
      Interfaces.Clear;
    end;
  end;
end;

function TakeNRPTSnapshot(Policies: TStringList): Boolean;
begin
  Result := False;
  if Policies = nil then Exit;
  Policies.Clear;
  try
    Result := CollectNRPTSnapshot(Policies);
  finally
    if not Result then Policies.Clear;
  end;
end;

function TakeWinsockCatalogSnapshot(Providers: TStringList): Boolean;
begin
  Result := False;
  if Providers = nil then Exit;
  Providers.Clear;
  try
    Result := CollectWinsockCatalogSnapshot(Providers);
  finally
    if not Result then Providers.Clear;
  end;
end;

{$IFDEF NHW_NATIVE10N_TESTS}
{$I Cozy.NHW.Native10N.PathNative.inc}
{$ENDIF}

initialization
  ResolveLock := TCriticalSection.Create;
finalization
  ResolveLock.Free;
end.
