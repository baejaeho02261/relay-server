unit Cozy.NHW.ModuleOriginVerification;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows, System.SysUtils, System.Generics.Collections, Cozy.NHW.Logging;

type
  TModuleOriginState = record
    ModulePath: string;
    MappedPath: string;
    MappedNameDifferent: Boolean;
    TrustChecked: Boolean;
    SignatureTrusted: Boolean;
    SeenAt: UInt64;
    LastSeen: UInt64;
    SuspectSamples: Byte;
    Reported: Boolean;
    PendingCandidate: Boolean;
  end;

  // v46: checks full path, mapped backing filename, and Authenticode status.
  // An unsigned file or a new DLL alone is NEVER a detection.
  TModuleOriginMonitor = class
  private
    FInspectionAttempted: Boolean;
    FModules: TDictionary<NativeUInt, TModuleOriginState>;
    FPrimed: Boolean;
    FLastScan: UInt64;
    FLastReport: UInt64;
    FAccessTick: UInt64;
    FThreadTick: UInt64;
    FContinuityBroken: Boolean;
    procedure StageModule(Module: HMODULE; Baseline: Boolean; Tick: UInt64;
      Pending: TDictionary<NativeUInt, TModuleOriginState>;
      var ReportNow: Boolean);
    function RecheckStagedInventory(
      Pending: TDictionary<NativeUInt, TModuleOriginState>): Boolean;
    procedure CommitStagedInventory(
      var Pending: TDictionary<NativeUInt, TModuleOriginState>;
      ReportNow: Boolean; Tick: UInt64; var Detected: TDetectionKinds);
  public
    property InspectionAttempted: Boolean read FInspectionAttempted;
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Examine(Baseline, HighExternalAccess: Boolean;
      Tick: UInt64; var Detected: TDetectionKinds);
  end;

function ModuleOriginCandidate(const ModulePath, MappedPath: string;
  KnownSignature, TrustedSignature, NewlyLoaded: Boolean): Boolean;

{$IFDEF NHW_NATIVE5D_TESTS}
function TestModuleOriginHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses System.SyncObjs, Cozy.NHW.WinPointers, Cozy.NHW.SignalCorrelation;

const
  MODULE_SCAN_PERIOD_MS = 6000;
  MODULE_WINDOW_MS = 12000;
  MODULE_REPORT_COOLDOWN_MS = 30000;
  MODULE_MAX_COUNT = 256;
  WTD_UI_NONE = 2;
  WTD_REVOKE_NONE = 0;
  WTD_CHOICE_FILE = 1;
  WTD_CACHE_ONLY_URL_RETRIEVAL = $1000;
  ACTION_VERIFY_V2: TGUID = '{00AAC56B-CD44-11D0-8CC2-00C04FC295EE}';

type
  TEnumProcessModulesFn = function(Process: THandle; Modules: Pointer;
    Bytes: Cardinal; out Needed: Cardinal): BOOL; stdcall;
  TGetModuleFileNameWFn = function(Module: HMODULE; Buffer: PWideChar;
    Chars: Cardinal): Cardinal; stdcall;
  TGetMappedFileNameWFn = function(Process: THandle; Address: Pointer;
    Buffer: PWideChar; Chars: Cardinal): Cardinal; stdcall;
  TWinTrustFileInfo = record
    cbStruct: Cardinal;
    FilePath: PWideChar;
    FileHandle: THandle;
    KnownSubject: Pointer;
  end;
  TWinTrustData = record
    cbStruct: Cardinal;
    PolicyCallback: Pointer;
    SIPClient: Pointer;
    UIChoice: Cardinal;
    RevocationChecks: Cardinal;
    Choice: Cardinal;
    FileInfo: Pointer;
    StateAction: Cardinal;
    StateHandle: THandle;
    URLReference: PWideChar;
    ProviderFlags: Cardinal;
    UIContext: Cardinal;
    SignatureSettings: Pointer;
  end;
  TWinVerifyTrustFn = function(Owner: HWND; Action: Pointer;
    Data: Pointer): LongInt; stdcall;

var
  FEnum: TEnumProcessModulesFn = nil;
  FModuleFileName: TGetModuleFileNameWFn = nil;
  FMappedName: TGetMappedFileNameWFn = nil;
  FVerify: TWinVerifyTrustFn = nil;
  FResolved: Boolean = False;
  ModuleResolveLock: TCriticalSection;
  PsapiModule, WintrustModule: HMODULE;

function ResolveModuleNative: Boolean;
var
  K: HMODULE;
  E: TEnumProcessModulesFn;
  N: TGetModuleFileNameWFn;
  M: TGetMappedFileNameWFn;
  V: TWinVerifyTrustFn;
begin
  Result := False;
  ModuleResolveLock.Acquire;
  try
    if FResolved then Exit(True);
    K := WinModule('kernel32.dll');
    if K = 0 then Exit;
    E := TEnumProcessModulesFn(WinExport(K, 'K32EnumProcessModules'));
    M := TGetMappedFileNameWFn(WinExport(K, 'K32GetMappedFileNameW'));
    if not Assigned(E) or not Assigned(M) then
    begin
      if PsapiModule = 0 then PsapiModule := WinLoadLibrary('psapi.dll');
      if not Assigned(E) then
        E := TEnumProcessModulesFn(WinExport(PsapiModule, 'EnumProcessModules'));
      if not Assigned(M) then
        M := TGetMappedFileNameWFn(WinExport(PsapiModule, 'GetMappedFileNameW'));
    end;
    N := TGetModuleFileNameWFn(WinExport(K, 'GetModuleFileNameW'));
    if not Assigned(E) or not Assigned(N) or not Assigned(M) then Exit;
    if WintrustModule = 0 then WintrustModule := WinLoadLibrary('wintrust.dll');
    if (SizeOf(TWinTrustFileInfo) = 32) and (SizeOf(TWinTrustData) = 88) then
      V := TWinVerifyTrustFn(WinExport(WintrustModule, 'WinVerifyTrust'))
    else
      V := nil;
    // Publish a complete inventory API set once. Signature support is
    // optional; missing verification remains UNKNOWN, never untrusted.
    FEnum := E;
    FModuleFileName := N;
    FMappedName := M;
    FVerify := V;
    FResolved := True;
    Result := True;
  finally
    ModuleResolveLock.Release;
  end;
end;

function ReadModuleName(Module: HMODULE): string;
var
  Buf: TArray<WideChar>;
  N, Capacity: Cardinal;
begin
  Result := '';
  if not Assigned(FModuleFileName) then Exit;
  Capacity := 1024;
  while Capacity <= 32768 do
  begin
    SetLength(Buf, Integer(Capacity));
    FillChar(Buf[0], Capacity * SizeOf(WideChar), 0);
    N := FModuleFileName(Module, @Buf[0], Capacity);
    if N = 0 then Exit;
    if N < Capacity - 1 then
    begin
      SetString(Result, PWideChar(@Buf[0]), Integer(N));
      if Pos(#0, Result) <> 0 then Result := '';
      Exit;
    end;
    Capacity := Capacity * 2;
  end;
end;

function ReadMappedName(Module: HMODULE): string;
var
  Buf: TArray<WideChar>;
  N, Capacity: Cardinal;
begin
  Result := '';
  if not Assigned(FMappedName) then Exit;
  Capacity := 1024;
  while Capacity <= 32768 do
  begin
    SetLength(Buf, Integer(Capacity));
    FillChar(Buf[0], Capacity * SizeOf(WideChar), 0);
    N := FMappedName(WinCurrentProcess, Pointer(Module), @Buf[0], Capacity);
    if N = 0 then Exit;
    if N < Capacity - 1 then
    begin
      SetString(Result, PWideChar(@Buf[0]), Integer(N));
      if Pos(#0, Result) <> 0 then Result := '';
      Exit;
    end;
    Capacity := Capacity * 2;
  end;
end;

function ReadModuleInventory(out Modules: TArray<HMODULE>): Boolean;
var
  Needed: Cardinal;
  I, J, Count: Integer;
begin
  Result := False;
  SetLength(Modules, 0);
  if not Assigned(FEnum) then Exit;
  SetLength(Modules, MODULE_MAX_COUNT);
  try
    FillChar(Modules[0], Length(Modules) * SizeOf(HMODULE), 0);
    Needed := 0;
    if not FEnum(WinCurrentProcess, @Modules[0],
      Cardinal(Length(Modules) * SizeOf(HMODULE)), Needed) then Exit;
    if (Needed = 0) or (Needed > Cardinal(MODULE_MAX_COUNT * SizeOf(HMODULE))) or
       ((Needed mod Cardinal(SizeOf(HMODULE))) <> 0) then Exit;
    Count := Integer(Needed div Cardinal(SizeOf(HMODULE)));
    for I := 0 to Count - 1 do
    begin
      if NativeUInt(Modules[I]) < $10000 then Exit;
      for J := 0 to I - 1 do
        if Modules[J] = Modules[I] then Exit;
    end;
    SetLength(Modules, Count);
    Result := True;
  finally
    if not Result then SetLength(Modules, 0);
  end;
end;

function SignatureTrusted(const Path: string; out Checked: Boolean): Boolean;
var
  Info: TWinTrustFileInfo;
  Data: TWinTrustData;
  Action: TGUID;
begin
  Result := False;
  Checked := Assigned(FVerify) and (Path <> '');
  if not Checked then Exit;
  Info := Default(TWinTrustFileInfo);
  Info.cbStruct := SizeOf(Info);
  Info.FilePath := PWideChar(Path);
  Data := Default(TWinTrustData);
  Data.cbStruct := SizeOf(Data);
  Data.UIChoice := WTD_UI_NONE;
  Data.RevocationChecks := WTD_REVOKE_NONE;
  Data.Choice := WTD_CHOICE_FILE;
  Data.FileInfo := @Info;
  Data.ProviderFlags := WTD_CACHE_ONLY_URL_RETRIEVAL;
  Action := ACTION_VERIFY_V2;
  try
    Result := FVerify(0, @Action, @Data) = 0;
  except
    Checked := False;
  end;
end;

function OriginWritableLocation(const Path: string): Boolean;
var
  S: string;
begin
  S := UpperCase(Path);
  Result := (Pos('\TEMP\', S) > 0) or
    (Pos('\APPDATA\LOCAL\TEMP\', S) > 0) or
    (Pos('\DOWNLOADS\', S) > 0);
end;

function ModuleOriginCandidate(const ModulePath, MappedPath: string;
  KnownSignature, TrustedSignature, NewlyLoaded: Boolean): Boolean;
var
  A, B: string;
begin
  Result := False;
  if not KnownSignature or TrustedSignature or not NewlyLoaded then Exit;
  if (ModulePath = '') or (MappedPath = '') then Exit;
  A := ExtractFileName(ModulePath);
  B := ExtractFileName(MappedPath);
  if (A = '') or (B = '') then Exit;
  // Two independently obtained filenames disagree, or a new unsigned
  // module is loaded from a user-writable staging directory.
  Result := not SameText(A, B) or OriginWritableLocation(ModulePath);
end;

constructor TModuleOriginMonitor.Create;
begin
  inherited Create;
  FModules := TDictionary<NativeUInt, TModuleOriginState>.Create;
  Reset;
end;

destructor TModuleOriginMonitor.Destroy;
begin
  FModules.Free;
  inherited Destroy;
end;

procedure TModuleOriginMonitor.Reset;
begin
  FInspectionAttempted := False;
  FModules.Clear;
  FPrimed := False;
  FLastScan := 0;
  FLastReport := 0;
  FAccessTick := 0;
  FThreadTick := 0;
  FContinuityBroken := False;
end;

procedure TModuleOriginMonitor.StageModule(Module: HMODULE; Baseline: Boolean; Tick: UInt64;
  Pending: TDictionary<NativeUInt, TModuleOriginState>;
  var ReportNow: Boolean);
var
  Base: NativeUInt;
  Info: TModuleOriginState;
  Path, Backing: string;
  Known, ChangedIdentity, Candidate: Boolean;
begin
  Base := NativeUInt(Module);
  Known := FModules.TryGetValue(Base, Info);
  if not Known then
  begin
    Info := Default(TModuleOriginState);
    Info.SeenAt := Tick;
    Info.PendingCandidate := FPrimed and not Baseline;
  end;
  if FContinuityBroken then Info.SuspectSamples := 0;
  Info.LastSeen := Tick; // Presence is established even when a path fails.
  Path := ReadModuleName(Module);
  Backing := ReadMappedName(Module);
  if (Path = '') or (Backing = '') then
  begin
    Info.SuspectSamples := 0;
    if Baseline then Info.PendingCandidate := False;
    Pending.Add(Base, Info); // Preserve identity; not an unload.
    Exit;
  end;
  ChangedIdentity := Known and (Info.ModulePath <> '') and
    (not SameText(Path, Info.ModulePath) or
     not SameText(Backing, Info.MappedPath));
  if ChangedIdentity then
  begin
    Info := Default(TModuleOriginState);
    Info.SeenAt := Tick;
    Info.PendingCandidate := FPrimed and not Baseline;
  end;
  Info.ModulePath := Path;
  Info.MappedPath := Backing;
  Info.LastSeen := Tick;
  // A baseline placeholder remains a baseline when its names become
  // readable later. Failed signature queries are UNKNOWN and retried.
  if not Info.TrustChecked then
    Info.SignatureTrusted := SignatureTrusted(Path, Info.TrustChecked);
  if Baseline then Info.PendingCandidate := False;
  Candidate := FPrimed and not Baseline and
    ModuleOriginCandidate(Path, Backing, Info.TrustChecked,
      Info.SignatureTrusted, Info.PendingCandidate);
  if Candidate then
  begin
    if Info.SuspectSamples < 3 then Inc(Info.SuspectSamples);
  end
  else Info.SuspectSamples := 0;
  if Candidate and (Info.SuspectSamples >= 2) and not Info.Reported and
     not ReportNow and RecentSignal(FAccessTick, Tick, MODULE_WINDOW_MS) and
     RecentSignal(FThreadTick, Tick, MODULE_WINDOW_MS) and
     ((FLastReport = 0) or ((Tick >= FLastReport) and
      (Tick - FLastReport >= MODULE_REPORT_COOLDOWN_MS))) then
  begin
    Info.Reported := True;
    ReportNow := True;
  end;
  Pending.Add(Base, Info);
end;

function TModuleOriginMonitor.RecheckStagedInventory(
  Pending: TDictionary<NativeUInt, TModuleOriginState>): Boolean;
var
  Recheck: TArray<HMODULE>;
  I: Integer;
begin
  Result := False;
  // Do not remove an old record or publish a detection from a changing
  // inventory. A second complete enumeration must match the same bases.
  // This reduces races; it is not an atomic loader snapshot/ABA proof.
  if not ReadModuleInventory(Recheck) then
  begin
    FContinuityBroken := True;
    Exit;
  end;
  if Length(Recheck) <> Pending.Count then
  begin
    FContinuityBroken := True;
    Exit;
  end;
  for I := 0 to High(Recheck) do
    if not Pending.ContainsKey(NativeUInt(Recheck[I])) then
    begin
      FContinuityBroken := True;
      Exit;
    end;
  Result := True;
end;

procedure TModuleOriginMonitor.CommitStagedInventory(
  var Pending: TDictionary<NativeUInt, TModuleOriginState>;
  ReportNow: Boolean; Tick: UInt64; var Detected: TDetectionKinds);
var
  OldModules: TDictionary<NativeUInt, TModuleOriginState>;
begin
  OldModules := FModules;
  FModules := Pending;
  Pending := OldModules;
  FPrimed := True;
  FContinuityBroken := False;
  if ReportNow then
  begin
    Include(Detected, dkModuleOrigin);
    FLastReport := Tick;
  end;
end;

procedure TModuleOriginMonitor.Examine(Baseline,
  HighExternalAccess: Boolean; Tick: UInt64;
  var Detected: TDetectionKinds);
var
  Modules: TArray<HMODULE>;
  I: Integer;
  ReportNow: Boolean;
  Pending: TDictionary<NativeUInt, TModuleOriginState>;
begin
  FInspectionAttempted := False;
  if (FLastScan <> 0) and (Tick < FLastScan) then
  begin
    FContinuityBroken := True;
    FAccessTick := 0;
    FThreadTick := 0;
    FLastReport := 0;
  end;
  if HighExternalAccess then FAccessTick := Tick;
  if (Detected * [dkPrivateThread, dkRemoteThread, dkExecutionProvenance]) <> [] then
    FThreadTick := Tick;
  if (FLastScan <> 0) and (Tick >= FLastScan) and
     (Tick - FLastScan < MODULE_SCAN_PERIOD_MS) then Exit;
  FLastScan := Tick;
  Pending := nil;
  try
    try
      if not ResolveModuleNative then
      begin
        FContinuityBroken := True;
        Exit;
      end;
      FInspectionAttempted := True;
      if not ReadModuleInventory(Modules) then
      begin
        FContinuityBroken := True;
        Exit;
      end;
      Pending := TDictionary<NativeUInt, TModuleOriginState>.Create;
      ReportNow := False;
      for I := 0 to High(Modules) do
        StageModule(Modules[I], Baseline, Tick, Pending, ReportNow);
      if not RecheckStagedInventory(Pending) then Exit;
      CommitStagedInventory(Pending, ReportNow, Tick, Detected);
    except
      FContinuityBroken := True;
      raise;
    end;
  finally
    Pending.Free;
  end;
end;

{$IFDEF NHW_NATIVE5D_TESTS}
{$I Cozy.NHW.Native5D.ModuleOrigin.inc}
{$ENDIF}

initialization
  ModuleResolveLock := TCriticalSection.Create;
finalization
  ModuleResolveLock.Free;
end.
