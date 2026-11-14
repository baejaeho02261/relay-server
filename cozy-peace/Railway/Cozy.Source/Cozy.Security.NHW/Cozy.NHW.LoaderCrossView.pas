unit Cozy.NHW.LoaderCrossView;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, Cozy.NHW.Logging;

type
  TLoaderViewCounts = record
    Valid: Boolean;
    PSAPICount: Cardinal;
    ToolhelpCount: Cardinal;
    Missing: Cardinal;
  end;

  TLoaderMismatch = record
    Base: NativeUInt;
    MissingFrom: Byte; // 1 = Toolhelp, 2 = PSAPI
  end;
  TLoaderMismatches = TArray<TLoaderMismatch>;

  // v62: require the SAME address/direction set in complete observations.
  // Two user-mode APIs are not independent roots of trust. Neither this
  // comparison nor its two PSAPI reads is an atomic loader snapshot.
  TLoaderCrossViewMonitor = class
  private
    FLastScan: UInt64;
    FLastReport: UInt64;
    FLastObservation: UInt64;
    FLastMismatch: TLoaderMismatches;
    FConfirmations: Integer;
    procedure ClearCandidate;
  public
    constructor Create;
    procedure Reset;
    procedure Examine(Baseline, IndependentEvidence: Boolean;
      Tick: UInt64; var Detected: TDetectionKinds);
  end;

function CaptureLoaderCrossView(out Counts: TLoaderViewCounts): Boolean;
function LoaderViewCandidate(const Counts: TLoaderViewCounts;
  Confirmations: Integer; Evidence: Boolean): Boolean;

{$IFDEF NHW_NATIVE5E_TESTS}
function TestLoaderCrossViewHardening(out Failure: string;
  out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses System.SysUtils, Cozy.NHW.WinPointers;

const
  MAX_LOADER_MODULES = 512;
  TH32CS_SNAPMODULE = $00000008;
  TH32CS_SNAPMODULE32 = $00000010;
  LOADER_SCAN_MS = 7000;
  LOADER_CONFIRM_GAP_MS = 14000;
  LOADER_COOLDOWN_MS = 60000;

type
  TLoaderModules = array[0..MAX_LOADER_MODULES-1] of NativeUInt;
  TEnumProcessModules = function(Process: THandle; Modules: Pointer;
    BufferBytes: Cardinal; out Needed: Cardinal): BOOL; stdcall;
  TCreateModuleSnapshot = function(Flags, PID: Cardinal): THandle; stdcall;
  TModuleEntry32W = record
    dwSize: Cardinal;
    th32ModuleID: Cardinal;
    th32ProcessID: Cardinal;
    GlblcntUsage: Cardinal;
    ProccntUsage: Cardinal;
    modBaseAddr: Pointer;
    modBaseSize: Cardinal;
    hModule: HMODULE;
    szModule: array[0..255] of WideChar;
    szExePath: array[0..259] of WideChar;
  end;
  TModule32FirstW = function(Snapshot: THandle;
    var Entry: TModuleEntry32W): BOOL; stdcall;
  TModule32NextW = function(Snapshot: THandle;
    var Entry: TModuleEntry32W): BOOL; stdcall;

var
  EnumModules: TEnumProcessModules = nil;
  CreateSnapshot: TCreateModuleSnapshot = nil;
  ModuleFirst: TModule32FirstW = nil;
  ModuleNext: TModule32NextW = nil;
  Resolved: Boolean = False;

{$IFDEF NHW_NATIVE5E_TESTS}
type TLoaderCloseHook = procedure(Snapshot: THandle);
var LoaderCloseHook: TLoaderCloseHook = nil;
{$ENDIF}

procedure CloseLoaderSnapshot(Snapshot: THandle);
begin
{$IFDEF NHW_NATIVE5E_TESTS}
  if Assigned(LoaderCloseHook) then
  begin LoaderCloseHook(Snapshot); Exit; end;
{$ENDIF}
  WinCloseHandle(Snapshot);
end;

procedure ResolveViewAPIs;
var K, P: HMODULE;
begin
  if Resolved then Exit;
  K := WinModule('kernel32.dll');
  P := WinLoadLibrary('psapi.dll');
  EnumModules := TEnumProcessModules(WinExport(K, 'K32EnumProcessModules'));
  if not Assigned(EnumModules) then
    EnumModules := TEnumProcessModules(WinExport(P, 'EnumProcessModules'));
  CreateSnapshot := TCreateModuleSnapshot(
    WinExport(K, 'CreateToolhelp32Snapshot'));
  ModuleFirst := TModule32FirstW(WinExport(K, 'Module32FirstW'));
  ModuleNext := TModule32NextW(WinExport(K, 'Module32NextW'));
  Resolved := True;
end;

function SortLoaderModules(var Modules: TLoaderModules; Count: Integer): Boolean;
var I, J: Integer; Value: NativeUInt;
begin
  Result := False;
  if (Count <= 0) or (Count > Length(Modules)) then Exit;
  // Bounded insertion sort avoids managed allocations while parsing a view.
  for I := 0 to Count - 1 do
  begin
    Value := Modules[I];
    if Value < $10000 then Exit;
    J := I;
    while J > 0 do
    begin
      if Modules[J-1] <= Value then Break;
      Modules[J] := Modules[J-1];
      Dec(J);
    end;
    Modules[J] := Value;
  end;
  for I := 1 to Count - 1 do
    if Modules[I] = Modules[I-1] then Exit; // duplicate/partial API response
  Result := True;
end;

function ReadLoaderPSAPI(out Modules: TLoaderModules; out Count: Integer): Boolean;
var Needed: Cardinal;
begin
  Result := False;
  Modules := Default(TLoaderModules);
  Count := 0;
  Needed := 0;
  if not EnumModules(WinCurrentProcess, @Modules[0], SizeOf(Modules), Needed) then Exit;
  if (Needed = 0) or (Needed > Cardinal(SizeOf(Modules))) or
     ((Needed mod Cardinal(SizeOf(NativeUInt))) <> 0) then Exit;
  Count := Integer(Needed div Cardinal(SizeOf(NativeUInt)));
  Result := SortLoaderModules(Modules, Count);
  if not Result then Count := 0;
end;

function SameLoaderModules(const A, B: TLoaderModules; NA, NB: Integer): Boolean;
var I: Integer;
begin
  Result := False;
  if NA <> NB then Exit;
  for I := 0 to NA - 1 do if A[I] <> B[I] then Exit;
  Result := True;
end;

function SameLoaderMismatches(const A, B: TLoaderMismatches): Boolean;
var I: Integer;
begin
  Result := False;
  if Length(A) <> Length(B) then Exit;
  for I := 0 to Length(A) - 1 do
    if (A[I].Base <> B[I].Base) or
       (A[I].MissingFrom <> B[I].MissingFrom) then Exit;
  Result := True;
end;

function ReadLoaderToolhelp(Snapshot: THandle; PID: Cardinal;
  out TH: TLoaderModules; out NTH: Integer): Boolean;
var
  E: TModuleEntry32W;
  EndError: Cardinal;
begin
  Result := False;
  TH := Default(TLoaderModules);
  NTH := 0;
  E := Default(TModuleEntry32W);
  E.dwSize := SizeOf(E);
  if not ModuleFirst(Snapshot, E) then Exit;
  while True do
  begin
    if NTH >= MAX_LOADER_MODULES then Exit;
    if (E.dwSize <> Cardinal(SizeOf(E))) or (E.th32ProcessID <> PID) or
       (NativeUInt(E.modBaseAddr) < $10000) or (E.modBaseSize = 0) or
       (NativeUInt(E.modBaseAddr) > High(NativeUInt) - NativeUInt(E.modBaseSize)) then Exit;
    TH[NTH] := NativeUInt(E.modBaseAddr);
    Inc(NTH);
    E := Default(TModuleEntry32W);
    E.dwSize := SizeOf(E);
    if not ModuleNext(Snapshot, E) then
    begin
      EndError := WinGetLastError; // must be captured before another API
      if EndError <> ERROR_NO_MORE_FILES then Exit;
      Break;
    end;
  end;
  if not SortLoaderModules(TH, NTH) then Exit;
  Result := True;
end;

procedure CollectLoaderDifferences(const PS, TH: TLoaderModules;
  NPS, NTH: Integer; out Items: TLoaderMismatches; out NMissing: Integer);
var
  I, J: Integer;
begin
  SetLength(Items, NPS + NTH);
  I := 0;
  J := 0;
  NMissing := 0;
  while (I < NPS) or (J < NTH) do
  begin
    if I >= NPS then
    begin
      Items[NMissing].Base := TH[J];
      Items[NMissing].MissingFrom := 2;
      Inc(J);
    end
    else if J >= NTH then
    begin
      Items[NMissing].Base := PS[I];
      Items[NMissing].MissingFrom := 1;
      Inc(I);
    end
    else if PS[I] = TH[J] then
    begin Inc(I); Inc(J); Continue; end
    else if PS[I] < TH[J] then
    begin
      Items[NMissing].Base := PS[I];
      Items[NMissing].MissingFrom := 1;
      Inc(I);
    end
    else
    begin
      Items[NMissing].Base := TH[J];
      Items[NMissing].MissingFrom := 2;
      Inc(J);
    end;
    Inc(NMissing);
  end;
  SetLength(Items, NMissing);
end;

function CaptureLoaderDetails(out Counts: TLoaderViewCounts;
  out Mismatches: TLoaderMismatches): Boolean;
var
  PS, TH, AfterPS: TLoaderModules;
  Snapshot: THandle;
  NPS, NTH, NAfter, NMissing: Integer;
  PID: Cardinal;
  Items: TLoaderMismatches;
  Candidate: TLoaderViewCounts;
begin
  Counts := Default(TLoaderViewCounts);
  Mismatches := nil;
  Candidate := Default(TLoaderViewCounts);
  Result := False;
  ResolveViewAPIs;
  if not Assigned(EnumModules) or not Assigned(CreateSnapshot) or
     not Assigned(ModuleFirst) or not Assigned(ModuleNext) then Exit;
  if not ReadLoaderPSAPI(PS, NPS) then Exit;
  PID := WinCurrentProcessId;
  Snapshot := CreateSnapshot(TH32CS_SNAPMODULE or TH32CS_SNAPMODULE32, PID);
  if (Snapshot = INVALID_HANDLE_VALUE) or (Snapshot = 0) then Exit;
  try
    if not ReadLoaderToolhelp(Snapshot, PID, TH, NTH) then Exit;
    // Changing PSAPI membership invalidates this comparison, not an alarm.
    if not ReadLoaderPSAPI(AfterPS, NAfter) then Exit;
    if not SameLoaderModules(PS, AfterPS, NPS, NAfter) then Exit;
    CollectLoaderDifferences(PS, TH, NPS, NTH, Items, NMissing);
    Candidate.PSAPICount := Cardinal(NPS);
    Candidate.ToolhelpCount := Cardinal(NTH);
    Candidate.Missing := Cardinal(NMissing);
    Candidate.Valid := True;
  finally
    CloseLoaderSnapshot(Snapshot);
  end;
  Counts := Candidate; // publish only after successful enumeration/cleanup
  Mismatches := Items;
  Result := True;
end;

function CaptureLoaderCrossView(out Counts: TLoaderViewCounts): Boolean;
var Mismatches: TLoaderMismatches;
begin
  Result := CaptureLoaderDetails(Counts, Mismatches);
end;

function LoaderViewCandidate(const Counts: TLoaderViewCounts;
  Confirmations: Integer; Evidence: Boolean): Boolean;
begin
  // Public predicate remains compatible with the existing regression tests;
  // the monitor enforces exact mismatch identity before it reaches this gate.
  Result := Counts.Valid and (Counts.Missing > 0) and
    (Confirmations >= 3) and Evidence;
end;

constructor TLoaderCrossViewMonitor.Create;
begin inherited Create; Reset; end;

procedure TLoaderCrossViewMonitor.ClearCandidate;
begin
  FLastMismatch := nil;
  FLastObservation := 0;
  FConfirmations := 0;
end;

procedure TLoaderCrossViewMonitor.Reset;
begin
  FLastScan := 0;
  FLastReport := 0;
  ClearCandidate;
end;

procedure TLoaderCrossViewMonitor.Examine(Baseline,
  IndependentEvidence: Boolean; Tick: UInt64;
  var Detected: TDetectionKinds);
var Counts: TLoaderViewCounts; Current: TLoaderMismatches;
begin
  if (FLastScan <> 0) and (Tick < FLastScan) then Reset;
  if (FLastScan <> 0) and (Tick >= FLastScan) and
    (Tick - FLastScan < LOADER_SCAN_MS) then Exit;
  FLastScan := Tick;
  try
    if not CaptureLoaderDetails(Counts, Current) then
    begin
      ClearCandidate;
      Exit;
    end;
  except
    ClearCandidate;
    raise;
  end;
  if Baseline or (Counts.Missing = 0) then
  begin
    ClearCandidate;
    Exit;
  end;
  if (FConfirmations <> 0) and (Tick > FLastObservation) and
     (Tick - FLastObservation <= LOADER_CONFIRM_GAP_MS) and
     SameLoaderMismatches(Current, FLastMismatch) then
  begin
    if FConfirmations < 3 then Inc(FConfirmations);
  end
  else FConfirmations := 1;
  FLastMismatch := Current;
  FLastObservation := Tick;
  if LoaderViewCandidate(Counts, FConfirmations, IndependentEvidence) and
     ((FLastReport = 0) or
      ((Tick >= FLastReport) and (Tick - FLastReport >= LOADER_COOLDOWN_MS))) then
  begin
    Include(Detected, dkLoaderCrossView);
    FLastReport := Tick;
  end;
end;

{$IFDEF NHW_NATIVE5E_TESTS}
{$I Cozy.NHW.Native5E.LoaderCrossView.inc}
{$ENDIF}

end.
