unit Cozy.NHW.PECodeIntegrity;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  Cozy.NHW.Logging,
  Cozy.NHW.PECodeDigest;

type
  TCodeImageDigest = Cozy.NHW.PECodeDigest.TCodeImageDigest;

  TCodeIntegrityCell = record
    ModuleBase: NativeUInt;
    BaselineDigest: UInt64;
    PendingDigest: UInt64;
    Primed: Boolean;
    Stable: Boolean;
    PendingCount: Integer;
  end;

  TCodeSectionSpan = Cozy.NHW.PECodeDigest.TCodeSectionSpan;
  TCodeImageLayout = Cozy.NHW.PECodeDigest.TCodeImageLayout;
  TCodeScanProgress = Cozy.NHW.PECodeDigest.TCodeScanProgress;

  // Read-only, after-loader baseline. Large images are covered over multiple
  // bounded passes, NOT sampled only at their start. A pending pass is not a
  // complete digest. Live reads are not an atomic process snapshot.
  TPECodeIntegrityMonitor = class
  private
    // Last Examine only: known failed collection, not a throttled/pending pass.
    FObservationFailed: Boolean;
    FOwnImageChanged: Boolean;
    FCells: array[0..3] of TCodeIntegrityCell;
    FProgress: array[0..3] of TCodeScanProgress;
    FLastScan: UInt64;
    FLastReport: UInt64;
    FWasBaseline: Boolean;
    procedure ClearCandidate(Index: Integer);
  public
    property ObservationFailed: Boolean read FObservationFailed;
    property OwnImageChanged: Boolean read FOwnImageChanged;
    constructor Create;
    procedure Reset;
    procedure Examine(Baseline: Boolean; Tick: UInt64;
      var Detected: TDetectionKinds);
  end;

// Compatibility entry point for diagnostics: complete one-shot digest,
// bounded by the 512 MiB image limit. The monitor uses incremental work.
function CaptureExecutableCodeDigest(Module: HMODULE;
  out Digest: TCodeImageDigest): Boolean;

{$IFDEF NHW_NATIVE5F_TESTS}
function TestPECodeHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  System.SysUtils,
  Cozy.NHW.PEView,
  Cozy.NHW.NativeSafety,
  Cozy.NHW.WinPointers,
  Cozy.NHW.PERules;

const
  CODE_SCAN_PERIOD_MS = 6000;
  CODE_REPORT_COOLDOWN_MS = 60000;
{$IFDEF NHW_NATIVE5F_TESTS}
type
  TCodeModuleHook = function(Index: Integer): HMODULE;
var
  CodeModuleHook: TCodeModuleHook = nil;
{$ENDIF}

function CodeModule(Index: Integer): HMODULE;
begin
{$IFDEF NHW_NATIVE5F_TESTS}
  if Assigned(CodeModuleHook) then Exit(CodeModuleHook(Index));
{$ENDIF}
  case Index of
    0: Result := HMODULE(HInstance);
    1: Result := WinModule('ntdll.dll');
    2: Result := WinModule('kernel32.dll');
    3: Result := WinModule('kernelbase.dll');
  else Result := 0;
  end;
end;

function CaptureExecutableCodeDigest(Module: HMODULE;
  out Digest: TCodeImageDigest): Boolean;
begin
  Result := Cozy.NHW.PECodeDigest.CaptureExecutableCodeDigest(Module, Digest);
end;

constructor TPECodeIntegrityMonitor.Create;
begin inherited Create; Reset; end;

procedure TPECodeIntegrityMonitor.ClearCandidate(Index: Integer);
begin
  FCells[Index].PendingDigest := 0;
  FCells[Index].PendingCount := 0;
  // Two *successful* complete startup reads must agree; a failed read breaks
  // initial priming, but never overwrites an already established baseline.
  if not FCells[Index].Stable then FCells[Index].Primed := False;
end;

procedure TPECodeIntegrityMonitor.Reset;
begin
  FObservationFailed := False;
  FOwnImageChanged := False;
  FillChar(FCells, SizeOf(FCells), 0);
  FillChar(FProgress, SizeOf(FProgress), 0);
  FLastScan := 0;
  FLastReport := 0;
  FWasBaseline := False;
end;

procedure TPECodeIntegrityMonitor.Examine(Baseline: Boolean;
  Tick: UInt64; var Detected: TDetectionKinds);
var
  Module: HMODULE;
  D: TCodeImageDigest;
  C: TCodeIntegrityCell;
  I: Integer;
  Changed, Restarted: Boolean;
  Status: TCodeScanResult;
begin
  FObservationFailed := False;
  FOwnImageChanged := False;
  if ((FLastScan <> 0) and (Tick < FLastScan)) or
    (Baseline <> FWasBaseline) then
  begin
    for I := 0 to 3 do
    begin
      ClearCandidate(I);
      FProgress[I] := Default(TCodeScanProgress);
    end;
    if Tick < FLastScan then FLastReport := 0;
  end;
  FWasBaseline := Baseline;
  if (FLastScan <> 0) and (Tick >= FLastScan) and
    (Tick - FLastScan < CODE_SCAN_PERIOD_MS) then Exit;
  FLastScan := Tick;
  Changed := False;
  try
    for I := 0 to 3 do
    begin
      Module := CodeModule(I);
      if FCells[I].ModuleBase <> NativeUInt(Module) then
      begin
        FCells[I] := Default(TCodeIntegrityCell);
        FCells[I].ModuleBase := NativeUInt(Module);
        FProgress[I] := Default(TCodeScanProgress);
      end;
      if Module = 0 then
      begin
        ClearCandidate(I);
        Continue;
      end;
      Status := AdvanceCodeDigest(Module, CODE_SCAN_BUDGET,
        FProgress[I], D, Restarted);
      if Restarted then
      begin
        FObservationFailed := True; // layout continuity was lost
        ClearCandidate(I);
      end;
      if (Status = csrFailed) or (CodeModule(I) <> Module) then
      begin
        FObservationFailed := True;
        ClearCandidate(I);
        FProgress[I] := Default(TCodeScanProgress);
        Continue;
      end;
      if Status = csrPending then Continue;
      C := FCells[I];
      if not C.Primed then
      begin
        C.Primed := True;
        C.BaselineDigest := D.Value;
      end
      else if not C.Stable then
      begin
        if D.Value = C.BaselineDigest then C.Stable := True
        else C.BaselineDigest := D.Value;
      end
      else if Baseline then
      begin
        C.BaselineDigest := D.Value;
        C.PendingDigest := 0;
        C.PendingCount := 0;
      end
      else if D.Value = C.BaselineDigest then
      begin
        C.PendingDigest := 0;
        C.PendingCount := 0;
      end
      else
      begin
        if (C.PendingCount = 0) or (D.Value <> C.PendingDigest) then
        begin
          C.PendingDigest := D.Value;
          C.PendingCount := 1;
        end
        else if C.PendingCount < 2 then Inc(C.PendingCount);
        if C.PendingCount >= 2 then
        begin
          Changed := True;
          // Slot zero is the executable loaded by the Cozy process.
          if I = 0 then FOwnImageChanged := True;
        end;
      end;
      FCells[I] := C;
    end;
  except
    FObservationFailed := True;
    FOwnImageChanged := False;
    for I := 0 to 3 do
    begin
      ClearCandidate(I);
      FProgress[I] := Default(TCodeScanProgress);
    end;
    raise; // preserve the existing engine fault-isolation contract
  end;
  if Changed and ((FLastReport = 0) or
    ((Tick >= FLastReport) and
     (Tick - FLastReport >= CODE_REPORT_COOLDOWN_MS))) then
  begin
    Include(Detected, dkPECodeIntegrity);
    FLastReport := Tick;
  end;
end;

{$IFDEF NHW_NATIVE5F_TESTS}
{$I Cozy.NHW.Native5F.PECode.inc}
{$ENDIF}

end.
