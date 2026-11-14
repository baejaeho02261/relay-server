unit Cozy.NHW.ExecutableLifecycle;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows, System.Generics.Collections, Cozy.NHW.Logging;

type
  TExecProtection = (epOther, epWritable, epExecutable, epRWX);
  TExecRegionSample = record
    AllocationBase: NativeUInt;
    Size: NativeUInt;
    Protection: TExecProtection;
  end;

  TExecTransitionCandidate = record
    AllocationBase, Size: NativeUInt;
    Protection: TExecProtection;
    TransitionTick, LastConfirmedTick: UInt64;
    Confirmed, Reported: Boolean;
  end;

  // v54: current-process MEM_PRIVATE protections, from complete bounded
  // address-space sweeps. Missing samples never imply a transition.
  TExecutableLifecycle = class
  private
    FPrevious: TDictionary<NativeUInt, TExecRegionSample>;
    FCurrent: TDictionary<NativeUInt, TExecRegionSample>;
    FPending: TDictionary<NativeUInt, TExecTransitionCandidate>;
    FNext: NativeUInt;
    FRunning: Boolean;
    FSweepBaseline: Boolean;
    FPrimed: Boolean;
    FStart: UInt64;
    FLastComplete: UInt64;
    FLastIndependent: UInt64;
    FLastReport: UInt64;
    procedure BeginSweep(Tick: UInt64);
    procedure CancelSweep;
    procedure EndSweep(Baseline: Boolean; Tick: UInt64;
      var Detected: TDetectionKinds);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Examine(Baseline, IndependentEvidence: Boolean;
      Tick: UInt64; var Detected: TDetectionKinds);
  end;

function ClassifyPrivateProtection(const Protect: Cardinal): TExecProtection;
function IsExecutableTransition(Previous, Current: TExecProtection): Boolean;

{$IFDEF NHW_NATIVE5G_TESTS}
function TestExecutableLifecycleHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses System.SysUtils, Cozy.NHW.AllocationNative, Cozy.NHW.WinPointers;

const
  MAX_EXEC_REGIONS = 16000;
  MAX_REGIONS_PER_STEP = 160;
  MAX_SWEEP_MS = 60000;
  SWEEP_REST_MS = 4000;
  INDEPENDENT_MS = 120000;
  EXEC_COOLDOWN_MS = 60000;
  EXEC_CANDIDATE_MS = 120000;

{$IFDEF NHW_NATIVE5G_TESTS}
type
  TExecQueryHook = function(Address: NativeUInt; out R: TVirtualRegion): Boolean;
  TExecAvailableHook = function: Boolean;
  TExecLimitHook = function: NativeUInt;
var
  ExecQueryHook: TExecQueryHook = nil;
  ExecAvailableHook: TExecAvailableHook = nil;
  ExecLimitHook: TExecLimitHook = nil;
{$ENDIF}

function ExecAvailable: Boolean;
begin
{$IFDEF NHW_NATIVE5G_TESTS}
  if Assigned(ExecAvailableHook) then Exit(ExecAvailableHook());
{$ENDIF}
  Result := AllocationNativeAvailable;
end;

function ExecLimit: NativeUInt;
begin
{$IFDEF NHW_NATIVE5G_TESTS}
  if Assigned(ExecLimitHook) then Exit(ExecLimitHook());
{$ENDIF}
  Result := MaximumUserVirtualAddress;
end;

function ExecQuery(Address: NativeUInt; out R: TVirtualRegion): Boolean;
begin
  R := Default(TVirtualRegion);
{$IFDEF NHW_NATIVE5G_TESTS}
  if Assigned(ExecQueryHook) then Exit(ExecQueryHook(Address, R));
{$ENDIF}
  Result := QueryVirtualRegion(WinCurrentProcess, Address, R);
end;

function ExecCandidateLive(const C: TExecTransitionCandidate;
  const Current: TExecRegionSample; Tick: UInt64): Boolean;
begin
  Result := (C.AllocationBase = Current.AllocationBase) and
    (C.Size = Current.Size) and (C.Protection = Current.Protection) and
    (Tick >= C.TransitionTick) and (Tick >= C.LastConfirmedTick) and
    (Tick - C.TransitionTick <= EXEC_CANDIDATE_MS);
end;

function ClassifyPrivateProtection(const Protect: Cardinal): TExecProtection;
begin
  Result := epOther;
  if (Protect and ALLOC_PAGE_GUARD) <> 0 then Exit;
  case Protect and $FF of
    $04, $08: Result := epWritable; // PAGE_READWRITE / WRITECOPY
    $10, $20: Result := epExecutable;
    $40, $80: Result := epRWX;
  end;
end;

function IsExecutableTransition(Previous, Current: TExecProtection): Boolean;
begin
  Result := ((Previous = epWritable) and
    (Current in [epExecutable, epRWX])) or
    ((Previous <> epRWX) and (Current = epRWX));
end;

constructor TExecutableLifecycle.Create;
begin
  inherited Create;
  FPrevious := TDictionary<NativeUInt, TExecRegionSample>.Create;
  FCurrent := TDictionary<NativeUInt, TExecRegionSample>.Create;
  FPending := TDictionary<NativeUInt, TExecTransitionCandidate>.Create;
  Reset;
end;

destructor TExecutableLifecycle.Destroy;
begin
  FPending.Free;
  FCurrent.Free;
  FPrevious.Free;
  inherited Destroy;
end;

procedure TExecutableLifecycle.Reset;
begin
  FPrevious.Clear;
  FCurrent.Clear;
  FPending.Clear;
  FNext := $10000;
  FRunning := False;
  FSweepBaseline := False;
  FPrimed := False;
  FStart := 0;
  FLastComplete := 0;
  FLastIndependent := 0;
  FLastReport := 0;
end;

procedure TExecutableLifecycle.BeginSweep(Tick: UInt64);
begin
  FCurrent.Clear;
  FRunning := True;
  FNext := $10000;
  FStart := Tick;
  FSweepBaseline := False;
end;

procedure TExecutableLifecycle.CancelSweep;
begin
  FCurrent.Clear;
  FPending.Clear;
  FRunning := False;
end;

procedure TExecutableLifecycle.EndSweep(Baseline: Boolean;
  Tick: UInt64; var Detected: TDetectionKinds);
var
  NewPending: TDictionary<NativeUInt, TExecTransitionCandidate>;
  Independent, CanReport, ReportNow: Boolean;

  procedure BuildTransitionCandidates;
  var
    Pair: TPair<NativeUInt, TExecRegionSample>;
    Prev: TExecRegionSample;
    Candidate: TExecTransitionCandidate;
    PreviousKnown, HasCandidate: Boolean;
  begin
    for Pair in FCurrent do
    begin
      PreviousKnown := FPrevious.TryGetValue(Pair.Key, Prev) and
        (Prev.AllocationBase = Pair.Value.AllocationBase) and
        (Prev.Size = Pair.Value.Size);
      if not FPrimed or Baseline or FSweepBaseline or not PreviousKnown then
        Continue;
      HasCandidate := False;
      Candidate := Default(TExecTransitionCandidate);
      if IsExecutableTransition(Prev.Protection, Pair.Value.Protection) then
      begin
        Candidate.AllocationBase := Pair.Value.AllocationBase;
        Candidate.Size := Pair.Value.Size;
        Candidate.Protection := Pair.Value.Protection;
        Candidate.TransitionTick := Tick;
        Candidate.LastConfirmedTick := Tick;
        HasCandidate := True;
      end
      else if FPending.TryGetValue(Pair.Key, Candidate) and
        ExecCandidateLive(Candidate, Pair.Value, Tick) then
      begin
        // Confirmation needs another completed sweep at a later time.
        if Tick > Candidate.LastConfirmedTick then
        begin
          Candidate.Confirmed := True;
          Candidate.LastConfirmedTick := Tick;
        end;
        HasCandidate := True;
      end;
      if not HasCandidate then Continue;
      if Candidate.Confirmed and not Candidate.Reported and
        Independent and CanReport then
      begin
        Candidate.Reported := True;
        ReportNow := True;
      end;
      NewPending.AddOrSetValue(Pair.Key, Candidate);
    end;
  end;

  procedure CommitCompletedSweep;
  var
    OldPending: TDictionary<NativeUInt, TExecTransitionCandidate>;
    OldPrevious: TDictionary<NativeUInt, TExecRegionSample>;
  begin
    // Publish complete dictionaries only. A failed allocation above cannot
    // leave a half-updated baseline, nor publish a detection from it.
    OldPending := FPending;
    FPending := NewPending;
    NewPending := OldPending;
    OldPrevious := FPrevious;
    FPrevious := FCurrent;
    FCurrent := OldPrevious;
    FPrimed := True;
    FLastComplete := Tick;
  end;

begin
  FRunning := False;
  NewPending := nil;
  try
    try
      NewPending := TDictionary<NativeUInt,TExecTransitionCandidate>.Create;
      Independent := (FLastIndependent <> 0) and
        (Tick >= FLastIndependent) and
        (Tick - FLastIndependent <= INDEPENDENT_MS);
      CanReport := (FLastReport = 0) or (Tick < FLastReport) or
        (Tick - FLastReport >= EXEC_COOLDOWN_MS);
      ReportNow := False;
      BuildTransitionCandidates;
      CommitCompletedSweep;
      if ReportNow then
      begin
        Include(Detected, dkExecutableLifecycle);
        FLastReport := Tick;
      end;
    except
      CancelSweep;
      raise;
    end;
  finally
    NewPending.Free;
    FCurrent.Clear;
    FSweepBaseline := False;
  end;
end;

procedure TExecutableLifecycle.Examine(Baseline,
  IndependentEvidence: Boolean; Tick: UInt64;
  var Detected: TDetectionKinds);
var
  Limit: NativeUInt;

  procedure ScanRegionStep;
  var
    R: TVirtualRegion;
    Item: TExecRegionSample;
    Next: NativeUInt;
    I: Integer;
  begin
    for I := 1 to MAX_REGIONS_PER_STEP do
    begin
      if FNext >= Limit then
      begin
        EndSweep(Baseline, Tick, Detected);
        Exit;
      end;
      if not ExecQuery(FNext, R) or
        (R.Size = 0) or (R.BaseAddress > High(NativeUInt) - R.Size) then
      begin
        CancelSweep;
        Exit;
      end;
      if (R.State = ALLOC_MEM_COMMIT) and
         (R.RegionType = ALLOC_MEM_PRIVATE) then
      begin
        Item.AllocationBase := R.AllocationBase;
        Item.Size := R.Size;
        Item.Protection := ClassifyPrivateProtection(R.Protect);
        if Item.Protection <> epOther then
        begin
          if FCurrent.Count >= MAX_EXEC_REGIONS then
          begin
            CancelSweep;
            Exit;
          end;
          FCurrent.AddOrSetValue(R.BaseAddress, Item);
        end;
      end;
      Next := R.BaseAddress + R.Size;
      if Next <= FNext then
      begin
        CancelSweep;
        Exit;
      end;
      FNext := Next;
    end;
  end;

begin
  if IndependentEvidence or
    ((Detected * [dkPrivateThread, dkExecutionProvenance,
       dkImageCOWIntegrity, dkPECodeIntegrity]) <> []) then
    FLastIndependent := Tick;
  if not ExecAvailable then
  begin CancelSweep; Exit; end;
  if Baseline then FPending.Clear;
  if not FRunning then
  begin
    if (FLastComplete <> 0) and (Tick >= FLastComplete) and
      (Tick - FLastComplete < SWEEP_REST_MS) then Exit;
    BeginSweep(Tick);
  end;
  FSweepBaseline := FSweepBaseline or Baseline;
  if (Tick < FStart) or (Tick - FStart > MAX_SWEEP_MS) then
  begin
    CancelSweep;
    Exit;
  end;
  Limit := ExecLimit;
  if Limit <= $10000 then
  begin CancelSweep; Exit; end;
  try
  ScanRegionStep;
  except
    CancelSweep;
    raise;
  end;
end;

{$IFDEF NHW_NATIVE5G_TESTS}
{$I Cozy.NHW.Native5G.ExecutableLifecycle.inc}
{$ENDIF}

end.
