unit Cozy.NHW.RegionClassifier;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.Generics.Collections,
  Cozy.NHW.AllocationNative,
  Cozy.NHW.Logging;

type
  TRegionClass = (rcOther, rcPrivateWritable, rcPrivateExecutable,
    rcPrivateRWX, rcMappedExecutable, rcImageExecutable);

  TRegionObservation = record
    BaseAddress: NativeUInt;
    AllocationBase: NativeUInt;
    Size: NativeUInt;
    Kind: TRegionClass;
  end;

  TRegionClassCounts = record
    PrivateExecutable: Cardinal;
    PrivateRWX: Cardinal;
    MappedExecutable: Cardinal;
    ImageExecutable: Cardinal;
  end;

  // v39: metadata only. Uses incremental read-only NtQueryVirtualMemory
  // sweeps against our OWN PID, preserving completed-snapshot semantics.
  TMemoryRegionClassifier = class
  private
    // Last Examine only: known failed collection, not a throttled/pending pass.
    FObservationFailed: Boolean;
    FPrevious: TDictionary<NativeUInt, TRegionObservation>;
    FCurrent: TDictionary<NativeUInt, TRegionObservation>;
    FPending: TDictionary<NativeUInt, TRegionObservation>;
    FRunning: Boolean;
    FOverflow: Boolean;
    FHaveBaseline: Boolean;
    FNextAddress: NativeUInt;
    FSweepStartTick: UInt64;
    FLastCompleteTick: UInt64;
    FLastReportTick: UInt64;
    FCounts: TRegionClassCounts;
    FWorkingCounts: TRegionClassCounts;
    procedure BeginSweep(Tick: UInt64);
    procedure EndSweep(Baseline: Boolean; Tick: UInt64;
      var Detected: TDetectionKinds);
    procedure CancelSweep;
    procedure Observe(const Region: TVirtualRegion);
    function BuildTransitionCandidates(Baseline: Boolean;
      NewPending: TDictionary<NativeUInt, TRegionObservation>): Boolean;
    procedure CommitCompletedSweep(
      var NewPending: TDictionary<NativeUInt, TRegionObservation>; Tick: UInt64);
    procedure ReportCompletedSweep(Confirmed: Boolean; Tick: UInt64;
      var Detected: TDetectionKinds);
    procedure AdvanceSweep(Baseline: Boolean; Tick: UInt64;
      var Detected: TDetectionKinds);
  public
    property ObservationFailed: Boolean read FObservationFailed;
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Examine(Baseline: Boolean; Tick: UInt64;
      var Detected: TDetectionKinds);
    property Counts: TRegionClassCounts read FCounts;
  end;

function ClassifyMemoryRegion(const Region: TVirtualRegion): TRegionClass;
function SuspiciousPrivateTransition(const Old, New: TRegionObservation;
  OldKnown: Boolean): Boolean;

{$IFDEF NHW_NATIVE10N_TESTS}
function TestRegionClassifier10N(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  Cozy.NHW.WinPointers, System.SysUtils;

{$IFDEF NHW_NATIVE10N_TESTS}
var RegionFailCommit10N: Boolean = False;
{$ENDIF}

const
  MAX_REGIONS_PER_STEP = 160;
  MAX_CLASSIFIED_REGIONS = 16000;
  MAX_SWEEP_DURATION_MS = 60000;
  SWEEP_PAUSE_MS = 4000;
  REGION_REPORT_COOLDOWN_MS = 20000;

function ClassifyMemoryRegion(const Region: TVirtualRegion): TRegionClass;
var
  Permission: Cardinal;
begin
  Result := rcOther;
  if (Region.State <> ALLOC_MEM_COMMIT) or
     ((Region.Protect and ALLOC_PAGE_GUARD) <> 0) then Exit;
  Permission := Region.Protect and $FF;
  if Region.RegionType = ALLOC_MEM_PRIVATE then
  begin
    if Permission = ALLOC_PAGE_EXECUTE_READWRITE then
      Result := rcPrivateRWX
    else if RegionIsExecutable(Region) then
      Result := rcPrivateExecutable
    else if (Permission = $04) or (Permission = $08) then
      Result := rcPrivateWritable;
  end
  else if RegionIsExecutable(Region) then
  begin
    if Region.RegionType = ALLOC_MEM_IMAGE then
      Result := rcImageExecutable
    else if Region.RegionType = ALLOC_MEM_MAPPED then
      Result := rcMappedExecutable;
  end;
end;

function SuspiciousPrivateTransition(const Old, New: TRegionObservation;
  OldKnown: Boolean): Boolean;
begin
  Result := False;
  if not (New.Kind in [rcPrivateRWX, rcPrivateExecutable]) then Exit;
  if not OldKnown then
    Exit(New.Kind = rcPrivateRWX);
  if (Old.BaseAddress <> New.BaseAddress) or
     (Old.AllocationBase <> New.AllocationBase) then Exit;
  // A newly introduced RWX region, or an observed writable-to-executable
  // transition in the same allocation. A pre-existing RX page is not flagged.
  Result := ((New.Kind = rcPrivateRWX) and
             (Old.Kind <> rcPrivateRWX)) or
            ((Old.Kind = rcPrivateWritable) and
             (New.Kind = rcPrivateExecutable));
end;

constructor TMemoryRegionClassifier.Create;
begin
  inherited Create;
  FPrevious := TDictionary<NativeUInt, TRegionObservation>.Create;
  FCurrent := TDictionary<NativeUInt, TRegionObservation>.Create;
  FPending := TDictionary<NativeUInt, TRegionObservation>.Create;
  Reset;
end;

destructor TMemoryRegionClassifier.Destroy;
begin
  FPending.Free;
  FCurrent.Free;
  FPrevious.Free;
  inherited Destroy;
end;

procedure TMemoryRegionClassifier.Reset;
begin
  FObservationFailed := False;
  FPrevious.Clear;
  FCurrent.Clear;
  FPending.Clear;
  FRunning := False;
  FOverflow := False;
  FHaveBaseline := False;
  FNextAddress := 0;
  FSweepStartTick := 0;
  FLastCompleteTick := 0;
  FLastReportTick := 0;
  FCounts := Default(TRegionClassCounts);
  FWorkingCounts := Default(TRegionClassCounts);
end;

procedure TMemoryRegionClassifier.BeginSweep(Tick: UInt64);
begin
  FCurrent.Clear;
  FWorkingCounts := Default(TRegionClassCounts);
  FOverflow := False;
  FRunning := True;
  FNextAddress := $10000;
  FSweepStartTick := Tick;
end;

procedure TMemoryRegionClassifier.CancelSweep;
begin
  FObservationFailed := True;
  FCurrent.Clear;
  FRunning := False;
  FOverflow := False;
  FWorkingCounts := Default(TRegionClassCounts);
  // Do not regard gaps, access failures or partial sweeps as changes.
  FPending.Clear;
end;

procedure TMemoryRegionClassifier.Observe(const Region: TVirtualRegion);
var
  Item: TRegionObservation;
begin
  Item.Kind := ClassifyMemoryRegion(Region);
  case Item.Kind of
    rcPrivateExecutable: Inc(FWorkingCounts.PrivateExecutable);
    rcPrivateRWX: Inc(FWorkingCounts.PrivateRWX);
    rcMappedExecutable: Inc(FWorkingCounts.MappedExecutable);
    rcImageExecutable: Inc(FWorkingCounts.ImageExecutable);
  end;
  if Item.Kind = rcOther then Exit;
  if FCurrent.Count >= MAX_CLASSIFIED_REGIONS then
  begin
    FOverflow := True;
    Exit;
  end;
  Item.BaseAddress := Region.BaseAddress;
  Item.AllocationBase := Region.AllocationBase;
  Item.Size := Region.Size;
  FCurrent.AddOrSetValue(Item.BaseAddress, Item);
end;

function TMemoryRegionClassifier.BuildTransitionCandidates(Baseline: Boolean;
  NewPending: TDictionary<NativeUInt, TRegionObservation>): Boolean;
var
  Item: TPair<NativeUInt, TRegionObservation>;
  Previous, Candidate: TRegionObservation;
  HadPrevious: Boolean;
begin
  Result := False;
  for Item in FCurrent do
  begin
    if FHaveBaseline and (not Baseline) then
    begin
      if FPending.TryGetValue(Item.Key, Candidate) and
         (Candidate.Kind = Item.Value.Kind) and
         (Candidate.AllocationBase = Item.Value.AllocationBase) and
         (Candidate.Size = Item.Value.Size) then
        Result := True;
      Previous := Default(TRegionObservation);
      HadPrevious := FPrevious.TryGetValue(Item.Key, Previous);
      if SuspiciousPrivateTransition(Previous, Item.Value, HadPrevious) then
        NewPending.AddOrSetValue(Item.Key, Item.Value);
    end;
  end;
end;

procedure TMemoryRegionClassifier.CommitCompletedSweep(
  var NewPending: TDictionary<NativeUInt, TRegionObservation>; Tick: UInt64);
var
  OldPrevious: TDictionary<NativeUInt, TRegionObservation>;
begin
  // All allocations have succeeded. Publish both complete collections;
  // no Clear+Add loop can leave a partially rebuilt accepted baseline.
  OldPrevious := FPrevious;
  FPrevious := FCurrent;
  FCurrent := OldPrevious;
  OldPrevious := FPending;
  FPending := NewPending;
  NewPending := OldPrevious;
  FHaveBaseline := True;
  FCounts := FWorkingCounts;
  FLastCompleteTick := Tick;
  FRunning := False;
end;

procedure TMemoryRegionClassifier.ReportCompletedSweep(Confirmed: Boolean; Tick: UInt64;
  var Detected: TDetectionKinds);
begin
  if Confirmed and ((FLastReportTick = 0) or
     ((Tick >= FLastReportTick) and
      (Tick - FLastReportTick >= REGION_REPORT_COOLDOWN_MS))) then
  begin
    Include(Detected, dkPrivateExecRegion);
    FLastReportTick := Tick;
  end;
end;

procedure TMemoryRegionClassifier.EndSweep(Baseline: Boolean;
  Tick: UInt64; var Detected: TDetectionKinds);
var
  Confirmed: Boolean;
  NewPending: TDictionary<NativeUInt, TRegionObservation>;
begin
  if FOverflow then
  begin
    CancelSweep;
    Exit;
  end;
  NewPending := nil;
  try
    try
      NewPending := TDictionary<NativeUInt, TRegionObservation>.Create;
      Confirmed := BuildTransitionCandidates(Baseline, NewPending);
      {$IFDEF NHW_NATIVE10N_TESTS}
      if RegionFailCommit10N then raise EOutOfMemory.Create('Native10N test');
      {$ENDIF}
      CommitCompletedSweep(NewPending, Tick);
      ReportCompletedSweep(Confirmed, Tick, Detected);
    except
      CancelSweep;
      raise;
    end;
  finally
    NewPending.Free;
    FCurrent.Clear;
  end;
end;

procedure TMemoryRegionClassifier.AdvanceSweep(Baseline: Boolean; Tick: UInt64;
  var Detected: TDetectionKinds);
var
  R: TVirtualRegion;
  Limit, Next: NativeUInt;
  I: Integer;
begin
  Limit := MaximumUserVirtualAddress;
  for I := 1 to MAX_REGIONS_PER_STEP do
  begin
    if FNextAddress > Limit then
    begin
      EndSweep(Baseline, Tick, Detected);
      Exit;
    end;
    if not QueryVirtualRegion(WinCurrentProcess, FNextAddress, R) then
    begin
      CancelSweep;
      Exit;
    end;
    Observe(R);
    if FOverflow or (R.Size > High(NativeUInt) - R.BaseAddress) then
    begin
      CancelSweep;
      Exit;
    end;
    Next := R.BaseAddress + R.Size;
    if Next <= FNextAddress then
    begin
      CancelSweep;
      Exit;
    end;
    FNextAddress := Next;
  end;
end;

procedure TMemoryRegionClassifier.Examine(Baseline: Boolean;
  Tick: UInt64; var Detected: TDetectionKinds);
begin
  FObservationFailed := False;
  if not AllocationNativeAvailable then
  begin
    CancelSweep;
    Exit;
  end;
  if not FRunning then
  begin
    if (FLastCompleteTick <> 0) and (Tick >= FLastCompleteTick) and
       (Tick - FLastCompleteTick < SWEEP_PAUSE_MS) then Exit;
    BeginSweep(Tick);
  end;
  if (Tick < FSweepStartTick) or
     (Tick - FSweepStartTick > MAX_SWEEP_DURATION_MS) then
  begin
    CancelSweep;
    Exit;
  end;
  try
    AdvanceSweep(Baseline, Tick, Detected);
  except
    CancelSweep;
    raise;
  end;
end;

{$IFDEF NHW_NATIVE10N_TESTS}
{$I Cozy.NHW.Native10N.RegionClassifier.inc}
{$ENDIF}

end.
