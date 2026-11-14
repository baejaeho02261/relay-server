unit Cozy.NHW.AllocationGuard;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, System.SysUtils, System.Generics.Collections,
  Cozy.NHW.AllocationNative, Cozy.NHW.Logging, Cozy.NHW.MappingGuard, Cozy.NHW.ProtectionGuard;

type
  // Aggregated metadata for one MEM_PRIVATE virtual-address reservation.
  // Contains no page bytes and no pointers to owned/private memory.
  TAllocationSample = record
    Base: NativeUInt;
    ReservedBytes: UInt64;
    CommittedBytes: UInt64;
    ExecutableBytes: UInt64;
    RWXBytes: UInt64;
    RegionSignature: UInt64;
  end;

  TAllocationSignal = (asAllocation, asCommit, asExecute, asRWX, asRelease);
  TAllocationSignals = set of TAllocationSignal;

  TAllocationTrack = record
    Stable: TAllocationSample;
    Pending: TAllocationSample;
    PendingCount: Integer;
    HasStable: Boolean;
    MissingSweeps: Integer;
    ObservationEpoch: UInt64;
  end;

  TVirtualAllocationGuard = class
  private
    // Last Examine only: known failed collection, not a throttled/pending pass.
    FObservationFailed: Boolean;
    FMappingObserver: TMappingGuard;
    FProtectionObserver: TProtectionGuard;
    FExcludedAddress: NativeUInt;
    FExcludedWriteAddress: NativeUInt;
    FCurrent: TDictionary<NativeUInt, TAllocationSample>;
    FTracked: TDictionary<NativeUInt, TAllocationTrack>;
    FBurstTicks: TList<UInt64>;
    FNextAddress: NativeUInt;
    FSweepStartTick: UInt64;
    FLastBurstTick: UInt64;
    FCompletedSweeps: Integer;
    FRunning: Boolean;
    FNextSweepTick: UInt64;
    FRegionCount: Integer;
    FObservationEpoch: UInt64;
    procedure AddRegion(const Region: TVirtualRegion);
    procedure AccumulatePrivateRegion(const Region: TVirtualRegion);
    procedure ReconcilePresentAllocations(Tick: UInt64;
      IsWarmup: Boolean; var Detected: TDetectionKinds);
    procedure ReconcileMissingAllocations(ProcessHandle: THandle;
      Tick: UInt64; IsWarmup: Boolean; var Detected: TDetectionKinds);
    procedure FinishSweep(ProcessHandle: THandle; Tick: UInt64;
      var Detected: TDetectionKinds);
    procedure CountChange(Tick: UInt64; var Detected: TDetectionKinds);
    procedure StartSweep(Tick: UInt64);
    procedure CancelSweep(Tick: UInt64);
    procedure RefreshTrack(var Track: TAllocationTrack);
  public
    property ObservationFailed: Boolean read FObservationFailed;
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Examine(TargetPID: Cardinal; Tick: UInt64;
      var Detected: TDetectionKinds);
    property MappingObserver: TMappingGuard read FMappingObserver write FMappingObserver;
    property ProtectionObserver: TProtectionGuard read FProtectionObserver write FProtectionObserver;
    // Exclude the single isolated PAGE_GUARD test page, so the guard's
    // intentional re-arming is not misreported as v24 memory tampering.
    property ExcludedAddress: NativeUInt read FExcludedAddress write FExcludedAddress;
    property ExcludedWriteAddress: NativeUInt read FExcludedWriteAddress write FExcludedWriteAddress;
  end;

function AllocationSamplesEqual(const L, R: TAllocationSample): Boolean;
function AnalyzeAllocationTransition(const Before, After: TAllocationSample;
  BeforeKnown: Boolean): TAllocationSignals;

{$IFDEF NHW_NATIVE10N_TESTS}
function TestAllocationGuard10N(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses Cozy.NHW.Types, Cozy.NHW.Native, Cozy.NHW.WinPointers;

const
  MAX_QUERIES_PER_STEP = 160;
  MAX_METADATA_REGIONS = 32768;
  MAX_SWEEP_TIME_MS = 20000;
  SWEEP_GAP_MS = 1000;
  LARGE_ALLOCATION_BYTES = 1024 * 1024;
  COMMIT_CHANGE_BYTES = 64 * 1024;
  BURST_WINDOW_MS = 5000;
  BURST_THRESHOLD = 4;
  BURST_COOLDOWN_MS = 6000;
  REGION_FNV_PRIME: UInt64 = $00000100000001B3;

function AllocationSamplesEqual(const L, R: TAllocationSample): Boolean;
begin
  Result := (L.Base = R.Base) and
    (L.ReservedBytes = R.ReservedBytes) and
    (L.CommittedBytes = R.CommittedBytes) and
    (L.ExecutableBytes = R.ExecutableBytes) and
    (L.RWXBytes = R.RWXBytes) and
    (L.RegionSignature = R.RegionSignature);
end;

function AnalyzeAllocationTransition(const Before, After: TAllocationSample;
  BeforeKnown: Boolean): TAllocationSignals;
begin
  Result := [];
  if not BeforeKnown then
  begin
    if After.ReservedBytes >= LARGE_ALLOCATION_BYTES then
      Include(Result, asAllocation);
    if After.RWXBytes > 0 then Include(Result, asRWX);
    Exit;
  end;
  if After.Base <> Before.Base then Exit;
  if (After.ReservedBytes >= Before.ReservedBytes) and
     (After.ReservedBytes - Before.ReservedBytes >= LARGE_ALLOCATION_BYTES) then
    Include(Result, asAllocation);
  if (After.CommittedBytes >= Before.CommittedBytes) and
     (After.CommittedBytes - Before.CommittedBytes >= COMMIT_CHANGE_BYTES) then
    Include(Result, asCommit);
  // Conservative protection-change inference: both snapshots must have
  // unchanged commit size; an executable *new commit* is not called PROTECT.
  if (After.CommittedBytes = Before.CommittedBytes) and
     (After.ExecutableBytes > Before.ExecutableBytes) then
    Include(Result, asExecute);
  if (After.RWXBytes > Before.RWXBytes) and (After.RWXBytes > 0) then
    Include(Result, asRWX);
  if (Before.CommittedBytes >= After.CommittedBytes) and
     (Before.CommittedBytes - After.CommittedBytes >= COMMIT_CHANGE_BYTES) then
    Include(Result, asRelease);
end;

constructor TVirtualAllocationGuard.Create;
begin
  inherited Create;
  FCurrent := TDictionary<NativeUInt, TAllocationSample>.Create;
  FTracked := TDictionary<NativeUInt, TAllocationTrack>.Create;
  FBurstTicks := TList<UInt64>.Create;
  Reset;
end;

destructor TVirtualAllocationGuard.Destroy;
begin
  FBurstTicks.Free;
  FTracked.Free;
  FCurrent.Free;
  inherited Destroy;
end;

procedure TVirtualAllocationGuard.Reset;
begin
  FObservationFailed := False;
  if FMappingObserver <> nil then FMappingObserver.Reset;
  if FProtectionObserver <> nil then FProtectionObserver.Reset;
  FCurrent.Clear;
  FTracked.Clear;
  FBurstTicks.Clear;
  FExcludedAddress := 0;
  FExcludedWriteAddress := 0;
  FNextAddress := $10000;
  FSweepStartTick := 0;
  FLastBurstTick := 0;
  FCompletedSweeps := 0;
  FNextSweepTick := 0;
  FRunning := False;
  FRegionCount := 0;
  FObservationEpoch := 1;
end;

procedure TVirtualAllocationGuard.StartSweep(Tick: UInt64);
begin
  if FMappingObserver <> nil then FMappingObserver.BeginSweep;
  if FProtectionObserver <> nil then FProtectionObserver.BeginSweep;
  FCurrent.Clear;
  FSweepStartTick := Tick;
  FNextAddress := $10000;
  FRegionCount := 0;
  FRunning := True;
end;

procedure TVirtualAllocationGuard.RefreshTrack(var Track: TAllocationTrack);
begin
  if Track.ObservationEpoch = FObservationEpoch then Exit;
  Track.Pending := Default(TAllocationSample);
  Track.PendingCount := 0;
  Track.MissingSweeps := 0;
  Track.ObservationEpoch := FObservationEpoch;
end;

procedure TVirtualAllocationGuard.CancelSweep(Tick: UInt64);
begin
  FObservationFailed := True;
  FRunning := False;
  FCurrent.Clear;
  FBurstTicks.Clear;
  // Lazy invalidation avoids allocating a key array on the failure path.
  // Every subsequent tracked value crosses RefreshTrack before it is used.
  if FObservationEpoch = High(UInt64) then
  begin
    FTracked.Clear; // unreachable in practice; never reuse an ancient epoch
    FObservationEpoch := 1;
  end
  else Inc(FObservationEpoch);
  if Tick > High(UInt64) - SWEEP_GAP_MS then
    FNextSweepTick := High(UInt64)
  else
    FNextSweepTick := Tick + SWEEP_GAP_MS;
  if FMappingObserver <> nil then FMappingObserver.CancelSweep;
  if FProtectionObserver <> nil then FProtectionObserver.CancelSweep;
end;

procedure TVirtualAllocationGuard.AccumulatePrivateRegion(const Region: TVirtualRegion);
var
  Sample: TAllocationSample;
  Area: UInt64;
begin
  if not RegionIsPrivate(Region) then Exit;
  if (Region.AllocationBase < $10000) or (Region.Size = 0) then Exit;
  Area := UInt64(Region.Size);
  if not FCurrent.TryGetValue(Region.AllocationBase, Sample) then
  begin
    Sample := Default(TAllocationSample);
    Sample.Base := Region.AllocationBase;
    Sample.RegionSignature := $CBF29CE484222325;
  end;
  if Area > High(UInt64) - Sample.ReservedBytes then Exit;
  Inc(Sample.ReservedBytes, Area);
  if Region.State = ALLOC_MEM_COMMIT then
  begin
    Inc(Sample.CommittedBytes, Area);
    if RegionIsExecutable(Region) then
      Inc(Sample.ExecutableBytes, Area);
    if RegionIsRWX(Region) then Inc(Sample.RWXBytes, Area);
  end;
  // Stable, order-dependent summary of each region's metadata. This is a
  // comparison fingerprint, not a cryptographic integrity signature.
  Sample.RegionSignature :=
    (Sample.RegionSignature xor UInt64(Region.BaseAddress)) * REGION_FNV_PRIME;
  Sample.RegionSignature :=
    (Sample.RegionSignature xor UInt64(Region.Size)) * REGION_FNV_PRIME;
  Sample.RegionSignature :=
    (Sample.RegionSignature xor UInt64(Region.State)) * REGION_FNV_PRIME;
  Sample.RegionSignature :=
    (Sample.RegionSignature xor UInt64(Region.Protect)) * REGION_FNV_PRIME;
  FCurrent.AddOrSetValue(Region.AllocationBase, Sample);
end;

procedure TVirtualAllocationGuard.AddRegion(const Region: TVirtualRegion);
begin
  if (FExcludedAddress <> 0) and
     ((Region.AllocationBase = FExcludedAddress) or
      ((Region.BaseAddress <= FExcludedAddress) and
       (Region.Size > 0) and
       (FExcludedAddress - Region.BaseAddress < Region.Size))) then Exit;
  if (FExcludedWriteAddress <> 0) and
     ((Region.AllocationBase = FExcludedWriteAddress) or
      ((Region.BaseAddress <= FExcludedWriteAddress) and
       (Region.Size > 0) and
       (FExcludedWriteAddress - Region.BaseAddress < Region.Size))) then Exit;
  if FMappingObserver <> nil then FMappingObserver.ObserveRegion(Region);
  if FProtectionObserver <> nil then FProtectionObserver.ObserveRegion(Region);
  AccumulatePrivateRegion(Region);
end;

procedure TVirtualAllocationGuard.CountChange(Tick: UInt64;
  var Detected: TDetectionKinds);
var
  I: Integer;
begin
  FBurstTicks.Add(Tick);
  for I := FBurstTicks.Count - 1 downto 0 do
    if (Tick < FBurstTicks[I]) or
       (Tick - FBurstTicks[I] > BURST_WINDOW_MS) then
      FBurstTicks.Delete(I);
  if (FBurstTicks.Count >= BURST_THRESHOLD) and
     ((FLastBurstTick = 0) or
      ((Tick >= FLastBurstTick) and
       (Tick - FLastBurstTick >= BURST_COOLDOWN_MS))) then
  begin
    Include(Detected, dkAllocationBurst);
    FLastBurstTick := Tick;
    FBurstTicks.Clear;
  end;
end;

procedure TVirtualAllocationGuard.ReconcilePresentAllocations(Tick: UInt64;
  IsWarmup: Boolean; var Detected: TDetectionKinds);
var
  Pair: TPair<NativeUInt, TAllocationSample>;
  Tracked: TAllocationTrack;
  Current: TAllocationSample;
  Signals: TAllocationSignals;
begin
  for Pair in FCurrent do
  begin
    Current := Pair.Value;
    if not FTracked.TryGetValue(Pair.Key, Tracked) then
    begin
      Tracked := Default(TAllocationTrack);
      Tracked.ObservationEpoch := FObservationEpoch;
      Tracked.Pending := Current;
      Tracked.PendingCount := 1;
      if IsWarmup then
      begin
        Tracked.Stable := Current;
        Tracked.HasStable := True;
        Tracked.PendingCount := 0;
      end;
      FTracked.AddOrSetValue(Pair.Key, Tracked);
      Continue;
    end;
    RefreshTrack(Tracked);
    Tracked.MissingSweeps := 0;
    if IsWarmup then
    begin
      Tracked.Stable := Current;
      Tracked.HasStable := True;
      Tracked.PendingCount := 0;
    end
    else if not Tracked.HasStable then
    begin
      if AllocationSamplesEqual(Current, Tracked.Pending) then
        Inc(Tracked.PendingCount)
      else
      begin
        Tracked.Pending := Current;
        Tracked.PendingCount := 1;
      end;
      if Tracked.PendingCount >= 2 then
      begin
        Tracked.HasStable := True;
        Tracked.Stable := Current;
        Signals := AnalyzeAllocationTransition(Default(TAllocationSample),
          Current, False);
        if asAllocation in Signals then Include(Detected, dkAllocation);
        if asRWX in Signals then Include(Detected, dkRWX);
        if Signals <> [] then CountChange(Tick, Detected);
        Tracked.PendingCount := 0;
      end;
    end
    else if AllocationSamplesEqual(Current, Tracked.Stable) then
      Tracked.PendingCount := 0
    else
    begin
      if (Tracked.PendingCount > 0) and
         AllocationSamplesEqual(Current, Tracked.Pending) then
        Inc(Tracked.PendingCount)
      else
      begin
        Tracked.Pending := Current;
        Tracked.PendingCount := 1;
      end;
      if Tracked.PendingCount >= 2 then
      begin
        Signals := AnalyzeAllocationTransition(Tracked.Stable,
          Current, True);
        if asAllocation in Signals then Include(Detected, dkAllocation);
        if asCommit in Signals then Include(Detected, dkCommit);
        if asExecute in Signals then Include(Detected, dkExecuteProtect);
        if asRWX in Signals then Include(Detected, dkRWX);
        if asRelease in Signals then Include(Detected, dkMemoryRelease);
        if Signals <> [] then CountChange(Tick, Detected);
        Tracked.Stable := Current;
        Tracked.PendingCount := 0;
      end;
    end;
    FTracked.AddOrSetValue(Pair.Key, Tracked);
  end;

end;

procedure TVirtualAllocationGuard.ReconcileMissingAllocations(ProcessHandle: THandle;
  Tick: UInt64; IsWarmup: Boolean; var Detected: TDetectionKinds);
var
  KnownPair: TPair<NativeUInt, TAllocationTrack>;
  Tracked: TAllocationTrack;
  OldKeys: TList<NativeUInt>;
  I: Integer;
  Base: NativeUInt;
begin
  OldKeys := TList<NativeUInt>.Create;
  try
    for KnownPair in FTracked do
      if not FCurrent.ContainsKey(KnownPair.Key) then
        OldKeys.Add(KnownPair.Key);
    for I := 0 to OldKeys.Count - 1 do
    begin
      Base := OldKeys[I];
      if not FTracked.TryGetValue(Base, Tracked) then Continue;
      RefreshTrack(Tracked);
      if IsWarmup then
      begin
        FTracked.Remove(Base);
        Continue;
      end;
      Tracked.Pending := Default(TAllocationSample);
      Tracked.PendingCount := 0;
      if Tracked.MissingSweeps < 2 then Inc(Tracked.MissingSweeps);
      if Tracked.MissingSweeps >= 2 then
      begin
        if Tracked.HasStable and
           (Tracked.Stable.ReservedBytes >= LARGE_ALLOCATION_BYTES) and
           ConfirmFreeAddress(ProcessHandle, Base) then
        begin
          Include(Detected, dkMemoryRelease);
          CountChange(Tick, Detected);
        end;
        FTracked.Remove(Base);
      end
      else
        FTracked.AddOrSetValue(Base, Tracked);
    end;
  finally
    OldKeys.Free;
  end;
end;

procedure TVirtualAllocationGuard.FinishSweep(ProcessHandle: THandle;
  Tick: UInt64; var Detected: TDetectionKinds);
var
  IsWarmup: Boolean;
begin
  IsWarmup := FCompletedSweeps < 2;
  ReconcilePresentAllocations(Tick, IsWarmup, Detected);
  ReconcileMissingAllocations(ProcessHandle, Tick, IsWarmup, Detected);
  if FMappingObserver <> nil then
    FMappingObserver.EndSweep(ProcessHandle, Tick, Detected);
  if FProtectionObserver <> nil then
    FProtectionObserver.EndSweep(Tick, Detected);
  if FCompletedSweeps < High(Integer) then Inc(FCompletedSweeps);
end;

procedure TVirtualAllocationGuard.Examine(TargetPID: Cardinal;
  Tick: UInt64; var Detected: TDetectionKinds);
var
  ProcessHandle: THandle;
  OwnHandle: Boolean;
  MaxAddr, NextAddr: NativeUInt;
  Region: TVirtualRegion;
  I: Integer;
  Completed: Boolean;
  StepDetected: TDetectionKinds;
begin
  FObservationFailed := False;
  if not AllocationNativeAvailable then
  begin
    CancelSweep(Tick);
    Exit;
  end;
  if not FRunning and (Tick < FNextSweepTick) then Exit;
  OwnHandle := False;
  ProcessHandle := 0;
  try
    try
      if not FRunning then StartSweep(Tick);
      if (Tick < FSweepStartTick) or
         (Tick - FSweepStartTick > MAX_SWEEP_TIME_MS) then
      begin
        CancelSweep(Tick);
        Exit;
      end;
      if TargetPID = WinCurrentProcessId then
        ProcessHandle := WinCurrentProcess
      else
      begin
        ProcessHandle := OpenNativeProcess(TargetPID, ACCESS_QUERY_INFORMATION);
        OwnHandle := ProcessHandle <> 0;
      end;
      if ProcessHandle = 0 then
      begin
        CancelSweep(Tick);
        Exit;
      end;
      MaxAddr := MaximumUserVirtualAddress;
      Completed := False;
      for I := 1 to MAX_QUERIES_PER_STEP do
      begin
        if FNextAddress > MaxAddr then
        begin
          Completed := True;
          Break;
        end;
        if not QueryVirtualRegion(ProcessHandle, FNextAddress, Region) then
        begin
          CancelSweep(Tick);
          Exit;
        end;
        Inc(FRegionCount);
        if (FRegionCount > MAX_METADATA_REGIONS) or
           (Region.Size = 0) or
           (Region.Size > High(NativeUInt) - Region.BaseAddress) then
        begin
          CancelSweep(Tick);
          Exit;
        end;
        NextAddr := Region.BaseAddress + Region.Size;
        if (Region.BaseAddress > FNextAddress) or (NextAddr <= FNextAddress) then
        begin
          CancelSweep(Tick);
          Exit;
        end;
        AddRegion(Region);
        if NextAddr > MaxAddr then
        begin
          Completed := True;
          Break;
        end;
        FNextAddress := NextAddr;
      end;
      if Completed then
      begin
        StepDetected := [];
        FinishSweep(ProcessHandle, Tick, StepDetected);
        Detected := Detected + StepDetected;
        FCurrent.Clear;
        FRunning := False;
        if Tick > High(UInt64) - SWEEP_GAP_MS then
          FNextSweepTick := High(UInt64)
        else
          FNextSweepTick := Tick + SWEEP_GAP_MS;
      end;
    except
      CancelSweep(Tick);
      raise; // Let the existing sensor fault-isolation layer record the failure.
    end;
  finally
    if OwnHandle then CloseNativeProcess(ProcessHandle);
  end;
end;

{$IFDEF NHW_NATIVE10N_TESTS}
{$I Cozy.NHW.Native10N.AllocationGuard.inc}
{$ENDIF}

end.
