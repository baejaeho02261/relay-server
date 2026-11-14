unit Cozy.NHW.MappingGuard;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows, System.SysUtils, System.Generics.Collections,
  Cozy.NHW.AllocationNative, Cozy.NHW.Logging;

type
  TMappingSample = record
    Base: NativeUInt;
    RegionType: Cardinal; // MEM_IMAGE or MEM_MAPPED only
    MappedBytes: UInt64;
    ExecutableBytes: UInt64;
    ProbePage: NativeUInt;
    SharedKnown: Boolean;   // true only for resident, valid WS page
    Shared: Boolean;
    BackingKnown: Boolean;  // Query name success, not guessed from pointer
    Backing: string;
  end;

  TMappingSignal = (msNewView, msCOW, msPageSharing, msBacking,
    msExecutable);
  TMappingSignals = set of TMappingSignal;

  TMappingTrack = record
    Stable: TMappingSample;
    Pending: TMappingSample;
    PendingCount: Integer;
    HasStable: Boolean;
    MissingSweeps: Integer;
  end;

  TMappingGuard = class
  private
    FCurrent: TDictionary<NativeUInt, TMappingSample>;
    FTracked: TDictionary<NativeUInt, TMappingTrack>;
    FChanges: TList<UInt64>;
    FCompletedSweeps: Integer;
    FLastBurstTick: UInt64;
    FOverflow: Boolean;
    FBackingCursor, FPageCursor: NativeUInt;
    FBackingPasses, FPagePasses: Integer;
    procedure CountChange(Tick: UInt64; var Detected: TDetectionKinds);
    procedure PopulateMetadata(ProcessHandle: THandle);
    procedure PopulateBackingBatch(ProcessHandle: THandle;
      const Batch: TArray<NativeUInt>);
    procedure PopulatePageBatch(ProcessHandle: THandle;
      const Batch: TArray<NativeUInt>);
    procedure ReconcilePresentMappings(Tick: UInt64; Warmup: Boolean;
      var Detected: TDetectionKinds);
    procedure ReconcileMissingMappings(Tick: UInt64; Warmup: Boolean;
      var Detected: TDetectionKinds);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure BeginSweep;
    procedure CancelSweep;
    procedure ObserveRegion(const Region: TVirtualRegion);
    procedure EndSweep(ProcessHandle: THandle; Tick: UInt64;
      var Detected: TDetectionKinds);
  end;

function MappingSamplesEqual(const L, R: TMappingSample): Boolean;
function AnalyzeMappingTransition(const Before, After: TMappingSample;
  BeforeKnown: Boolean): TMappingSignals;

{$IFDEF NHW_NATIVE10M_TESTS}
function TestMappingGuard10M(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses Cozy.NHW.MappingNative;

{$IFDEF NHW_NATIVE10M_TESTS}
{$I Cozy.NHW.Native10M.MappingGuard.Hooks.inc}
{$ENDIF}

const
  MAX_MAPPING_GROUPS = 8192;
  MAX_BACKING_LOOKUPS = 64;
  MAX_WORKING_SET_PAGES = 192;
  BURST_WINDOW_MS = 15000;
  BURST_THRESHOLD = 5;
  BURST_COOLDOWN_MS = 12000;

function MappingSamplesEqual(const L, R: TMappingSample): Boolean;
begin
  Result := (L.Base = R.Base) and (L.RegionType = R.RegionType) and
    (L.MappedBytes = R.MappedBytes) and
    (L.ExecutableBytes = R.ExecutableBytes);
  if Result and L.BackingKnown and R.BackingKnown then
    Result := SameText(L.Backing, R.Backing);
  if Result and L.SharedKnown and R.SharedKnown and
     (L.ProbePage = R.ProbePage) then
    Result := L.Shared = R.Shared;
end;

function AnalyzeMappingTransition(const Before, After: TMappingSample;
  BeforeKnown: Boolean): TMappingSignals;
begin
  Result := [];
  if not BeforeKnown then
  begin
    if After.MappedBytes > 0 then Include(Result, msNewView);
    if After.ExecutableBytes > 0 then Include(Result, msExecutable);
    Exit;
  end;
  if (Before.Base <> After.Base) or
     (Before.RegionType <> After.RegionType) then Exit;
  if (After.ExecutableBytes > Before.ExecutableBytes) and
     (After.ExecutableBytes > 0) then Include(Result, msExecutable);
  if Before.BackingKnown and After.BackingKnown and
     not SameText(Before.Backing, After.Backing) then
    Include(Result, msBacking);
  // A change of Shared bit is NOT proof of an external write or exact COW.
  // Only compare the *same resident page* in both successful snapshots.
  if Before.SharedKnown and After.SharedKnown and
     (Before.ProbePage <> 0) and (Before.ProbePage = After.ProbePage) then
  begin
    if (Before.RegionType = ALLOC_MEM_IMAGE) and
       (Before.Shared <> After.Shared) then
      Include(Result, msPageSharing);
    if Before.Shared and not After.Shared then
      Include(Result, msCOW);
  end;
end;

constructor TMappingGuard.Create;
begin
  inherited Create;
  FCurrent := TDictionary<NativeUInt, TMappingSample>.Create;
  FTracked := TDictionary<NativeUInt, TMappingTrack>.Create;
  FChanges := TList<UInt64>.Create;
  Reset;
end;

destructor TMappingGuard.Destroy;
begin
  FChanges.Free;
  FTracked.Free;
  FCurrent.Free;
  inherited Destroy;
end;

procedure TMappingGuard.Reset;
begin
  FCurrent.Clear;
  FTracked.Clear;
  FChanges.Clear;
  FCompletedSweeps := 0;
  FBackingCursor := 0;
  FPageCursor := 0;
  FBackingPasses := 0;
  FPagePasses := 0;
  FLastBurstTick := 0;
  FOverflow := False;
end;

procedure TMappingGuard.BeginSweep;
begin
  FCurrent.Clear;
  FOverflow := False;
end;

procedure TMappingGuard.CancelSweep;
var Keys: TArray<NativeUInt>; Key: NativeUInt; Track: TMappingTrack;
begin
  // Incomplete scans cannot confirm a candidate or imply disappearance.
  FCurrent.Clear;
  FOverflow := False;
  FBackingPasses := 0;
  FPagePasses := 0;
  Keys := FTracked.Keys.ToArray;
  for Key in Keys do
    if FTracked.TryGetValue(Key, Track) then
    begin
      Track.PendingCount := 0;
      Track.Pending := Default(TMappingSample);
      Track.MissingSweeps := 0;
      FTracked.AddOrSetValue(Key, Track);
    end;
end;

procedure TMappingGuard.ObserveRegion(const Region: TVirtualRegion);
var
  S: TMappingSample;
  Area: UInt64;
begin
  if FOverflow then Exit;
  if (Region.State <> ALLOC_MEM_COMMIT) or
     ((Region.RegionType <> ALLOC_MEM_IMAGE) and
      (Region.RegionType <> ALLOC_MEM_MAPPED)) or
     (Region.AllocationBase < $10000) or (Region.Size = 0) then Exit;
  Area := UInt64(Region.Size);
  if not FCurrent.TryGetValue(Region.AllocationBase, S) then
  begin
    if FCurrent.Count >= MAX_MAPPING_GROUPS then
    begin
      // Prevent partially collected candidate maps from causing fake changes.
      FOverflow := True;
      FCurrent.Clear;
      Exit;
    end;
    S := Default(TMappingSample);
    S.Base := Region.AllocationBase;
    S.RegionType := Region.RegionType;
    S.ProbePage := Region.BaseAddress;
  end;
  if Area > High(UInt64) - S.MappedBytes then Exit;
  Inc(S.MappedBytes, Area);
  if RegionIsExecutable(Region) then Inc(S.ExecutableBytes, Area);
  FCurrent.AddOrSetValue(S.Base, S);
end;

function SelectMappingBatch(Keys: TList<NativeUInt>; AfterKey: NativeUInt;
  Budget: Integer): TArray<NativeUInt>;
var Start, Count, I: Integer;
begin
  Result := nil;
  if (Keys = nil) or (Budget <= 0) then Exit;
  if Keys.Count = 0 then Exit;
  Start := 0;
  while (Start < Keys.Count) and (Keys[Start] <= AfterKey) do Inc(Start);
  if Start = Keys.Count then Start := 0;
  Count := Keys.Count;
  if Count > Budget then Count := Budget;
  SetLength(Result, Count);
  for I := 0 to Count - 1 do Result[I] := Keys[(Start + I) mod Keys.Count];
end;

procedure AdvanceMappingBatch(const Batch: TArray<NativeUInt>;
  var Cursor: NativeUInt; var Passes: Integer);
begin
  if Length(Batch) = 0 then
  begin
    Passes := 0;
    Exit;
  end;
  // Two consecutive complete sweeps allow the existing two-confirmation
  // policy to see metadata changes. A failed query still consumes its slot.
  Inc(Passes);
  if Passes >= 2 then
  begin
    Cursor := Batch[High(Batch)];
    Passes := 0;
  end;
end;

procedure TMappingGuard.PopulateBackingBatch(ProcessHandle: THandle;
  const Batch: TArray<NativeUInt>);
var
  Key: NativeUInt;
  S: TMappingSample;
  Backing: string;
begin
  for Key in Batch do
  begin
    if not FCurrent.TryGetValue(Key, S) then Continue;
    if QueryMappingBacking(ProcessHandle, S.ProbePage, Backing) then
    begin
      S.BackingKnown := True;
      S.Backing := Backing;
      FCurrent.AddOrSetValue(Key, S);
    end;
  end;
end;

procedure TMappingGuard.PopulatePageBatch(ProcessHandle: THandle;
  const Batch: TArray<NativeUInt>);
var
  ItemBuffer: array[0..MAX_WORKING_SET_PAGES - 1] of TMappingWorkingSetItem;
  KeyBuffer: array[0..MAX_WORKING_SET_PAGES - 1] of NativeUInt;
  I, ItemCount: Integer;
  Key: NativeUInt;
  S: TMappingSample;
begin
  ItemCount := 0;
  for Key in Batch do
  begin
    if not FCurrent.TryGetValue(Key, S) then Continue;
    if S.ProbePage < $10000 then Continue;
    ItemBuffer[ItemCount].VirtualAddress := Pointer(S.ProbePage);
    ItemBuffer[ItemCount].Attributes := 0;
    KeyBuffer[ItemCount] := Key;
    Inc(ItemCount);
  end;
  if (ItemCount > 0) and
     QueryMappingWorkingSet(ProcessHandle, ItemBuffer, ItemCount) then
    for I := 0 to ItemCount - 1 do
    begin
      if not MappingPageResident(ItemBuffer[I]) then Continue;
      Key := KeyBuffer[I];
      if not FCurrent.TryGetValue(Key, S) then Continue;
      S.SharedKnown := True;
      S.Shared := MappingPageShared(ItemBuffer[I]);
      FCurrent.AddOrSetValue(Key, S);
    end;
end;

procedure TMappingGuard.PopulateMetadata(ProcessHandle: THandle);
var
  Keys: TList<NativeUInt>;
  BackingBatch, PageBatch: TArray<NativeUInt>;
  Key: NativeUInt;
begin
  if not MappingNativeAvailable then Exit;
  Keys := TList<NativeUInt>.Create;
  try
    for Key in FCurrent.Keys do Keys.Add(Key);
    Keys.Sort;
    BackingBatch := SelectMappingBatch(Keys, FBackingCursor, MAX_BACKING_LOOKUPS);
    PageBatch := SelectMappingBatch(Keys, FPageCursor, MAX_WORKING_SET_PAGES);
    PopulateBackingBatch(ProcessHandle, BackingBatch);
    AdvanceMappingBatch(BackingBatch, FBackingCursor, FBackingPasses);
    PopulatePageBatch(ProcessHandle, PageBatch);
    AdvanceMappingBatch(PageBatch, FPageCursor, FPagePasses);
  finally
    Keys.Free;
  end;
end;

procedure TMappingGuard.CountChange(Tick: UInt64;
  var Detected: TDetectionKinds);
var
  I: Integer;
begin
  FChanges.Add(Tick);
  for I := FChanges.Count - 1 downto 0 do
    if (Tick < FChanges[I]) or (Tick - FChanges[I] > BURST_WINDOW_MS) then
      FChanges.Delete(I);
  if (FChanges.Count >= BURST_THRESHOLD) and
     ((FLastBurstTick = 0) or
      ((Tick >= FLastBurstTick) and
       (Tick - FLastBurstTick >= BURST_COOLDOWN_MS))) then
  begin
    Include(Detected, dkMappingBurst);
    FLastBurstTick := Tick;
    FChanges.Clear;
  end;
end;

procedure TMappingGuard.ReconcilePresentMappings(Tick: UInt64; Warmup: Boolean;
  var Detected: TDetectionKinds);
var
  Pair: TPair<NativeUInt, TMappingSample>;
  Tracked: TMappingTrack;
  Current: TMappingSample;
  Signals: TMappingSignals;
begin
  for Pair in FCurrent do
  begin
    Current := Pair.Value;
    if not FTracked.TryGetValue(Pair.Key, Tracked) then
    begin
      Tracked := Default(TMappingTrack);
      Tracked.Pending := Current;
      Tracked.PendingCount := 1;
      if Warmup then
      begin
        Tracked.Stable := Current;
        Tracked.HasStable := True;
        Tracked.PendingCount := 0;
      end;
      FTracked.AddOrSetValue(Pair.Key, Tracked);
      Continue;
    end;
    Tracked.MissingSweeps := 0;
    if Warmup then
    begin
      Tracked.Stable := Current;
      Tracked.HasStable := True;
      Tracked.PendingCount := 0;
    end
    else if not Tracked.HasStable then
    begin
      if MappingSamplesEqual(Current, Tracked.Pending) then
        Inc(Tracked.PendingCount)
      else
      begin
        Tracked.Pending := Current;
        Tracked.PendingCount := 1;
      end;
      if Tracked.PendingCount >= 2 then
      begin
        // A newly mapped image/view is normal runtime behaviour (lazy DLLs,
        // COM/WMI providers, security software, mapped data, etc.).  Establish
        // it as a stable reference only.  Security reporting starts from a
        // confirmed transition of an already-established mapping.
        Tracked.HasStable := True;
        Tracked.Stable := Current;
        Tracked.PendingCount := 0;
      end;
    end
    else if MappingSamplesEqual(Current, Tracked.Stable) then
    begin
      Tracked.PendingCount := 0;
      // Newly available metadata is only a reference value, not a transition.
      if Current.BackingKnown and not Tracked.Stable.BackingKnown then
      begin
        Tracked.Stable.BackingKnown := True;
        Tracked.Stable.Backing := Current.Backing;
      end;
      if Current.SharedKnown and not Tracked.Stable.SharedKnown then
      begin
        Tracked.Stable.SharedKnown := True;
        Tracked.Stable.Shared := Current.Shared;
        Tracked.Stable.ProbePage := Current.ProbePage;
      end;
    end
    else
    begin
      if (Tracked.PendingCount > 0) and
         MappingSamplesEqual(Current, Tracked.Pending) then
        Inc(Tracked.PendingCount)
      else
      begin
        Tracked.Pending := Current;
        Tracked.PendingCount := 1;
      end;
      if Tracked.PendingCount >= 2 then
      begin
        Signals := AnalyzeMappingTransition(Tracked.Stable, Current, True);
        if msCOW in Signals then Include(Detected, dkCOW);
        if msPageSharing in Signals then Include(Detected, dkPageSharing);
        if msBacking in Signals then Include(Detected, dkMappingBacking);
        if msExecutable in Signals then Include(Detected, dkExecutableMapping);
        // Burst telemetry counts only confirmed security-relevant mapping
        // transitions.  Ordinary map/unmap lifecycle churn is not evidence.
        if Signals <> [] then CountChange(Tick, Detected);
        Tracked.Stable := Current;
        Tracked.PendingCount := 0;
      end;
    end;
    FTracked.AddOrSetValue(Pair.Key, Tracked);
  end;
end;

procedure TMappingGuard.ReconcileMissingMappings(Tick: UInt64; Warmup: Boolean;
  var Detected: TDetectionKinds);
var
  KnownPair: TPair<NativeUInt, TMappingTrack>;
  Tracked: TMappingTrack;
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
      if Warmup then
      begin
        FTracked.Remove(Base);
        Continue;
      end;
      Inc(Tracked.MissingSweeps);
      if Tracked.MissingSweeps >= 2 then
      begin
        // Normal DLL/view unloads are lifecycle telemetry, not detections.
        FTracked.Remove(Base);
      end
      else
        FTracked.AddOrSetValue(Base, Tracked);
    end;
  finally
    OldKeys.Free;
  end;
end;

procedure TMappingGuard.EndSweep(ProcessHandle: THandle; Tick: UInt64;
  var Detected: TDetectionKinds);
var
  Warmup: Boolean;
begin
  if FOverflow then
  begin
    CancelSweep;
    Exit;
  end;
  try
    PopulateMetadata(ProcessHandle);
  except
    CancelSweep;
    raise;
  end;
  Warmup := FCompletedSweeps < 2;
  ReconcilePresentMappings(Tick, Warmup, Detected);

  ReconcileMissingMappings(Tick, Warmup, Detected);
  if FCompletedSweeps < High(Integer) then Inc(FCompletedSweeps);
end;

{$IFDEF NHW_NATIVE10M_TESTS}
{$I Cozy.NHW.Native10M.MappingGuard.inc}
{$ENDIF}

end.
