unit Cozy.NHW.ProtectionGuard;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Generics.Collections,
  Cozy.NHW.AllocationNative,
  Cozy.NHW.Logging;

type
  // Only read-only address-space metadata, never page contents.
  TProtectionSample = record
    Page: NativeUInt;
    AllocationBase: NativeUInt;
    RegionType: Cardinal;
    State: Cardinal;
    Protect: Cardinal;
  end;

  TProtectionSignal = (psTransition, psCycle, psImage,
    psGuard, psNoAccess);
  TProtectionSignals = set of TProtectionSignal;

  TProtectionTrack = record
    Stable: TProtectionSample;
    Pending: TProtectionSample;
    Confirmations: Integer;
    LastSeenSweep: UInt64;
    LastSeenTick: UInt64;
    CycleStage: Byte;
    CycleStartTick: UInt64;
  end;

  TBurstChange = record
    AllocationBase: NativeUInt;
    Tick: UInt64;
  end;

  TProtectionGuard = class
  private
    FCurrent: TDictionary<NativeUInt, TProtectionSample>;
    FTracks: TDictionary<NativeUInt, TProtectionTrack>;
    FRecentChanges: TList<TBurstChange>;
    FOverflow: Boolean;
    FContinuityBroken: Boolean;
    FSweepOpen: Boolean;
    FSweepNumber: UInt64;
    FLastBurstTick: UInt64;
    procedure PutPage(Page: NativeUInt; const Region: TVirtualRegion);
    procedure RecordChangedAllocation(Base: NativeUInt; Tick: UInt64;
      var Detected: TDetectionKinds);
    procedure CommitObservedPages(Tick: UInt64; BrokenBefore: Boolean;
      var Detected: TDetectionKinds);
    procedure PruneAbsentPages;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure BeginSweep;
    procedure CancelSweep;
    procedure ObserveRegion(const Region: TVirtualRegion);
    procedure EndSweep(Tick: UInt64; var Detected: TDetectionKinds);
  end;

function NormalizePageProtection(Value: Cardinal): Cardinal;
function AnalyzeProtectionTransition(const Before, After: TProtectionSample):
  TProtectionSignals;
function ProtectionIsRW(Protect: Cardinal): Boolean;
function ProtectionIsRX(Protect: Cardinal): Boolean;

{$IFDEF NHW_NATIVE5L_TESTS}
function TestProtectionGuard5L(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

const
  PAGE_BYTES = $1000;
  PROBE_STRIDE = $20000;  // one regular sample every 128 KiB
  MAX_PROBES = 32768;
  COMPARE_MAX_GAP_MS = 30000;
  CYCLE_WINDOW_MS = 20000;
  BURST_WINDOW_MS = 7000;
  BURST_THRESHOLD = 4;  // distinct allocation bases, not number of pages
  BURST_COOLDOWN_MS = 9000;
  PAGE_NOACCESS_LOCAL = $01;
  PAGE_READWRITE_LOCAL = $04;
  PAGE_WRITECOPY_LOCAL = $08;
  PAGE_EXECUTE_LOCAL = $10;
  PAGE_EXECUTE_READ_LOCAL = $20;
  PAGE_EXECUTE_READWRITE_LOCAL = $40;
  PAGE_EXECUTE_WRITECOPY_LOCAL = $80;
  PAGE_GUARD_LOCAL = $100;

function NormalizePageProtection(Value: Cardinal): Cardinal;
begin
  // Ignore cache and CFG modifier bits, retain PAGE_GUARD.
  Result := Value and $1FF;
end;

function ProtectionIsRW(Protect: Cardinal): Boolean;
begin
  Result := ((Protect and PAGE_GUARD_LOCAL) = 0) and
    (((Protect and $FF) = PAGE_READWRITE_LOCAL) or
     ((Protect and $FF) = PAGE_WRITECOPY_LOCAL));
end;

function ProtectionIsRX(Protect: Cardinal): Boolean;
begin
  Result := ((Protect and PAGE_GUARD_LOCAL) = 0) and
    (((Protect and $FF) = PAGE_EXECUTE_LOCAL) or
     ((Protect and $FF) = PAGE_EXECUTE_READ_LOCAL));
end;

function IsExecutable(Protect: Cardinal): Boolean;
begin
  Result := ((Protect and PAGE_GUARD_LOCAL) = 0) and
    (((Protect and $FF) = PAGE_EXECUTE_LOCAL) or
     ((Protect and $FF) = PAGE_EXECUTE_READ_LOCAL) or
     ((Protect and $FF) = PAGE_EXECUTE_READWRITE_LOCAL) or
     ((Protect and $FF) = PAGE_EXECUTE_WRITECOPY_LOCAL));
end;

function Comparable(const Before, After: TProtectionSample): Boolean;
begin
  Result := (Before.Page = After.Page) and
    (Before.AllocationBase = After.AllocationBase) and
    (Before.RegionType = After.RegionType) and
    (Before.State = ALLOC_MEM_COMMIT) and
    (After.State = ALLOC_MEM_COMMIT);
end;

function AnalyzeProtectionTransition(const Before, After: TProtectionSample):
  TProtectionSignals;
var
  PreviousProtection, CurrentProtection: Cardinal;
begin
  Result := [];
  if not Comparable(Before, After) then Exit;
  PreviousProtection := NormalizePageProtection(Before.Protect);
  CurrentProtection := NormalizePageProtection(After.Protect);
  if PreviousProtection = CurrentProtection then Exit;
  if ProtectionIsRW(PreviousProtection) and
     IsExecutable(CurrentProtection) then
    Include(Result, psTransition);
  if (Before.RegionType = ALLOC_MEM_IMAGE) and
     (After.RegionType = ALLOC_MEM_IMAGE) then
    Include(Result, psImage);
  if ((PreviousProtection xor CurrentProtection) and PAGE_GUARD_LOCAL) <> 0 then
    Include(Result, psGuard);
  if ((PreviousProtection and $FF) = PAGE_NOACCESS_LOCAL) xor
     ((CurrentProtection and $FF) = PAGE_NOACCESS_LOCAL) then
    Include(Result, psNoAccess);
end;

function IsSuspiciousNoAccessTransition(const Before, After: TProtectionSample): Boolean;
var
  PreviousProtection, CurrentProtection: Cardinal;
begin
  Result := False;
  if not Comparable(Before, After) or
     (Before.RegionType <> ALLOC_MEM_IMAGE) then Exit;
  PreviousProtection := NormalizePageProtection(Before.Protect);
  CurrentProtection := NormalizePageProtection(After.Protect);
  // Heap, stack, VM reservations and guard-page transitions commonly use
  // PAGE_NOACCESS. Only an executable image-page transition is even a
  // candidate for this security output; independent causal evidence is
  // still required by the server before revoking a session.
  if ((PreviousProtection or CurrentProtection) and PAGE_GUARD_LOCAL) <> 0 then Exit;
  Result := (((PreviousProtection and $FF) = PAGE_NOACCESS_LOCAL) xor
             ((CurrentProtection and $FF) = PAGE_NOACCESS_LOCAL)) and
    (IsExecutable(PreviousProtection) or IsExecutable(CurrentProtection));
end;

constructor TProtectionGuard.Create;
begin
  inherited Create;
  FCurrent := TDictionary<NativeUInt, TProtectionSample>.Create;
  FTracks := TDictionary<NativeUInt, TProtectionTrack>.Create;
  FRecentChanges := TList<TBurstChange>.Create;
  Reset;
end;

destructor TProtectionGuard.Destroy;
begin
  FRecentChanges.Free;
  FTracks.Free;
  FCurrent.Free;
  inherited Destroy;
end;

procedure TProtectionGuard.Reset;
begin
  FCurrent.Clear;
  FTracks.Clear;
  FRecentChanges.Clear;
  FOverflow := False;
  FContinuityBroken := False;
  FSweepOpen := False;
  FSweepNumber := 0;
  FLastBurstTick := 0;
end;

procedure TProtectionGuard.BeginSweep;
begin
  if FSweepOpen then CancelSweep; // Abandoning an unfinished scan is a gap.
  FCurrent.Clear;
  FOverflow := False;
  FSweepOpen := True;
end;

procedure TProtectionGuard.CancelSweep;
begin
  // Keep accepted per-page baselines; invalidate unconfirmed history lazily
  // on the next complete sweep without allocating during failure cleanup.
  FContinuityBroken := True;
  FSweepOpen := False;
  FCurrent.Clear;
  FRecentChanges.Clear;
  FOverflow := False;
end;

procedure TProtectionGuard.PutPage(Page: NativeUInt;
  const Region: TVirtualRegion);
var
  Sample: TProtectionSample;
begin
  if FOverflow or (Page < $10000) then Exit;
  if FCurrent.ContainsKey(Page) then Exit;
  if FCurrent.Count >= MAX_PROBES then
  begin
    FOverflow := True;
    FCurrent.Clear;
    Exit;
  end;
  Sample := Default(TProtectionSample);
  Sample.Page := Page;
  Sample.AllocationBase := Region.AllocationBase;
  Sample.RegionType := Region.RegionType;
  Sample.State := Region.State;
  Sample.Protect := NormalizePageProtection(Region.Protect);
  FCurrent.Add(Page, Sample);
end;

procedure TProtectionGuard.ObserveRegion(const Region: TVirtualRegion);
var
  EndAddress, Page, GridPage, IncBy: NativeUInt;
begin
  if FOverflow or (Region.State <> ALLOC_MEM_COMMIT) or
     (Region.AllocationBase < $10000) or
     (Region.Size < PAGE_BYTES) or
     (Region.BaseAddress > High(NativeUInt) - Region.Size) then Exit;
  EndAddress := Region.BaseAddress + Region.Size;
  Page := Region.BaseAddress;
  if (Page and (PAGE_BYTES - 1)) <> 0 then
  begin
    if Page > High(NativeUInt) - (PAGE_BYTES - 1) then Exit;
    Page := (Page + PAGE_BYTES - 1) and (not NativeUInt(PAGE_BYTES - 1));
  end;
  if Page >= EndAddress then Exit;
  PutPage(Page, Region);
  if FOverflow then Exit;
  if Page > High(NativeUInt) - (PROBE_STRIDE - 1) then Exit;
  GridPage := (Page + PROBE_STRIDE - 1) and
    (not NativeUInt(PROBE_STRIDE - 1));
  IncBy := PROBE_STRIDE;
  while (GridPage < EndAddress) and (not FOverflow) do
  begin
    PutPage(GridPage, Region);
    if (GridPage > High(NativeUInt) - IncBy) then Break;
    Inc(GridPage, IncBy);
  end;
end;

procedure TProtectionGuard.RecordChangedAllocation(Base: NativeUInt;
  Tick: UInt64; var Detected: TDetectionKinds);
var
  I: Integer;
  Event: TBurstChange;
begin
  for I := FRecentChanges.Count - 1 downto 0 do
    if (Tick < FRecentChanges[I].Tick) or
       (Tick - FRecentChanges[I].Tick > BURST_WINDOW_MS) then
      FRecentChanges.Delete(I);
  // Multiple 128-KiB probes in one allocation are ONE burst event.
  for I := 0 to FRecentChanges.Count - 1 do
    if FRecentChanges[I].AllocationBase = Base then Exit;
  Event.AllocationBase := Base;
  Event.Tick := Tick;
  FRecentChanges.Add(Event);
  if (FRecentChanges.Count >= BURST_THRESHOLD) and
     ((FLastBurstTick = 0) or
      ((Tick >= FLastBurstTick) and
       (Tick - FLastBurstTick >= BURST_COOLDOWN_MS))) then
  begin
    Include(Detected, dkProtectBurst);
    FLastBurstTick := Tick;
    FRecentChanges.Clear;
  end;
end;

procedure TProtectionGuard.CommitObservedPages(Tick: UInt64; BrokenBefore: Boolean;
  var Detected: TDetectionKinds);
var
  Pair: TPair<NativeUInt, TProtectionSample>;
  Track: TProtectionTrack;
  Signals: TProtectionSignals;
  Item: TProtectionSample;
  PreviousProtect, CurrentProtect: Cardinal;
begin
  for Pair in FCurrent do
  begin
    Item := Pair.Value;
    if not FTracks.TryGetValue(Pair.Key, Track) then
    begin
      Track := Default(TProtectionTrack);
      Track.Stable := Item;
      Track.LastSeenSweep := FSweepNumber;
      Track.LastSeenTick := Tick;
      FTracks.Add(Pair.Key, Track);
      Continue;
    end;
    if BrokenBefore then
    begin
      Track.Pending := Default(TProtectionSample);
      Track.Confirmations := 0;
      Track.CycleStage := 0;
      Track.CycleStartTick := 0;
    end;
    if (Track.LastSeenSweep + 1 <> FSweepNumber) or
       (Tick < Track.LastSeenTick) or
       (Tick - Track.LastSeenTick > COMPARE_MAX_GAP_MS) or
       (not Comparable(Track.Stable, Item)) then
    begin
      // A gap or different backing allocation cannot prove protection change.
      Track.Stable := Item;
      Track.Pending := Default(TProtectionSample);
      Track.Confirmations := 0;
      Track.CycleStage := 0;
      Track.CycleStartTick := 0;
    end
    else if FSweepNumber <= 2 then
    begin
      Track.Stable := Item;
      Track.Confirmations := 0;
    end
    else if Track.Stable.Protect = Item.Protect then
      Track.Confirmations := 0
    else
    begin
      if (Track.Confirmations > 0) and
         (Track.Pending.Protect = Item.Protect) then
      begin
        if Track.Confirmations < 2 then Inc(Track.Confirmations);
      end
      else
      begin
        Track.Pending := Item;
        Track.Confirmations := 1;
      end;
      if Track.Confirmations >= 2 then
      begin
        Signals := AnalyzeProtectionTransition(Track.Stable, Item);
        if psTransition in Signals then Include(Detected, dkProtectTransition);
        if psImage in Signals then Include(Detected, dkImageProtection);
        if psGuard in Signals then Include(Detected, dkGuardTransition);
        if (psNoAccess in Signals) and
           IsSuspiciousNoAccessTransition(Track.Stable, Item) then
          Include(Detected, dkNoAccess);
        if Signals <> [] then
          RecordChangedAllocation(Item.AllocationBase, Tick, Detected);
        PreviousProtect := Track.Stable.Protect;
        CurrentProtect := Item.Protect;
        if ProtectionIsRW(PreviousProtect) and
           ProtectionIsRX(CurrentProtect) then
        begin
          Track.CycleStage := 1;
          Track.CycleStartTick := Tick;
        end
        else if (Track.CycleStage = 1) and
                ProtectionIsRX(PreviousProtect) and
                ProtectionIsRW(CurrentProtect) then
        begin
          if (Tick >= Track.CycleStartTick) and
             (Tick - Track.CycleStartTick <= CYCLE_WINDOW_MS) then
            Include(Detected, dkProtectionCycle);
          Track.CycleStage := 0;
        end
        else
          Track.CycleStage := 0;
        Track.Stable := Item;
        Track.Confirmations := 0;
      end;
    end;
    Track.LastSeenSweep := FSweepNumber;
    Track.LastSeenTick := Tick;
    FTracks.AddOrSetValue(Pair.Key, Track);
  end;
end;

procedure TProtectionGuard.PruneAbsentPages;
var
  Keys: TList<NativeUInt>;
  Key: NativeUInt;
  Track: TProtectionTrack;
  I: Integer;
begin
  Keys := TList<NativeUInt>.Create;
  try
    for Key in FTracks.Keys do
      if not FCurrent.ContainsKey(Key) then Keys.Add(Key);
    for I := 0 to Keys.Count - 1 do
    begin
      Key := Keys[I];
      if not FTracks.TryGetValue(Key, Track) then Continue;
      if (FSweepNumber >= Track.LastSeenSweep + 2) then FTracks.Remove(Key);
    end;
  finally
    Keys.Free;
  end;
end;

procedure TProtectionGuard.EndSweep(Tick: UInt64;
  var Detected: TDetectionKinds);
var
  BrokenBefore: Boolean;
begin
  if not FSweepOpen then Exit;
  if FOverflow then
  begin
    CancelSweep;
    Exit;
  end;
  BrokenBefore := FContinuityBroken;
  FContinuityBroken := True; // Remains broken if any commit step raises.
  try
    Inc(FSweepNumber);
    CommitObservedPages(Tick, BrokenBefore, Detected);
    PruneAbsentPages;
    FCurrent.Clear;
    FContinuityBroken := False;
    FSweepOpen := False;
  except
    CancelSweep;
    raise;
  end;
end;

{$IFDEF NHW_NATIVE5L_TESTS}
{$I Cozy.NHW.Native5L.ProtectionGuard.inc}
{$ENDIF}

end.
