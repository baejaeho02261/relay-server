unit Cozy.NHW.MemoryDelta;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  Cozy.NHW.AllocationNative;

type
  TMemoryDeltaMark = record
    BaseAddress: NativeUInt;
    AllocationBase: NativeUInt;
    RegionType: Cardinal;
    Protect: Cardinal;
    State: Cardinal;
    PendingProtect: Cardinal;
    Confirmations: Byte;
    RegionSize: NativeUInt;
    PendingState: Cardinal;
    PendingTick: UInt64;
    PendingSince: UInt64;
    NeedsBaseline: Boolean;
  end;

  // Read-only rotating metadata cache. Does NOT scan page contents.
  // Confirmed transitions are evidence for follow-up, not attack verdicts.
  // No output or file writes are produced by this optional sensor.
  TIncrementalMemoryDelta = class
  private
    FMarks: array[0..255] of TMemoryDeltaMark;
    FCount: Integer;
    FNextStore: Integer;
    FNextRecheck: Integer;
    FSeedCursor: NativeUInt;
    FLastChange: UInt64;
    FLastTick: UInt64;
    FObservedTransitions: Cardinal;
    procedure AddMark(const R: TVirtualRegion);
    procedure ClearPending;
  public
    constructor Create;
    procedure Reset;
    procedure Examine(SelfTarget, Baseline, AllowHeavy: Boolean;
      Tick: UInt64);
    property ObservedTransitions: Cardinal read FObservedTransitions;
    property LastChangeTick: UInt64 read FLastChange;
  end;

{$IFDEF NHW_NATIVE5F_TESTS}
function TestMemoryDeltaHardening(out Failure: string;
  out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses System.SysUtils, Cozy.NHW.WinPointers, Cozy.NHW.NativeSafety;

const
  INITIAL_ADDRESS = $10000;
  RECHECK_PER_SCAN = 16;
  SEED_PER_SCAN = 12;
  DELTA_CANDIDATE_MS = 120000;

{$IFDEF NHW_NATIVE5F_TESTS}
type
  TDeltaAvailableHook = function: Boolean;
  TDeltaMaxHook = function: NativeUInt;
  TDeltaQueryHook = function(Address: NativeUInt;
    out Region: TVirtualRegion): Boolean;
var
  DeltaAvailableHook: TDeltaAvailableHook = nil;
  DeltaMaxHook: TDeltaMaxHook = nil;
  DeltaQueryHook: TDeltaQueryHook = nil;
{$ENDIF}

function DeltaAvailable: Boolean;
begin
{$IFDEF NHW_NATIVE5F_TESTS}
  if Assigned(DeltaAvailableHook) then Exit(DeltaAvailableHook());
{$ENDIF}
  Result := AllocationNativeAvailable;
end;

function DeltaMaxAddress: NativeUInt;
begin
{$IFDEF NHW_NATIVE5F_TESTS}
  if Assigned(DeltaMaxHook) then Exit(DeltaMaxHook());
{$ENDIF}
  Result := MaximumUserVirtualAddress;
end;

function DeltaQuery(Address: NativeUInt; out Region: TVirtualRegion): Boolean;
begin
  Region := Default(TVirtualRegion);
{$IFDEF NHW_NATIVE5F_TESTS}
  if Assigned(DeltaQueryHook) then Exit(DeltaQueryHook(Address, Region));
{$ENDIF}
  Result := QueryVirtualRegion(WinCurrentProcess, Address, Region);
end;

procedure ClearDeltaCandidate(var Mark: TMemoryDeltaMark);
begin
  Mark.PendingProtect := 0;
  Mark.PendingState := 0;
  Mark.PendingTick := 0;
  Mark.PendingSince := 0;
  Mark.Confirmations := 0;
end;

function ValidDeltaRegion(const R: TVirtualRegion): Boolean;
begin
  Result := NHWAddressSpan(R.BaseAddress, R.Size) and
    ((R.State = ALLOC_MEM_COMMIT) or (R.State = ALLOC_MEM_RESERVE) or
    (R.State = ALLOC_MEM_FREE));
end;

function ApplyDeltaSample(var Mark: TMemoryDeltaMark;
  QueryOK: Boolean; const Current: TVirtualRegion;
  Baseline: Boolean; Tick: UInt64): Boolean;
var
  CurrentProtect: Cardinal;
  Changed: Boolean;
begin
  Result := False;
  if (Mark.BaseAddress = 0) or not QueryOK or not ValidDeltaRegion(Current) then
  begin ClearDeltaCandidate(Mark); Exit; end;
  if (Current.BaseAddress <> Mark.BaseAddress) or
    (Current.AllocationBase <> Mark.AllocationBase) or
    (Current.RegionType <> Mark.RegionType) or
    (Current.Size <> Mark.RegionSize) or (Current.State = ALLOC_MEM_FREE) then
  begin
    Mark := Default(TMemoryDeltaMark);
    Exit; // remapped/split/merged/freed region is a different observation
  end;
  CurrentProtect := Current.Protect;
  if Current.State <> ALLOC_MEM_COMMIT then CurrentProtect := 0;
  if Baseline or Mark.NeedsBaseline then
  begin
    Mark.NeedsBaseline := False;
    Mark.Protect := CurrentProtect;
    Mark.State := Current.State;
    ClearDeltaCandidate(Mark);
    Exit;
  end;
  if (Mark.Confirmations <> 0) and
    (NHWExpired(Mark.PendingSince, Tick, DELTA_CANDIDATE_MS) or
    (Tick < Mark.PendingTick)) then ClearDeltaCandidate(Mark);
  Changed := (CurrentProtect <> Mark.Protect) or (Current.State <> Mark.State);
  if not Changed then
  begin ClearDeltaCandidate(Mark); Exit; end;
  if (Mark.Confirmations > 0) and
    (Mark.PendingProtect = CurrentProtect) and (Mark.PendingState = Current.State) then
  begin
    // Multiple examinations at the same logical tick are not independent reads.
    if (Tick > Mark.PendingTick) and (Mark.Confirmations < 2) then
      Inc(Mark.Confirmations);
  end
  else
  begin
    Mark.PendingProtect := CurrentProtect;
    Mark.PendingState := Current.State;
    Mark.PendingSince := Tick;
    Mark.Confirmations := 1;
  end;
  Mark.PendingTick := Tick;
  if Mark.Confirmations >= 2 then
  begin
    Mark.Protect := CurrentProtect;
    Mark.State := Current.State;
    ClearDeltaCandidate(Mark);
    Result := True;
  end;
end;

constructor TIncrementalMemoryDelta.Create;
begin inherited Create; Reset; end;

procedure TIncrementalMemoryDelta.ClearPending;
var I: Integer;
begin
  for I := 0 to FCount - 1 do ClearDeltaCandidate(FMarks[I]);
end;

procedure TIncrementalMemoryDelta.Reset;
begin
  FillChar(FMarks, SizeOf(FMarks), 0);
  FCount := 0;
  FNextStore := 0;
  FNextRecheck := 0;
  FSeedCursor := INITIAL_ADDRESS;
  FLastChange := 0;
  FLastTick := 0;
  FObservedTransitions := 0;
end;

procedure TIncrementalMemoryDelta.AddMark(const R: TVirtualRegion);
var I, Pos: Integer;
begin
  if not ValidDeltaRegion(R) or (R.State <> ALLOC_MEM_COMMIT) then Exit;
  if not RegionIsExecutable(R) and
    not ((R.RegionType = ALLOC_MEM_PRIVATE) and
      ((R.Protect and $FF) in [$04, $08])) then Exit;
  for I := 0 to FCount - 1 do
    if FMarks[I].BaseAddress = R.BaseAddress then Exit;
  Pos := FNextStore;
  FMarks[Pos] := Default(TMemoryDeltaMark);
  FMarks[Pos].BaseAddress := R.BaseAddress;
  FMarks[Pos].AllocationBase := R.AllocationBase;
  FMarks[Pos].RegionSize := R.Size;
  FMarks[Pos].RegionType := R.RegionType;
  FMarks[Pos].Protect := R.Protect;
  FMarks[Pos].State := R.State;
  FNextStore := (FNextStore + 1) mod Length(FMarks);
  if FCount < Length(FMarks) then Inc(FCount);
end;

procedure TIncrementalMemoryDelta.Examine(SelfTarget, Baseline,
  AllowHeavy: Boolean; Tick: UInt64);
var
  I, Idx, Rechecks: Integer;
  Current: TVirtualRegion;
  MaxAddr, NextAddr: NativeUInt;
  Entry: TMemoryDeltaMark;
  OK: Boolean;
  Transitions: Cardinal;

  procedure RecheckCachedRegions;
  var
    I: Integer;
  begin
    Rechecks := FCount;
    if Rechecks > RECHECK_PER_SCAN then Rechecks := RECHECK_PER_SCAN;
    // At most one visit per mark in this invocation, even with <16 marks.
    for I := 1 to Rechecks do
    begin
      if FNextRecheck >= FCount then FNextRecheck := 0;
      Idx := FNextRecheck;
      FNextRecheck := (FNextRecheck + 1) mod FCount;
      Entry := FMarks[Idx];
      if Entry.BaseAddress = 0 then Continue;
      OK := DeltaQuery(Entry.BaseAddress, Current);
      if ApplyDeltaSample(Entry, OK, Current, Baseline, Tick) then Inc(Transitions);
      FMarks[Idx] := Entry;
    end;
  end;

  procedure SeedNewRegions;
  var
    I: Integer;
  begin
    for I := 1 to SEED_PER_SCAN do
    begin
      if (FSeedCursor < INITIAL_ADDRESS) or (FSeedCursor > MaxAddr) then
        FSeedCursor := INITIAL_ADDRESS;
      if not DeltaQuery(FSeedCursor, Current) or not ValidDeltaRegion(Current) or
        not NHWContainedSpan(Current.BaseAddress, Current.Size, FSeedCursor, 1) then
      begin
        if MaxAddr - FSeedCursor < $1000 then FSeedCursor := INITIAL_ADDRESS
        else Inc(FSeedCursor, $1000);
        Continue;
      end;
      AddMark(Current);
      if not NHWTryAddAddress(Current.BaseAddress, Current.Size, NextAddr) or
        (NextAddr <= FSeedCursor) or (NextAddr > MaxAddr) then
        FSeedCursor := INITIAL_ADDRESS
      else FSeedCursor := NextAddr;
    end;
  end;

  procedure PublishObservedTransitions;
  begin
    if Transitions <> 0 then
    begin
      if Transitions > High(Cardinal) - FObservedTransitions then
        FObservedTransitions := High(Cardinal)
      else Inc(FObservedTransitions, Transitions);
      FLastChange := Tick;
    end;
  end;

begin
  if not SelfTarget then
  begin ClearPending; Exit; end;
  if Baseline then
  begin
    // Marks not visited in this bounded pass still need a new accepted sample.
    // Preserve this flag across query failures and budget-skipped calls.
    for I := 0 to FCount - 1 do FMarks[I].NeedsBaseline := True;
    ClearPending;
  end
  else if (FLastTick <> 0) and (Tick < FLastTick) then ClearPending;
  if not AllowHeavy then Exit;
  if not DeltaAvailable then
  begin ClearPending; Exit; end;
  if (FLastTick <> 0) and (Tick = FLastTick) then Exit;
  MaxAddr := DeltaMaxAddress;
  if MaxAddr < INITIAL_ADDRESS then
  begin ClearPending; Exit; end;
  FLastTick := Tick;
  Transitions := 0;
  try
    RecheckCachedRegions;
    SeedNewRegions;
  except
    ClearPending;
    raise;
  end;
  PublishObservedTransitions;
end;

{$IFDEF NHW_NATIVE5F_TESTS}
{$I Cozy.NHW.Native5F.MemoryDelta.inc}
{$ENDIF}

end.
