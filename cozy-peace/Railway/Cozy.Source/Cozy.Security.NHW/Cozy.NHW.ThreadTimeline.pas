unit Cozy.NHW.ThreadTimeline;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, System.Generics.Collections, Cozy.NHW.Lifecycle,
  Cozy.NHW.Logging;

type
  TThreadTimelineKind = (tkAppeared, tkDisappeared, tkStartChanged);
  TThreadTimelineEvent = record
    Tick: UInt64;
    ThreadID: Cardinal;
    StartAddress: NativeUInt;
    Kind: TThreadTimelineKind;
    PrivateExecutable: Boolean;
  end;
  TThreadTimelineState = record
    StartAddress: NativeUInt;
    FirstSeen: UInt64;
    LastSeen: UInt64;
    Confirmations: Byte;
    Eligible: Boolean;
    PrivateExecutable: Boolean;
    Reported: Boolean;
    RegionBase, AllocationBase, RegionSize: NativeUInt;
    Protect: Cardinal;
    LastConfirmedTick: UInt64;
  end;

  // v76: own-process completed-snapshot thread history, bounded RAM only.
  // Thread IDs are retired only after a complete native snapshot.
  TThreadTimeline = class
  private
    FThreads: TDictionary<Cardinal, TThreadTimelineState>;
    FHistory: array[0..255] of TThreadTimelineEvent;
    FNext, FCount: Integer;
    FPrimed: Boolean;
    FLastMemory, FLastAccess, FLastReport: UInt64;
    FLastTick: UInt64;
    FHasTick: Boolean;
    procedure InvalidateConfirmations;
    procedure AddEvent(Tick: UInt64; ID: Cardinal;
      Address: NativeUInt; Kind: TThreadTimelineKind;
      PrivateExec: Boolean);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Examine(OwnTarget, Valid, Baseline,
      EpochStable, HighExternal: Boolean;
      const Threads: TThreadSampleMap;
      const Kinds: TDetectionKinds; Tick: UInt64;
      var Detected: TDetectionKinds);
    function Recent(IndexFromNewest: Integer;
      out Entry: TThreadTimelineEvent): Boolean;
    property Count: Integer read FCount;
  end;

function ThreadTimelineCandidate(IsNew, PrivateExecutable: Boolean;
  Confirmations: Byte; MemoryRecent, ExternalRecent,
  EpochStable: Boolean): Boolean;

{$IFDEF NHW_NATIVE5G_TESTS}
function TestThreadTimelineHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses System.SysUtils, Cozy.NHW.AllocationNative, Cozy.NHW.WinPointers, Cozy.NHW.Types,
  Cozy.NHW.NativeSafety;

const
  MAX_TIMELINE_THREADS = 2048;
  TIMELINE_WINDOW_MS = 15000;

{$IFDEF NHW_NATIVE5G_TESTS}
type TTimelineQueryHook = function(Address: NativeUInt;
  out Region: TVirtualRegion): Boolean;
var TimelineQueryHook: TTimelineQueryHook = nil;
{$ENDIF}

function TimelineQuery(Address: NativeUInt; out R: TVirtualRegion): Boolean;
begin
  R := Default(TVirtualRegion);
{$IFDEF NHW_NATIVE5G_TESTS}
  if Assigned(TimelineQueryHook) then Exit(TimelineQueryHook(Address, R));
{$ENDIF}
  Result := QueryVirtualRegion(WinCurrentProcess, Address, R);
end;

procedure ClearTimelineConfirmation(var State: TThreadTimelineState);
begin
  State.PrivateExecutable := False;
  State.Confirmations := 0;
  State.RegionBase := 0;
  State.AllocationBase := 0;
  State.RegionSize := 0;
  State.Protect := 0;
  State.LastConfirmedTick := 0;
end;

function ApplyTimelineRegion(var State: TThreadTimelineState;
  QueryOK: Boolean; const R: TVirtualRegion; Tick: UInt64): Boolean;
var SameRegion: Boolean;
begin
  Result := False;
  if not QueryOK or (State.StartAddress = 0) or
    (R.AllocationBase = 0) or (R.AllocationBase > R.BaseAddress) or
    not NHWContainedSpan(R.BaseAddress, R.Size, State.StartAddress, 1) or
    (R.RegionType <> ALLOC_MEM_PRIVATE) or not RegionIsExecutable(R) then
  begin ClearTimelineConfirmation(State); Exit; end;
  SameRegion := State.PrivateExecutable and
    (State.RegionBase = R.BaseAddress) and
    (State.AllocationBase = R.AllocationBase) and
    (State.RegionSize = R.Size) and (State.Protect = R.Protect);
  if not SameRegion or (Tick < State.LastConfirmedTick) then
  begin
    State.Confirmations := 0;
    State.LastConfirmedTick := 0;
  end;
  State.RegionBase := R.BaseAddress;
  State.AllocationBase := R.AllocationBase;
  State.RegionSize := R.Size;
  State.Protect := R.Protect;
  State.PrivateExecutable := True;
  // One timestamp is one observation, even when the caller repeats a scan.
  if (State.Confirmations = 0) or (Tick > State.LastConfirmedTick) then
  begin
    if State.Confirmations < 255 then Inc(State.Confirmations);
    State.LastConfirmedTick := Tick;
  end;
  Result := True;
end;

function ThreadTimelineCandidate(IsNew, PrivateExecutable: Boolean;
  Confirmations: Byte; MemoryRecent, ExternalRecent,
  EpochStable: Boolean): Boolean;
begin
  Result := IsNew and PrivateExecutable and (Confirmations >= 2) and
    MemoryRecent and ExternalRecent and EpochStable;
end;

constructor TThreadTimeline.Create;
begin
  inherited Create;
  FThreads := TDictionary<Cardinal, TThreadTimelineState>.Create;
  Reset;
end;

destructor TThreadTimeline.Destroy;
begin FThreads.Free; inherited Destroy; end;

procedure TThreadTimeline.Reset;
begin
  FThreads.Clear;
  FillChar(FHistory, SizeOf(FHistory), 0);
  FNext := 0;
  FCount := 0;
  FPrimed := False;
  FLastMemory := 0;
  FLastAccess := 0;
  FLastReport := 0;
  FLastTick := 0;
  FHasTick := False;
end;

procedure TThreadTimeline.InvalidateConfirmations;
var ID: Cardinal; State: TThreadTimelineState;
begin
  // Snapshot keys before replacing values; never mutate an active enumerator.
  for ID in FThreads.Keys.ToArray do
    if FThreads.TryGetValue(ID, State) then
    begin
      ClearTimelineConfirmation(State);
      FThreads.AddOrSetValue(ID, State);
    end;
end;

procedure TThreadTimeline.AddEvent(Tick: UInt64; ID: Cardinal;
  Address: NativeUInt; Kind: TThreadTimelineKind; PrivateExec: Boolean);
begin
  FHistory[FNext] := Default(TThreadTimelineEvent);
  FHistory[FNext].Tick := Tick;
  FHistory[FNext].ThreadID := ID;
  FHistory[FNext].StartAddress := Address;
  FHistory[FNext].Kind := Kind;
  FHistory[FNext].PrivateExecutable := PrivateExec;
  FNext := (FNext + 1) mod Length(FHistory);
  if FCount < Length(FHistory) then Inc(FCount);
end;

function TThreadTimeline.Recent(IndexFromNewest: Integer;
  out Entry: TThreadTimelineEvent): Boolean;
var Pos: Integer;
begin
  Entry := Default(TThreadTimelineEvent);
  Result := (IndexFromNewest >= 0) and (IndexFromNewest < FCount);
  if not Result then Exit;
  Pos := (FNext - 1 - IndexFromNewest + Length(FHistory)) mod
    Length(FHistory);
  Entry := FHistory[Pos];
end;

procedure TThreadTimeline.Examine(OwnTarget, Valid, Baseline,
  EpochStable, HighExternal: Boolean;
  const Threads: TThreadSampleMap;
  const Kinds: TDetectionKinds; Tick: UInt64;
  var Detected: TDetectionKinds);
var
  Pair: TPair<Cardinal, TThreadSample>;
  Missing: TList<Cardinal>;
  MemoryRecent, AccessRecent: Boolean;

  procedure RetireMissingThreads;
  var
    Known: TPair<Cardinal, TThreadTimelineState>;
    ID: Cardinal;
    State: TThreadTimelineState;
  begin
    for Known in FThreads do
      if not Threads.ContainsKey(Known.Key) then Missing.Add(Known.Key);
    for ID in Missing do
    begin
      if FThreads.TryGetValue(ID, State) then
        AddEvent(Tick, ID, State.StartAddress, tkDisappeared, False);
      FThreads.Remove(ID);
    end;
  end;

  procedure ApplyThreadSample(const Pair: TPair<Cardinal, TThreadSample>);
  var
    State: TThreadTimelineState;
    R: TVirtualRegion;
    IsNew, ValidPage: Boolean;
  begin
    IsNew := not FThreads.TryGetValue(Pair.Key, State);
    if IsNew or (State.StartAddress <> Pair.Value.StartAddress) then
    begin
      if IsNew and (FThreads.Count >= MAX_TIMELINE_THREADS) then Exit;
      State := Default(TThreadTimelineState);
      State.StartAddress := Pair.Value.StartAddress;
      State.FirstSeen := Tick;
      State.Eligible := FPrimed and not Baseline;
      if FPrimed then
      begin
        if IsNew then
          AddEvent(Tick, Pair.Key, State.StartAddress,
            tkAppeared, False)
        else
          AddEvent(Tick, Pair.Key, State.StartAddress,
            tkStartChanged, False);
      end;
    end;
    State.LastSeen := Tick;
    if Tick < State.FirstSeen then State.FirstSeen := Tick;
    ValidPage := False;
    if Baseline then
    begin
      State.Eligible := False;
      ClearTimelineConfirmation(State);
    end
    else if State.Eligible and not State.Reported and
      (State.StartAddress <> 0) then
    begin
      try
        ValidPage := TimelineQuery(State.StartAddress, R);
        ValidPage := ApplyTimelineRegion(State, ValidPage, R, Tick);
      except
        ClearTimelineConfirmation(State);
        FThreads.AddOrSetValue(Pair.Key, State);
        InvalidateConfirmations;
        raise; // retain the existing engine fault-isolation boundary
      end;
    end
    else ClearTimelineConfirmation(State);
    if ValidPage and not Baseline and not State.Reported and
      ThreadTimelineCandidate(State.Eligible,
        State.PrivateExecutable, State.Confirmations,
        MemoryRecent, AccessRecent, EpochStable) and
      (Tick >= State.FirstSeen) and
      (Tick - State.FirstSeen <= TIMELINE_WINDOW_MS) and
      ((FLastReport = 0) or (Tick < FLastReport) or
       (Tick - FLastReport >= 60000)) then
    begin
      Include(Detected, dkThreadTimeline);
      State.Reported := True;
      FLastReport := Tick;
    end;
    FThreads.AddOrSetValue(Pair.Key, State);
  end;

begin
  if not OwnTarget then begin Reset; Exit; end;
  if not Valid or (Threads = nil) then
  begin InvalidateConfirmations; Exit; end;
  if Threads.Count > MAX_TARGET_THREADS then
  begin InvalidateConfirmations; Exit; end;
  if FHasTick and (Tick < FLastTick) then
  begin
    InvalidateConfirmations;
    FLastMemory := 0;
    FLastAccess := 0;
    FLastReport := 0;
  end;
  FLastTick := Tick;
  FHasTick := True;
  if HighExternal then FLastAccess := Tick;
  if (Kinds * [dkPECodeIntegrity, dkImageCOWIntegrity,
    dkExecutableLifecycle, dkPrivateExecRegion,
    dkWriteIntegrity, dkImportRedirect, dkCodeProvenance]) <> [] then
    FLastMemory := Tick;
  MemoryRecent := (FLastMemory <> 0) and (Tick >= FLastMemory) and
    (Tick - FLastMemory <= TIMELINE_WINDOW_MS);
  AccessRecent := (FLastAccess <> 0) and (Tick >= FLastAccess) and
    (Tick - FLastAccess <= TIMELINE_WINDOW_MS);
  Missing := TList<Cardinal>.Create;
  try
    RetireMissingThreads;
    for Pair in Threads do
    begin
      ApplyThreadSample(Pair);
    end;
    FPrimed := True;
  finally Missing.Free; end;
end;

{$IFDEF NHW_NATIVE5G_TESTS}
{$I Cozy.NHW.Native5G.ThreadTimeline.inc}
{$ENDIF}

end.
