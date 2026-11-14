unit Cozy.NHW.ThreadExecutionProvenance;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows, System.Generics.Collections, Cozy.NHW.Lifecycle,
  Cozy.NHW.Logging, Cozy.NHW.ThreadOriginNative;

type
  TExecutionEntry = record
    StartAddress: NativeUInt;
    AllocationBase: NativeUInt;
    RegionBase: NativeUInt;
    RegionSize: NativeUInt;
    Protection: Cardinal;
    FirstSeen: UInt64;
    SeenAt: UInt64;
    Confirmations: Byte;
    Eligible: Boolean;
    Reported: Boolean;
  end;

  // v43: own-process thread-start provenance, read-only. Requires a complete
  // thread snapshot and TWO successful, consistent region observations.
  // TThreadSample has no creation timestamp; this is NOT proof of TID identity
  // or of a thread's current instruction pointer / actual execution.
  TThreadExecutionProvenance = class
  private
    FSeen: TDictionary<Cardinal, TExecutionEntry>;
    FPrimed: Boolean;
    FLastReport: UInt64;
    FLastTick: UInt64;
    FNextIndex: Integer;
    procedure InvalidateObservations;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Examine(OwnTarget: Boolean; const Threads: TThreadSampleMap;
      Valid, Baseline: Boolean; Tick: UInt64;
      var Detected: TDetectionKinds);
  end;

function ProvenanceConfirmed(Eligible: Boolean; Confirmations: Byte;
  FirstSeen, Tick: UInt64): Boolean;

{$IFDEF NHW_NATIVE5E_TESTS}
function TestThreadExecutionHardening(out Failure: string;
  out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses System.SysUtils, Cozy.NHW.WinPointers, Cozy.NHW.Types;

const
  PROVENANCE_CONFIRM_WINDOW_MS = 12000;
  PROVENANCE_REPORT_COOLDOWN_MS = 20000;
  MAX_THREAD_CHECKS_PER_SCAN = 64;

{$IFDEF NHW_NATIVE5E_TESTS}
type
  TExecutionQueryHook = function(Process: THandle; Address: NativeUInt;
    out Region: TThreadOriginRegion): Boolean;
var
  ExecutionQueryHook: TExecutionQueryHook = nil;
{$ENDIF}

function QueryExecutionRegion(Address: NativeUInt;
  out Region: TThreadOriginRegion): Boolean;
begin
  Region := Default(TThreadOriginRegion);
{$IFDEF NHW_NATIVE5E_TESTS}
  if Assigned(ExecutionQueryHook) then
    Exit(ExecutionQueryHook(WinCurrentProcess, Address, Region));
{$ENDIF}
  Result := QueryThreadStartRegion(WinCurrentProcess, Address, Region);
end;

function ProvenanceConfirmed(Eligible: Boolean; Confirmations: Byte;
  FirstSeen, Tick: UInt64): Boolean;
begin
  Result := Eligible and (Confirmations >= 2) and (Tick >= FirstSeen) and
    (Tick - FirstSeen <= PROVENANCE_CONFIRM_WINDOW_MS);
end;

procedure ClearExecutionCandidate(var Entry: TExecutionEntry);
begin
  // Keep per-thread eligibility/report suppression, not stale region evidence.
  Entry.AllocationBase := 0;
  Entry.RegionBase := 0;
  Entry.RegionSize := 0;
  Entry.Protection := 0;
  Entry.FirstSeen := 0;
  Entry.SeenAt := 0;
  Entry.Confirmations := 0;
end;

function SameExecutionRegion(const Entry: TExecutionEntry;
  const Region: TThreadOriginRegion): Boolean;
begin
  Result := (Entry.Confirmations <> 0) and
    (Entry.AllocationBase = Region.AllocationBase) and
    (Entry.RegionBase = Region.BaseAddress) and
    (Entry.RegionSize = Region.RegionSize) and
    (Entry.Protection = Region.Protect);
end;

constructor TThreadExecutionProvenance.Create;
begin
  inherited Create;
  FSeen := TDictionary<Cardinal, TExecutionEntry>.Create;
  Reset;
end;

destructor TThreadExecutionProvenance.Destroy;
begin
  FSeen.Free;
  inherited Destroy;
end;

procedure TThreadExecutionProvenance.Reset;
begin
  FSeen.Clear;
  FPrimed := False;
  FLastReport := 0;
  FLastTick := 0;
  FNextIndex := 0;
end;

procedure TThreadExecutionProvenance.InvalidateObservations;
var
  IDs: TArray<Cardinal>;
  ID: Cardinal;
  Entry: TExecutionEntry;
begin
  // Do not mutate a dictionary while enumerating its live enumerator.
  IDs := FSeen.Keys.ToArray;
  for ID in IDs do
    if FSeen.TryGetValue(ID, Entry) then
    begin
      ClearExecutionCandidate(Entry);
      FSeen.AddOrSetValue(ID, Entry);
    end;
end;

procedure TThreadExecutionProvenance.Examine(OwnTarget: Boolean;
  const Threads: TThreadSampleMap; Valid, Baseline: Boolean;
  Tick: UInt64; var Detected: TDetectionKinds);
var
  Pair: TPair<Cardinal, TThreadSample>;
  Missing: TList<Cardinal>;
  Index: Integer;

  procedure RetireMissingThreads;
  var
    Known: TPair<Cardinal, TExecutionEntry>;
    ID: Cardinal;
  begin
    // Only a valid full snapshot may retire an absent thread.
    for Known in FSeen do
      if not Threads.ContainsKey(Known.Key) then Missing.Add(Known.Key);
    for ID in Missing do FSeen.Remove(ID);
  end;

  procedure ConfirmExecutionRegion(var Entry: TExecutionEntry; const Reg: TThreadOriginRegion);
  var
    EligibleNow, SameCandidate: Boolean;
  begin
    EligibleNow := (Reg.StartAddress = Entry.StartAddress) and
      IsPrivateExecutableStart(Reg);
    if not EligibleNow or Baseline then
      ClearExecutionCandidate(Entry)
    else
    begin
      SameCandidate := SameExecutionRegion(Entry, Reg) and
        (Tick >= Entry.FirstSeen) and (Tick >= Entry.SeenAt) and
        (Tick - Entry.FirstSeen <= PROVENANCE_CONFIRM_WINDOW_MS);
      if not SameCandidate then
      begin
        // A different allocation/range/protection is a NEW candidate.
        // The previous range must not remain latched in the entry.
        ClearExecutionCandidate(Entry);
        Entry.AllocationBase := Reg.AllocationBase;
        Entry.RegionBase := Reg.BaseAddress;
        Entry.RegionSize := Reg.RegionSize;
        Entry.Protection := Reg.Protect;
        Entry.FirstSeen := Tick;
        Entry.SeenAt := Tick;
        Entry.Confirmations := 1;
      end
      else if Tick > Entry.SeenAt then
      begin
        if Entry.Confirmations < 3 then Inc(Entry.Confirmations);
        Entry.SeenAt := Tick;
      end;
    end;
  end;

  procedure InspectThreadSample(const Pair: TPair<Cardinal, TThreadSample>);
  var
    Entry: TExecutionEntry;
    Reg: TThreadOriginRegion;
    IsNew: Boolean;
  begin
    Entry := Default(TExecutionEntry);
    IsNew := not FSeen.TryGetValue(Pair.Key, Entry);
    if IsNew or (Entry.StartAddress <> Pair.Value.StartAddress) then
    begin
      Entry := Default(TExecutionEntry);
      Entry.StartAddress := Pair.Value.StartAddress;
      Entry.Eligible := FPrimed and not Baseline;
    end;
    if Baseline then
    begin
      ClearExecutionCandidate(Entry);
      Entry.Eligible := False;
      Entry.Reported := False;
    end;
    if (Pair.Key = 0) or (Pair.Value.ThreadID <> Pair.Key) then
    begin
      ClearExecutionCandidate(Entry);
      FSeen.AddOrSetValue(Pair.Key, Entry);
      Inc(Index);
      Exit;
    end;
    // Retain the existing 64-thread rotating budget; skipped work is not
    // a successful observation and cannot increment confirmations.
    if (Threads.Count > MAX_THREAD_CHECKS_PER_SCAN) and
       (((Index + FNextIndex) mod Threads.Count) >= MAX_THREAD_CHECKS_PER_SCAN) then
    begin
      Inc(Index);
      FSeen.AddOrSetValue(Pair.Key, Entry);
      Exit;
    end;
    Inc(Index);
    if not QueryExecutionRegion(Entry.StartAddress, Reg) then
    begin
      ClearExecutionCandidate(Entry);
      FSeen.AddOrSetValue(Pair.Key, Entry);
      Exit; // never evaluate the old count after a failed query
    end;
    ConfirmExecutionRegion(Entry, Reg);
    if not Baseline and not Entry.Reported and
       ProvenanceConfirmed(Entry.Eligible, Entry.Confirmations,
         Entry.FirstSeen, Tick) and
       ((FLastReport = 0) or
        ((Tick >= FLastReport) and
         (Tick - FLastReport >= PROVENANCE_REPORT_COOLDOWN_MS))) then
    begin
      Include(Detected, dkExecutionProvenance);
      Entry.Reported := True;
      FLastReport := Tick;
    end;
    FSeen.AddOrSetValue(Pair.Key, Entry);
  end;

begin
  if not OwnTarget then
  begin
    Reset;
    Exit;
  end;
  if (FLastTick <> 0) and (Tick < FLastTick) then
  begin
    InvalidateObservations;
    FLastReport := 0;
  end;
  FLastTick := Tick;
  if not Valid or (Threads = nil) then
  begin
    InvalidateObservations;
    Exit;
  end;
  if Threads.Count > MAX_TARGET_THREADS then
  begin
    InvalidateObservations;
    Exit;
  end;
  Missing := TList<Cardinal>.Create;
  try
    try
      RetireMissingThreads;
      Index := 0;
      for Pair in Threads do
      begin
        InspectThreadSample(Pair);
      end;
      if Threads.Count > 0 then
        FNextIndex := (FNextIndex + MAX_THREAD_CHECKS_PER_SCAN) mod Threads.Count
      else FNextIndex := 0;
      FPrimed := True;
    except
      InvalidateObservations;
      raise; // retain the engine's existing sensor-fault accounting
    end;
  finally
    Missing.Free;
  end;
end;

{$IFDEF NHW_NATIVE5E_TESTS}
{$I Cozy.NHW.Native5E.ThreadExecution.inc}
{$ENDIF}

end.
