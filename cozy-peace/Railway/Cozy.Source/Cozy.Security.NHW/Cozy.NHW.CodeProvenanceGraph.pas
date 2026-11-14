unit Cozy.NHW.CodeProvenanceGraph;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, System.Generics.Collections,
  Cozy.NHW.Lifecycle, Cozy.NHW.Logging;

type
  TCodeProvenanceNode = record
    StartAddress: NativeUInt;
    AllocationBase: NativeUInt;
    RegionBase, RegionSize: NativeUInt;
    Protect: Cardinal;
    FirstSeen: UInt64;
    LastSeen: UInt64;
    Confirmations: Byte;
    Eligible: Boolean;
    Reported: Boolean;
  end;

  // Self-only, read-only metadata. Private/JIT code alone is not an attack.
  // Engine owns this object; Examine/Reset must not run concurrently.
  TCodeProvenanceGraph = class
  private
    FNodes: TDictionary<Cardinal, TCodeProvenanceNode>;
    FPrimed: Boolean;
    FLastIndependent: UInt64;
    FLastReport: UInt64;
    FNextIndex: Integer;
    procedure InvalidateCandidates;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Examine(OwnTarget, SnapshotValid, Baseline, EpochStable,
      IndependentEvidence: Boolean; const Threads: TThreadSampleMap;
      Tick: UInt64; var Detected: TDetectionKinds);
  end;

function CodeProvenanceCandidate(Eligible: Boolean;
  Confirmations: Byte; IndependentRecent, EpochStable: Boolean): Boolean;
{$IFDEF NHW_NATIVE5H_TESTS}
function TestCodeProvenanceHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses Cozy.NHW.AllocationNative, Cozy.NHW.WinPointers, Cozy.NHW.Types
  {$IFDEF NHW_NATIVE5H_TESTS}, System.SysUtils{$ENDIF};

const
  MAX_PROVENANCE_NODES = 2048;
  MAX_CHECKS_PER_STEP = 64;
  PROVENANCE_WINDOW_MS = 15000;

{$IFDEF NHW_NATIVE5H_TESTS}
type TProvenanceQueryHook = function(Process: THandle; Address: NativeUInt;
  out Region: TVirtualRegion): Boolean;
var ProvenanceQueryHook: TProvenanceQueryHook = nil;
{$ENDIF}

function QueryProvenanceRegion(Address: NativeUInt;
  out Region: TVirtualRegion): Boolean;
begin
  Region := Default(TVirtualRegion);
  {$IFDEF NHW_NATIVE5H_TESTS}
  if Assigned(ProvenanceQueryHook) then
    Result := ProvenanceQueryHook(WinCurrentProcess, Address, Region)
  else
  {$ENDIF}
    Result := QueryVirtualRegion(WinCurrentProcess, Address, Region);
  if not Result then Exit;
  Result := (Address <> 0) and (Region.AllocationBase <> 0) and
    (Region.AllocationBase <= Region.BaseAddress) and
    (Region.Size <> 0) and (Address >= Region.BaseAddress);
  if Result then Result := Address - Region.BaseAddress < Region.Size;
end;

procedure ClearProvenanceCandidate(var Entry: TCodeProvenanceNode);
begin
  Entry.Confirmations := 0;
  Entry.LastSeen := 0;
  // Keep last-known relationship metadata ONLY for change/dedup comparison.
  // It is never current evidence without a new successful query.
  // Keep baseline eligibility and the already-reported flag on a read failure.
end;

function CodeProvenanceCandidate(Eligible: Boolean;
  Confirmations: Byte; IndependentRecent, EpochStable: Boolean): Boolean;
begin
  Result := Eligible and (Confirmations >= 2) and
    IndependentRecent and EpochStable;
end;

constructor TCodeProvenanceGraph.Create;
begin
  inherited Create;
  FNodes := TDictionary<Cardinal, TCodeProvenanceNode>.Create;
  Reset;
end;

destructor TCodeProvenanceGraph.Destroy;
begin FNodes.Free; inherited Destroy; end;

procedure TCodeProvenanceGraph.Reset;
begin
  FNodes.Clear;
  FPrimed := False;
  FLastIndependent := 0;
  FLastReport := 0;
  FNextIndex := 0;
end;

procedure TCodeProvenanceGraph.InvalidateCandidates;
var ID: Cardinal; Entry: TCodeProvenanceNode;
begin
  // Do not modify a dictionary while enumerating its live enumerator.
  for ID in FNodes.Keys.ToArray do
  begin
    Entry := FNodes[ID];
    ClearProvenanceCandidate(Entry);
    FNodes[ID] := Entry;
  end;
end;

procedure TCodeProvenanceGraph.Examine(OwnTarget, SnapshotValid,
  Baseline, EpochStable, IndependentEvidence: Boolean;
  const Threads: TThreadSampleMap; Tick: UInt64;
  var Detected: TDetectionKinds);
var
  Pair: TPair<Cardinal, TThreadSample>;
  Entry: TCodeProvenanceNode;
  Region: TVirtualRegion;
  Index: Integer;
  Recent, NewEntry, CurrentValid, SameRegion, RelationshipChanged: Boolean;

  procedure RetireMissingThreads;
  var
    ID: Cardinal;
  begin
    for ID in FNodes.Keys.ToArray do
      if not Threads.ContainsKey(ID) then FNodes.Remove(ID);
  end;

  procedure ObserveCurrentCodeRegion;
  begin
    Region := Default(TVirtualRegion);
    CurrentValid := False;
    if EpochStable and not Baseline and (Entry.StartAddress <> 0) and
       QueryProvenanceRegion(Entry.StartAddress, Region) then
      CurrentValid := (Region.RegionType = ALLOC_MEM_PRIVATE) and
        RegionIsExecutable(Region);
    if not CurrentValid then
      ClearProvenanceCandidate(Entry)
    else
    begin
      RelationshipChanged := (Entry.AllocationBase <> Region.AllocationBase) or
        (Entry.RegionBase <> Region.BaseAddress) or
        (Entry.RegionSize <> Region.Size) or (Entry.Protect <> Region.Protect);
      SameRegion := (Entry.Confirmations <> 0) and not RelationshipChanged and
        (Tick >= Entry.LastSeen) and (Tick >= Entry.FirstSeen) and
        (Tick - Entry.FirstSeen <= PROVENANCE_WINDOW_MS);
      if not SameRegion then
      begin
        // Replacement allocation/expired candidate gets a fresh sequence.
        if RelationshipChanged then Entry.Reported := False;
        Entry.AllocationBase := Region.AllocationBase;
        Entry.RegionBase := Region.BaseAddress;
        Entry.RegionSize := Region.Size;
        Entry.Protect := Region.Protect;
        Entry.FirstSeen := Tick;
        Entry.Confirmations := 1;
      end
      else if (Tick > Entry.LastSeen) and (Entry.Confirmations < 2) then
        Inc(Entry.Confirmations);
      Entry.LastSeen := Tick;
    end;
  end;

  procedure ReportConfirmedProvenance;
  begin
    if CurrentValid and Entry.Eligible and not Entry.Reported and
      CodeProvenanceCandidate(True, Entry.Confirmations, Recent, EpochStable) and
      ((FLastReport = 0) or (Tick < FLastReport) or
       (Tick - FLastReport >= 60000)) then
    begin
      Include(Detected, dkCodeProvenance);
      Entry.Reported := True;
      FLastReport := Tick;
    end;
  end;

begin
  if not OwnTarget then begin Reset; Exit; end;
  if not SnapshotValid or (Threads = nil) then
  begin InvalidateCandidates; FLastIndependent := 0; Exit; end;
  if Threads.Count > MAX_TARGET_THREADS then
  begin InvalidateCandidates; FLastIndependent := 0; Exit; end;
  if not EpochStable or Baseline then InvalidateCandidates;
  if Baseline then FLastIndependent := 0
  else if IndependentEvidence then FLastIndependent := Tick;
  Recent := (FLastIndependent <> 0) and (Tick >= FLastIndependent) and
    (Tick - FLastIndependent <= PROVENANCE_WINDOW_MS);
  try
    RetireMissingThreads;
    Index := 0;
    for Pair in Threads do
    begin
      NewEntry := not FNodes.TryGetValue(Pair.Key, Entry);
      if NewEntry or (Entry.StartAddress <> Pair.Value.StartAddress) then
      begin
        if NewEntry and (FNodes.Count >= MAX_PROVENANCE_NODES) then Continue;
        Entry := Default(TCodeProvenanceNode);
        Entry.StartAddress := Pair.Value.StartAddress;
        Entry.FirstSeen := Tick;
        Entry.Eligible := FPrimed and not Baseline;
      end;
      if Baseline then Entry.Eligible := False;
      if (Threads.Count > MAX_CHECKS_PER_STEP) and
         (((Index + FNextIndex) mod Threads.Count) >= MAX_CHECKS_PER_STEP) then
      begin
        Inc(Index);
        FNodes.AddOrSetValue(Pair.Key, Entry);
        Continue;
      end;
      Inc(Index);
      ObserveCurrentCodeRegion;
      // A stored candidate is never sufficient without a successful CURRENT read.
      ReportConfirmedProvenance;
      FNodes.AddOrSetValue(Pair.Key, Entry);
    end;
    FPrimed := True;
    if Threads.Count > 0 then
      FNextIndex := (FNextIndex + MAX_CHECKS_PER_STEP) mod Threads.Count;
  except
    InvalidateCandidates;
    FLastIndependent := 0;
    raise;
  end;
end;

{$IFDEF NHW_NATIVE5H_TESTS}
{$I Cozy.NHW.Native5H.CodeProvenance.inc}
{$ENDIF}
end.
