unit Cozy.NHW.SectionCorrelation;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, System.Generics.Collections,
  Cozy.NHW.Types, Cozy.NHW.Lifecycle, Cozy.NHW.Logging;

type
  TSectionThreadNode = record
    StartAddress: NativeUInt;
    AllocationBase: NativeUInt;
    Confirmations: Byte;
    Eligible: Boolean;
    Reported: Boolean;
    RegionBase, RegionSize: NativeUInt;
    Protect: Cardinal;
    CandidateSince, LastConfirmedTick: UInt64;
  end;

  // v74: correlation of external SECTION-handle context with an OWN thread
  // starting in an executable MEM_MAPPED region and an independent mapping
  // change. Section object identity is NOT equated with the VAD identity.
  TSectionCorrelation = class
  private
    FNodes: TDictionary<Cardinal, TSectionThreadNode>;
    FPrimed: Boolean;
    FLastSectionTick, FLastMappingTick, FLastAccessTick: UInt64;
    FLastReport: UInt64;
    FLastTick: UInt64;
    FHasTick: Boolean;
    procedure InvalidateConfirmations;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Examine(OwnTarget, Valid, Baseline, EpochStable,
      ExternalHigh: Boolean; TargetPID: Cardinal;
      const Threads: TThreadSampleMap;
      const Sections: TList<TIPCObservation>;
      const Kinds: TDetectionKinds; Tick: UInt64;
      var Detected: TDetectionKinds);
  end;

function SectionCorrelationCandidate(WasNew, MappedExecutable: Boolean;
  Confirmations: Byte; SectionRecent, MappingRecent,
  ExternalRecent, EpochStable: Boolean): Boolean;

{$IFDEF NHW_NATIVE5G_TESTS}
function TestSectionCorrelationHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses System.SysUtils, Cozy.NHW.AllocationNative, Cozy.NHW.WinPointers, Cozy.NHW.NativeSafety;

const
  SECTION_WINDOW_MS = 15000;
  MAX_SECTION_NODES = 2048;

{$IFDEF NHW_NATIVE5G_TESTS}
type TSectionQueryHook = function(Address: NativeUInt;
  out Region: TVirtualRegion): Boolean;
var SectionQueryHook: TSectionQueryHook = nil;
{$ENDIF}

function SectionQuery(Address: NativeUInt; out R: TVirtualRegion): Boolean;
begin
  R := Default(TVirtualRegion);
{$IFDEF NHW_NATIVE5G_TESTS}
  if Assigned(SectionQueryHook) then Exit(SectionQueryHook(Address, R));
{$ENDIF}
  Result := QueryVirtualRegion(WinCurrentProcess, Address, R);
end;

procedure ClearSectionConfirmation(var Node: TSectionThreadNode);
begin
  Node.Confirmations := 0;
  Node.CandidateSince := 0;
  Node.LastConfirmedTick := 0;
  // Retain the last observed identity, not its confidence. A later remap
  // is compared with this identity and then explicitly replaces it.
end;

function ApplySectionRegion(var Node: TSectionThreadNode;
  QueryOK: Boolean; const R: TVirtualRegion; Tick: UInt64): Boolean;
var SameRegion: Boolean;
begin
  Result := False;
  if not QueryOK or (Node.StartAddress = 0) or
    (R.AllocationBase = 0) or (R.AllocationBase > R.BaseAddress) or
    not NHWContainedSpan(R.BaseAddress, R.Size, Node.StartAddress, 1) or
    (R.RegionType <> ALLOC_MEM_MAPPED) or not RegionIsExecutable(R) then
  begin ClearSectionConfirmation(Node); Exit; end;
  SameRegion := (Node.AllocationBase = R.AllocationBase) and
    (Node.RegionBase = R.BaseAddress) and (Node.RegionSize = R.Size) and
    (Node.Protect = R.Protect);
  if not SameRegion then
  begin
    ClearSectionConfirmation(Node);
    Node.AllocationBase := R.AllocationBase;
    Node.RegionBase := R.BaseAddress;
    Node.RegionSize := R.Size;
    Node.Protect := R.Protect;
    Node.Reported := False; // a distinct mapping, not another confirmation
  end;
  if (Node.Confirmations > 0) and
    ((Tick < Node.LastConfirmedTick) or (Tick < Node.CandidateSince) or
     (Tick - Node.CandidateSince > SECTION_WINDOW_MS)) then
    ClearSectionConfirmation(Node);
  if Node.Confirmations = 0 then
  begin
    Node.CandidateSince := Tick;
    Node.LastConfirmedTick := Tick;
    Node.Confirmations := 1;
  end
  else if Tick > Node.LastConfirmedTick then
  begin
    if Node.Confirmations < 255 then Inc(Node.Confirmations);
    Node.LastConfirmedTick := Tick;
  end;
  Result := True;
end;

function SectionCorrelationCandidate(WasNew, MappedExecutable: Boolean;
  Confirmations: Byte; SectionRecent, MappingRecent,
  ExternalRecent, EpochStable: Boolean): Boolean;
begin
  Result := WasNew and MappedExecutable and (Confirmations >= 2) and
    SectionRecent and MappingRecent and ExternalRecent and EpochStable;
end;

constructor TSectionCorrelation.Create;
begin
  inherited Create;
  FNodes := TDictionary<Cardinal, TSectionThreadNode>.Create;
  Reset;
end;

destructor TSectionCorrelation.Destroy;
begin FNodes.Free; inherited Destroy; end;

procedure TSectionCorrelation.Reset;
begin
  FNodes.Clear;
  FPrimed := False;
  FLastSectionTick := 0;
  FLastMappingTick := 0;
  FLastAccessTick := 0;
  FLastReport := 0;
  FLastTick := 0;
  FHasTick := False;
end;

procedure TSectionCorrelation.InvalidateConfirmations;
var ID: Cardinal; Node: TSectionThreadNode;
begin
  for ID in FNodes.Keys.ToArray do
    if FNodes.TryGetValue(ID, Node) then
    begin
      ClearSectionConfirmation(Node);
      FNodes.AddOrSetValue(ID, Node);
    end;
end;

procedure TSectionCorrelation.Examine(OwnTarget, Valid,
  Baseline, EpochStable, ExternalHigh: Boolean; TargetPID: Cardinal;
  const Threads: TThreadSampleMap;
  const Sections: TList<TIPCObservation>;
  const Kinds: TDetectionKinds; Tick: UInt64;
  var Detected: TDetectionKinds);
var
  Node: TSectionThreadNode;
  Gone: TList<Cardinal>;
  R: TVirtualRegion;
  NewNode, Mapped, QueryOK: Boolean;
  SectionRecent, MappingRecent, AccessRecent: Boolean;

  procedure ObserveCorrelationContext;
  var
    S: TIPCObservation;
  begin
    if ExternalHigh then FLastAccessTick := Tick;
    if (Kinds * [dkMappedView, dkMappingBacking, dkSectionBacking,
      dkExecutableMapping, dkImageCOWIntegrity]) <> [] then
      FLastMappingTick := Tick;
    if Sections <> nil then
      for S in Sections do
        if (S.Kind = ikSection) and (S.OwnerPID <> 0) and
           (S.OwnerPID <> TargetPID) and (S.ObjectIdentity <> 0) then
        begin
          FLastSectionTick := Tick;
          Break;
        end;
    SectionRecent := (FLastSectionTick <> 0) and
      (Tick >= FLastSectionTick) and
      (Tick - FLastSectionTick <= SECTION_WINDOW_MS);
    MappingRecent := (FLastMappingTick <> 0) and
      (Tick >= FLastMappingTick) and
      (Tick - FLastMappingTick <= SECTION_WINDOW_MS);
    AccessRecent := (FLastAccessTick <> 0) and
      (Tick >= FLastAccessTick) and
      (Tick - FLastAccessTick <= SECTION_WINDOW_MS);
  end;

  procedure RetireMissingThreads;
  var
    Old: TPair<Cardinal,TSectionThreadNode>;
    Id: Cardinal;
  begin
    for Old in FNodes do
      if not Threads.ContainsKey(Old.Key) then Gone.Add(Old.Key);
    for Id in Gone do FNodes.Remove(Id);
  end;

  procedure InspectMappedThreads;
  var
    Pair: TPair<Cardinal,TThreadSample>;
  begin
    for Pair in Threads do
    begin
      NewNode := not FNodes.TryGetValue(Pair.Key, Node);
      if NewNode or (Node.StartAddress <> Pair.Value.StartAddress) then
      begin
        if NewNode and (FNodes.Count >= MAX_SECTION_NODES) then Continue;
        Node := Default(TSectionThreadNode);
        Node.StartAddress := Pair.Value.StartAddress;
        Node.Eligible := FPrimed and not Baseline;
      end;
      Mapped := False;
      if Baseline then
      begin
        Node.Eligible := False;
        ClearSectionConfirmation(Node);
      end
      else if Node.StartAddress <> 0 then
      begin
        try
          QueryOK := SectionQuery(Node.StartAddress, R);
          Mapped := ApplySectionRegion(Node, QueryOK, R, Tick);
        except
          ClearSectionConfirmation(Node);
          FNodes.AddOrSetValue(Pair.Key, Node);
          InvalidateConfirmations;
          raise;
        end;
      end
      else ClearSectionConfirmation(Node);
      if not Baseline and not Node.Reported and
        SectionCorrelationCandidate(Node.Eligible, Mapped,
          Node.Confirmations, SectionRecent, MappingRecent or Mapped,
          AccessRecent, EpochStable) and
        ((FLastReport = 0) or (Tick < FLastReport) or
         (Tick - FLastReport >= 60000)) then
      begin
        Include(Detected, dkSectionCorrelation);
        Node.Reported := True;
        FLastReport := Tick;
      end;
      FNodes.AddOrSetValue(Pair.Key, Node);
    end;
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
    FLastSectionTick := 0;
    FLastMappingTick := 0;
    FLastAccessTick := 0;
    FLastReport := 0;
  end;
  FLastTick := Tick;
  FHasTick := True;
  ObserveCorrelationContext;
  Gone := TList<Cardinal>.Create;
  try
    RetireMissingThreads;
    InspectMappedThreads;
    FPrimed := True;
  finally Gone.Free; end;
end;

{$IFDEF NHW_NATIVE5G_TESTS}
{$I Cozy.NHW.Native5G.SectionCorrelation.inc}
{$ENDIF}

end.
