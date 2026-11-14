unit Cozy.NHW.IncidentReconstruction;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, Cozy.NHW.Logging;

type
  TIncidentFamily = (ifExternal, ifMemory, ifThread,
    ifModule, ifObservationGap);
  TIncidentFamilies = set of TIncidentFamily;
  TInMemoryIncident = record
    Sequence: UInt64;
    TargetPID: Cardinal;
    Epoch: Cardinal;
    ActorPID: Cardinal; // stays zero without independently verified actor
    FirstTick: UInt64;
    LastTick: UInt64;
    Observations: Cardinal;
    HighestScore: Byte;
    Families: TIncidentFamilies;
    Detected: TDetectionKinds;
    Reported: Boolean;
  end;

  // v79: RAM-only bounded incident ring. Similar observations within the
  // SAME target/epoch are joined; distinct PIDs/epochs are never merged.
  TIncidentReconstruction = class
  private
    FItems: array[0..63] of TInMemoryIncident;
    FNext, FCount, FOpen: Integer;
    FSequence: UInt64;
    FLastReport: UInt64;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Prune(Tick: UInt64);
    procedure Reset;
    procedure RecordFrame(TargetPID, Epoch: Cardinal; Tick: UInt64;
      const Kinds: TDetectionKinds; HighExternal,
      Reliable: Boolean; Score: Integer;
      var Detected: TDetectionKinds);
    function Recent(IndexFromNewest: Integer;
      out Incident: TInMemoryIncident): Boolean;
    property Count: Integer read FCount;
  end;

function ClassifyIncident(const Kinds: TDetectionKinds;
  HighExternal, Reliable: Boolean): TIncidentFamilies;
function IncidentFamilyCount(Families: TIncidentFamilies): Integer;
function IncidentCandidate(Families: TIncidentFamilies;
  Observations: Cardinal; Score: Integer; Reliable: Boolean): Boolean;

implementation

uses Cozy.NHW.NativeSafety;

const INCIDENT_JOIN_MS = 20000;

function ClassifyIncident(const Kinds: TDetectionKinds;
  HighExternal, Reliable: Boolean): TIncidentFamilies;
begin
  Result := [];
  if HighExternal or
    ((Kinds * [dkProcess, dkThread, dkEscalation,
      dkTemporalHandleGraph, dkCrossAccess]) <> []) then
    Include(Result, ifExternal);
  if (Kinds * [dkPECodeIntegrity, dkImageCOWIntegrity,
    dkWriteIntegrity, dkPrivateExecRegion, dkExecutableLifecycle,
    dkImportRedirect, dkTLSCallbackIntegrity, dkCodeProvenance,
    dkIndirectTarget]) <> [] then
    Include(Result, ifMemory);
  if (Kinds * [dkPrivateThread, dkRemoteThread,
    dkExecutionProvenance, dkThreadTimeline,
    dkThreadProvenance, dkThreadSpawn]) <> [] then
    Include(Result, ifThread);
  if (Kinds * [dkModuleOrigin, dkSectionBacking,
    dkFileAttestation, dkLoaderCrossView,
    dkSectionCorrelation]) <> [] then
    Include(Result, ifModule);
  if (not Reliable) or
    ((Kinds * [dkETWLoss, dkCoverageGap,
      dkObservationUncertain, dkSensorPressure]) <> []) then
    Include(Result, ifObservationGap);
end;

function IncidentFamilyCount(Families: TIncidentFamilies): Integer;
var F: TIncidentFamily;
begin
  Result := 0;
  for F := Low(TIncidentFamily) to High(TIncidentFamily) do
    if (F <> ifObservationGap) and (F in Families) then Inc(Result);
end;

function IncidentCandidate(Families: TIncidentFamilies;
  Observations: Cardinal; Score: Integer; Reliable: Boolean): Boolean;
begin
  Result := Reliable and (Observations >= 2) and
    (IncidentFamilyCount(Families) >= 3) and (Score >= 60);
end;

constructor TIncidentReconstruction.Create;
begin inherited Create; Reset; end;

destructor TIncidentReconstruction.Destroy;
begin Reset; inherited Destroy; end;

procedure TIncidentReconstruction.Prune(Tick: UInt64);
var Oldest: Integer;
begin
  while FCount > 0 do
  begin
    Oldest := (FNext - FCount + Length(FItems)) mod Length(FItems);
    if not NHWExpired(FItems[Oldest].LastTick, Tick, 60000) then Break;
    if FOpen = Oldest then FOpen := -1;
    FItems[Oldest] := Default(TInMemoryIncident);
    Dec(FCount);
  end;
end;

procedure TIncidentReconstruction.Reset;
begin
  FillChar(FItems, SizeOf(FItems), 0);
  FNext := 0;
  FCount := 0;
  FOpen := -1;
  FSequence := 0;
  FLastReport := 0;
end;

procedure TIncidentReconstruction.RecordFrame(TargetPID, Epoch: Cardinal;
  Tick: UInt64; const Kinds: TDetectionKinds;
  HighExternal, Reliable: Boolean; Score: Integer;
  var Detected: TDetectionKinds);
var
  Families: TIncidentFamilies;
  Item: TInMemoryIncident;
  Index: Integer;
  procedure SelectIncident(out Index: Integer; out Item: TInMemoryIncident);
  begin
    Index := FOpen;
    if (Index < 0) or (FItems[Index].TargetPID <> TargetPID) or
      (FItems[Index].Epoch <> Epoch) or
      (Tick < FItems[Index].LastTick) or
      (Tick - FItems[Index].LastTick > INCIDENT_JOIN_MS) then
    begin
      Index := FNext;
      FNext := (FNext + 1) mod Length(FItems);
      if FCount < Length(FItems) then Inc(FCount);
      FOpen := Index;
      Inc(FSequence);
      Item := Default(TInMemoryIncident);
      Item.Sequence := FSequence;
      Item.TargetPID := TargetPID;
      Item.Epoch := Epoch;
      Item.FirstTick := Tick;
      Item.ActorPID := 0;
    end
    else Item := FItems[Index];
  end;

  procedure AccumulateIncidentEvidence;
  begin
    Inc(Item.Observations);
    Item.LastTick := Tick;
    Item.Detected := Item.Detected + Kinds;
    Item.Families := Item.Families + Families;
    if Score > Item.HighestScore then Item.HighestScore := Byte(Score);
  end;

  procedure ReportIncident;
  begin
    if not Item.Reported and
      IncidentCandidate(Item.Families, Item.Observations,
        Item.HighestScore, Reliable) and
      ((FLastReport = 0) or (Tick < FLastReport) or
       (Tick - FLastReport >= 60000)) then
    begin
      Include(Detected, dkIncidentReconstruction);
      Item.Reported := True;
      FLastReport := Tick;
    end;
  end;

begin
  // Pure visibility state without an actual signal does not form an incident.
  if (Kinds = []) and not HighExternal then Exit;
  Families := ClassifyIncident(Kinds, HighExternal, Reliable);
  if Families = [] then Exit;
  if (Score < 0) then Score := 0;
  if (Score > 100) then Score := 100;
  SelectIncident(Index, Item);
  AccumulateIncidentEvidence;
  ReportIncident;
  FItems[Index] := Item;
end;

function TIncidentReconstruction.Recent(IndexFromNewest: Integer;
  out Incident: TInMemoryIncident): Boolean;
var Pos: Integer;
begin
  Incident := Default(TInMemoryIncident);
  Result := (IndexFromNewest >= 0) and (IndexFromNewest < FCount);
  if not Result then Exit;
  Pos := (FNext - 1 - IndexFromNewest + Length(FItems)) mod
    Length(FItems);
  Incident := FItems[Pos];
end;

end.
