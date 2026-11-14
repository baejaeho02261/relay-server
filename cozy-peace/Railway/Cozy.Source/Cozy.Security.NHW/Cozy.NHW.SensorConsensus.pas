unit Cozy.NHW.SensorConsensus;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, Cozy.NHW.Logging;

type
  TConsensusFamily = (cfExternalAccess, cfThread, cfMemory,
    cfModule, cfObserver);
  TConsensusFamilies = set of TConsensusFamily;
  TConsensusFrame = record
    Tick: UInt64;
    Families: TConsensusFamilies;
    IndependentCount: Byte;
    Confidence: Byte;
    VisibilityReliable: Boolean;
    Corroborated: Boolean;
  end;

  // v92: evidence quality is not attack attribution or a standalone alert.
  TSensorConsensus = class
  private
    FLast: TConsensusFrame;
  public
    constructor Create;
    procedure Reset;
    procedure Evaluate(const Kinds: TDetectionKinds;
      ExternalAccess, ObserverMismatch, IdentityValid,
      TraceAvailable, TraceLost: Boolean;
      Tick: UInt64);
    procedure ConstrainToObservedRoots(RootCount: Byte; Complete: Boolean);
    property Last: TConsensusFrame read FLast;
  end;

function NHWConsensusCount(Families: TConsensusFamilies): Integer;

implementation

function NHWConsensusCount(Families: TConsensusFamilies): Integer;
var F: TConsensusFamily;
begin
  Result := 0;
  for F := Low(TConsensusFamily) to High(TConsensusFamily) do
    if F in Families then Inc(Result);
end;

constructor TSensorConsensus.Create;
begin inherited Create; Reset; end;

procedure TSensorConsensus.Reset;
begin FLast := Default(TConsensusFrame); end;

procedure TSensorConsensus.Evaluate(const Kinds: TDetectionKinds;
  ExternalAccess, ObserverMismatch, IdentityValid,
  TraceAvailable, TraceLost: Boolean; Tick: UInt64);
var N, Confidence: Integer;
begin
  FLast := Default(TConsensusFrame);
  FLast.Tick := Tick;
  if ExternalAccess or
     ((Kinds * [dkProcess, dkThread, dkEscalation,
       dkTemporalHandleGraph]) <> []) then
    Include(FLast.Families, cfExternalAccess);
  if (Kinds * [dkPrivateThread, dkRemoteThread,
    dkExecutionProvenance, dkThreadTimeline, dkThreadProvenance]) <> [] then
    Include(FLast.Families, cfThread);
  if (Kinds * [dkPECodeIntegrity, dkWriteIntegrity,
    dkImageCOWIntegrity, dkPrivateExecRegion,
    dkExecutableLifecycle, dkMemoryRelease]) <> [] then
    Include(FLast.Families, cfMemory);
  if (Kinds * [dkModuleOrigin, dkLoaderCrossView,
    dkFileAttestation, dkSectionBacking]) <> [] then
    Include(FLast.Families, cfModule);
  if ObserverMismatch then
    Include(FLast.Families, cfObserver);
  N := NHWConsensusCount(FLast.Families);
  FLast.IndependentCount := Byte(N);
  FLast.VisibilityReliable := IdentityValid and TraceAvailable and
    not TraceLost;
  Confidence := 10 + N * 20;
  if TraceLost then Dec(Confidence, 30);
  if not IdentityValid then Confidence := 0;
  if not TraceAvailable and (Confidence > 40) then Confidence := 40;
  if Confidence < 0 then Confidence := 0;
  if Confidence > 100 then Confidence := 100;
  FLast.Confidence := Byte(Confidence);
  FLast.Corroborated := (N >= 2) and
    FLast.VisibilityReliable and (Confidence >= 50);
end;

procedure TSensorConsensus.ConstrainToObservedRoots(RootCount: Byte;
  Complete: Boolean);
var Ceiling: Integer;
begin
  // Conservative metadata cap only; legacy detection kinds are untouched.
  if FLast.IndependentCount > RootCount then
    FLast.IndependentCount := RootCount;
  Ceiling := 10 + Integer(FLast.IndependentCount) * 20;
  if not Complete and (Ceiling > 40) then Ceiling := 40;
  if Integer(FLast.Confidence) > Ceiling then
    FLast.Confidence := Byte(Ceiling);
  FLast.VisibilityReliable := FLast.VisibilityReliable and Complete;
  FLast.Corroborated := FLast.Corroborated and Complete and
    (FLast.IndependentCount >= 2) and (FLast.Confidence >= 50);
end;

end.
