unit Cozy.NHW.KernelMappingEvidence;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Cozy.NHW.Logging;

type
  TKernelMappingEvidenceMonitor = class
  private
    FLastVulnerable: UInt64;
    FLastTimeline: UInt64;
    FLastModuleView: UInt64;
    FLastTrustPolicy: UInt64;
    FPendingSignature: Byte;
    FConfirmations: Byte;
    FLastConfirmTick: UInt64;
    FLastReport: UInt64;
    procedure ClearCandidate;
  public
    constructor Create;
    procedure Reset;
    procedure Observe(const Kinds: TDetectionKinds; Tick: UInt64;
      var Detected: TDetectionKinds);
  end;

function KernelMappingEvidenceCandidate(Byovd, Timeline, ModuleView,
  TrustPolicy: Boolean; Confirmations: Byte): Boolean;

implementation

const
  MAPPING_EVIDENCE_MS = 60000;
  MAPPING_CONFIRMATIONS = 2;
  MAPPING_REPORT_MS = 60000;

function Fresh(EvidenceTick, Tick: UInt64): Boolean; inline;
begin
  Result := (EvidenceTick <> 0) and (Tick >= EvidenceTick) and
    (Tick - EvidenceTick <= MAPPING_EVIDENCE_MS);
end;

function KernelMappingEvidenceCandidate(Byovd, Timeline, ModuleView,
  TrustPolicy: Boolean; Confirmations: Byte): Boolean;
var Families: Integer;
begin
  Families := Ord(Byovd) + Ord(Timeline) + Ord(ModuleView) + Ord(TrustPolicy);
  Result := (Confirmations >= MAPPING_CONFIRMATIONS) and
    ((Byovd and Timeline) or
     (TrustPolicy and (Families >= 2)) or
     ((Families >= 3) and ModuleView));
end;

constructor TKernelMappingEvidenceMonitor.Create;
begin
  inherited Create;
  Reset;
end;

procedure TKernelMappingEvidenceMonitor.ClearCandidate;
begin
  FPendingSignature := 0;
  FConfirmations := 0;
  FLastConfirmTick := 0;
end;

procedure TKernelMappingEvidenceMonitor.Reset;
begin
  FLastVulnerable := 0;
  FLastTimeline := 0;
  FLastModuleView := 0;
  FLastTrustPolicy := 0;
  FLastReport := 0;
  ClearCandidate;
end;

procedure TKernelMappingEvidenceMonitor.Observe(const Kinds: TDetectionKinds;
  Tick: UInt64; var Detected: TDetectionKinds);
var
  Byovd, Timeline, ModuleView, TrustPolicy: Boolean;
  Signature: Byte;
  CanReport: Boolean;
begin
  if dkVulnerableDriver in Kinds then FLastVulnerable := Tick;
  if dkDriverTimelineKernel in Kinds then FLastTimeline := Tick;
  if (dkDriverCrossView in Kinds) or (dkDriverIdentity in Kinds) or
     (dkSystemViewDisagreement in Kinds) then FLastModuleView := Tick;
  if (dkKernelTrustDowngrade in Kinds) or
     (dkCodeIntegrityPolicy in Kinds) or
     (dkCodeIntegrityEventCorrelation in Kinds) then FLastTrustPolicy := Tick;

  Byovd := Fresh(FLastVulnerable, Tick);
  Timeline := Fresh(FLastTimeline, Tick);
  ModuleView := Fresh(FLastModuleView, Tick);
  TrustPolicy := Fresh(FLastTrustPolicy, Tick);
  Signature := Byte(Ord(Byovd) or (Ord(Timeline) shl 1) or
    (Ord(ModuleView) shl 2) or (Ord(TrustPolicy) shl 3));
  if not KernelMappingEvidenceCandidate(Byovd, Timeline, ModuleView,
       TrustPolicy, MAPPING_CONFIRMATIONS) then
  begin
    ClearCandidate;
    Exit;
  end;
  if (FPendingSignature <> Signature) or
     ((FLastConfirmTick <> 0) and (Tick < FLastConfirmTick)) then
  begin
    FPendingSignature := Signature;
    FConfirmations := 1;
    FLastConfirmTick := Tick;
    Exit;
  end;
  if Tick > FLastConfirmTick then
  begin
    if FConfirmations < MAPPING_CONFIRMATIONS then Inc(FConfirmations);
    FLastConfirmTick := Tick;
  end;
  if not KernelMappingEvidenceCandidate(Byovd, Timeline, ModuleView,
       TrustPolicy, FConfirmations) then Exit;
  CanReport := (FLastReport = 0) or (Tick < FLastReport) or
    (Tick - FLastReport >= MAPPING_REPORT_MS);
  if CanReport then
  begin
    Include(Detected, dkKernelMappingEvidence);
    FLastReport := Tick;
  end;
end;

end.
