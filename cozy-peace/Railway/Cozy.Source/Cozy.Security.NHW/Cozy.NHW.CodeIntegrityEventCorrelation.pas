unit Cozy.NHW.CodeIntegrityEventCorrelation;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Cozy.NHW.Logging,
  Cozy.NHW.KernelTrust.EventLog;

type
  TCodeIntegrityEventCorrelationMonitor = class
  private
    FPrimed: Boolean;
    FLastRecordId: UInt64;
    FPendingMask: Cardinal;
    FPendingTick: UInt64;
    FConfirmations: Byte;
    FLastEvidenceTick: UInt64;
    FLastScan: UInt64;
    FLastReport: UInt64;
    FLastCaptureValid: Boolean;
    procedure ClearCandidate;
    procedure ObserveKernelEvidence(const Kinds: TDetectionKinds; Tick: UInt64);
  public
    constructor Create;
    procedure Reset;
    procedure Examine(const Kinds: TDetectionKinds; Tick: UInt64;
      var Detected: TDetectionKinds);
    property LastCaptureValid: Boolean read FLastCaptureValid;
  end;

function CodeIntegrityEventCorrelationCandidate(EventMask: Cardinal;
  KernelEvidenceRecent: Boolean; Confirmations: Byte): Boolean;

implementation

const
  CI_EVENT_SCAN_MS = 10000;
  CI_EVENT_EVIDENCE_MS = 60000;
  CI_EVENT_CONFIRMATIONS = 2;
  CI_EVENT_REPORT_MS = 60000;

function CodeIntegrityEventCorrelationCandidate(EventMask: Cardinal;
  KernelEvidenceRecent: Boolean; Confirmations: Byte): Boolean;
begin
  Result := (EventMask <> 0) and KernelEvidenceRecent and
    (Confirmations >= CI_EVENT_CONFIRMATIONS);
end;

constructor TCodeIntegrityEventCorrelationMonitor.Create;
begin
  inherited Create;
  Reset;
end;

procedure TCodeIntegrityEventCorrelationMonitor.ClearCandidate;
begin
  FPendingMask := 0;
  FPendingTick := 0;
  FConfirmations := 0;
end;

procedure TCodeIntegrityEventCorrelationMonitor.Reset;
begin
  FPrimed := False;
  FLastRecordId := 0;
  FLastEvidenceTick := 0;
  FLastScan := 0;
  FLastReport := 0;
  FLastCaptureValid := False;
  ClearCandidate;
end;

procedure TCodeIntegrityEventCorrelationMonitor.ObserveKernelEvidence(
  const Kinds: TDetectionKinds; Tick: UInt64);
begin
  if (Kinds * [dkVulnerableDriver, dkDriverIdentity, dkDriverCrossView,
      dkKernelTrustDowngrade, dkCodeIntegrityPolicy, dkDriverTimelineKernel,
      dkSystemViewDisagreement, dkKernelMappingEvidence]) <> [] then
    FLastEvidenceTick := Tick;
end;

procedure TCodeIntegrityEventCorrelationMonitor.Examine(
  const Kinds: TDetectionKinds; Tick: UInt64; var Detected: TDetectionKinds);
var
  Summary: TCodeIntegrityEventSummary;
  EvidenceRecent, CanReport: Boolean;
begin
  ObserveKernelEvidence(Kinds, Tick);
  if (FLastScan <> 0) and (Tick < FLastScan) then
  begin
    Reset;
    Exit;
  end;
  if (FLastScan <> 0) and (Tick - FLastScan < CI_EVENT_SCAN_MS) then Exit;
  FLastScan := Tick;
  FLastCaptureValid := CaptureCodeIntegrityEventSummary(FLastRecordId, Summary);
  if not FLastCaptureValid or not Summary.Valid then
  begin
    ClearCandidate;
    Exit;
  end;
  if not FPrimed then
  begin
    FPrimed := True;
    FLastRecordId := Summary.LatestRecordId;
    ClearCandidate;
    Exit;
  end;
  if (Summary.LatestRecordId <> 0) and
     (Summary.LatestRecordId < FLastRecordId) then
  begin
    FLastRecordId := Summary.LatestRecordId;
    ClearCandidate;
    Exit;
  end;
  if Summary.NewRecordCount <> 0 then
  begin
    if Summary.LatestRecordId > FLastRecordId then
      FLastRecordId := Summary.LatestRecordId;
    FPendingMask := Summary.StrongMask;
    FPendingTick := Tick;
    FConfirmations := 1;
  end;
  if (FPendingMask = 0) or (FPendingTick = 0) or (Tick < FPendingTick) or
     (Tick - FPendingTick > CI_EVENT_EVIDENCE_MS) then
  begin
    ClearCandidate;
    Exit;
  end;
  EvidenceRecent := (FLastEvidenceTick <> 0) and (Tick >= FLastEvidenceTick) and
    (Tick - FLastEvidenceTick <= CI_EVENT_EVIDENCE_MS);
  if EvidenceRecent and (Tick > FPendingTick) and
     (FConfirmations < CI_EVENT_CONFIRMATIONS) then
    Inc(FConfirmations);
  if not CodeIntegrityEventCorrelationCandidate(FPendingMask,
       EvidenceRecent, FConfirmations) then Exit;
  CanReport := (FLastReport = 0) or (Tick < FLastReport) or
    (Tick - FLastReport >= CI_EVENT_REPORT_MS);
  if CanReport then
  begin
    Include(Detected, dkCodeIntegrityEventCorrelation);
    FLastReport := Tick;
  end;
end;

end.
