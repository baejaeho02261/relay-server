unit Cozy.NHW.KernelTrust.CorrelationPolicy;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Cozy.NHW.Logging,
  Cozy.NHW.SessionTrustLadder;

type
  TKernelCorrelationSummary = record
    FamilyMask: Byte;
    StrongSignalCount: Byte;
    IndependentFamilies: Byte;
    Score: Word;
    CanInvalidate: Boolean;
  end;

function EvaluateKernelCorrelation(const Kinds: TDetectionKinds;
  Trust: TKernelSessionTrust; ResponseQuorum: Boolean): TKernelCorrelationSummary;

implementation

const
  KCF_BOOT = $01;
  KCF_DRIVER = $02;
  KCF_VIEW = $04;
  KCF_INTEGRITY = $08;
  KCF_MAPPING = $10;
  KCF_TELEMETRY = $20;

function BitCount8(V: Byte): Byte;
begin
  Result := 0;
  while V <> 0 do
  begin
    Inc(Result);
    V := V and (V - 1);
  end;
end;

procedure AddScore(var S: TKernelCorrelationSummary; Value: Word;
  Strong: Boolean);
begin
  if High(Word) - S.Score < Value then S.Score := High(Word)
  else Inc(S.Score, Value);
  if Strong and (S.StrongSignalCount < High(Byte)) then
    Inc(S.StrongSignalCount);
end;

function EvaluateKernelCorrelation(const Kinds: TDetectionKinds;
  Trust: TKernelSessionTrust; ResponseQuorum: Boolean): TKernelCorrelationSummary;
begin
  Result := Default(TKernelCorrelationSummary);

  if (Kinds * [dkBootTrust, dkVBSHVCI, dkBootAttestationContinuity,
      dkHypervisorVBSCrossView, dkKernelDMAIOMMUTrust]) <> [] then
    Result.FamilyMask := Result.FamilyMask or KCF_BOOT;
  if (Kinds * [dkVulnerableDriver, dkDriverTimelineKernel,
      dkDriverLoadProvenance, dkDriverServiceTimeline]) <> [] then
    Result.FamilyMask := Result.FamilyMask or KCF_DRIVER;
  if (Kinds * [dkDriverIdentity, dkDriverCrossView,
      dkSystemViewDisagreement]) <> [] then
    Result.FamilyMask := Result.FamilyMask or KCF_VIEW;
  if (Kinds * [dkKernelTrustDowngrade, dkCodeIntegrityPolicy,
      dkCodeIntegrityEventCorrelation, dkDriverSignerAttestation]) <> [] then
    Result.FamilyMask := Result.FamilyMask or KCF_INTEGRITY;
  if dkKernelMappingEvidence in Kinds then
    Result.FamilyMask := Result.FamilyMask or KCF_MAPPING;
  if dkKernelTelemetryGap in Kinds then
    Result.FamilyMask := Result.FamilyMask or KCF_TELEMETRY;

  if dkKernelMappingEvidence in Kinds then AddScore(Result, 5, True);
  if dkVulnerableDriver in Kinds then AddScore(Result, 4, True);
  if dkKernelTrustDowngrade in Kinds then AddScore(Result, 4, True);
  if dkCodeIntegrityEventCorrelation in Kinds then AddScore(Result, 4, True);
  if dkDriverSignerAttestation in Kinds then AddScore(Result, 3, True);
  if dkDriverServiceTimeline in Kinds then AddScore(Result, 3, True);
  if dkKernelTelemetryGap in Kinds then AddScore(Result, 3, True);

  if (Kinds * [dkDriverIdentity, dkDriverCrossView,
      dkSystemViewDisagreement]) <> [] then AddScore(Result, 2, False);
  if (Kinds * [dkBootTrust, dkVBSHVCI, dkBootAttestationContinuity,
      dkHypervisorVBSCrossView, dkKernelDMAIOMMUTrust]) <> [] then
    AddScore(Result, 2, False);
  if (Kinds * [dkDriverTimelineKernel, dkDriverLoadProvenance,
      dkCodeIntegrityPolicy]) <> [] then AddScore(Result, 2, False);

  Result.IndependentFamilies := BitCount8(Result.FamilyMask);
  Result.CanInvalidate := (Trust = kstUntrusted) and ResponseQuorum and
    (((Result.StrongSignalCount >= 1) and
      (Result.IndependentFamilies >= 2) and (Result.Score >= 6)) or
     ((Result.IndependentFamilies >= 3) and (Result.Score >= 8)));
end;

end.
