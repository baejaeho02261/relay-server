program CozyNHW_KernelTrust5B_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Win64 only'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.KernelTrust.Native in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.KernelTrust.Native.pas',
  Cozy.NHW.KernelTrustDowngrade in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.KernelTrustDowngrade.pas',
  Cozy.NHW.CodeIntegrityPolicy in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.CodeIntegrityPolicy.pas',
  Cozy.NHW.DriverTimeline in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.DriverTimeline.pas',
  Cozy.NHW.SystemViewDisagreement in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SystemViewDisagreement.pas',
  Cozy.NHW.KernelMappingEvidence in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.KernelMappingEvidence.pas';

procedure Check(Value: Boolean);
begin
  if not Value then raise Exception.Create('KernelTrust5B validation failed');
end;

var
  A, B: TCodeIntegrityPolicySnapshot;
begin
  Check(KernelTrustDowngradeMask(CODEINTEGRITY_OPTION_ENABLED,
    CODEINTEGRITY_OPTION_ENABLED) = 0);
  Check(KernelTrustDowngradeMask(CODEINTEGRITY_OPTION_ENABLED, 0) <> 0);
  Check(KernelTrustDowngradeMask(CODEINTEGRITY_OPTION_ENABLED,
    CODEINTEGRITY_OPTION_ENABLED or CODEINTEGRITY_OPTION_TESTSIGN) <> 0);
  Check(not KernelTrustDowngradeCandidate(1, 2));
  Check(KernelTrustDowngradeCandidate(1, 3));

  A := Default(TCodeIntegrityPolicySnapshot);
  A.Valid := True; A.PolicyCount := 2; A.Fingerprint := 10; A.HasSiPolicy := True;
  B := A;
  Check(not CodeIntegrityPolicyChanged(A, B));
  B.PolicyCount := 1;
  Check(CodeIntegrityPolicyChanged(A, B));
  Check(CodeIntegrityPolicyReduced(A, B));
  Check(not CodeIntegrityPolicyCandidate(True, True, True, 2));
  Check(CodeIntegrityPolicyCandidate(True, True, True, 3));
  Check(not CodeIntegrityPolicyCandidate(True, False, True, 3));
  Check(CodeIntegrityPolicyCandidate(True, False, True, 4));

  Check(not DriverTimelineCandidate(False, 1000, 2));
  Check(not DriverTimelineCandidate(True, 70000, 2));
  Check(not DriverTimelineCandidate(True, 1000, 1));
  Check(DriverTimelineCandidate(True, 1000, 2));

  Check(not SystemViewDisagreementCandidate(SVD_MODULE_BASE, 3));
  Check(not SystemViewDisagreementCandidate(SVD_MODULE_BASE or SVD_MODULE_PATH, 2));
  Check(SystemViewDisagreementCandidate(SVD_MODULE_BASE or SVD_HVCI_STATE, 3));

  Check(not KernelMappingEvidenceCandidate(False, True, False, False, 2));
  Check(KernelMappingEvidenceCandidate(True, True, False, False, 2));
  Check(KernelMappingEvidenceCandidate(False, False, True, True, 2));
  Check(not KernelMappingEvidenceCandidate(True, False, False, False, 2));
end.
