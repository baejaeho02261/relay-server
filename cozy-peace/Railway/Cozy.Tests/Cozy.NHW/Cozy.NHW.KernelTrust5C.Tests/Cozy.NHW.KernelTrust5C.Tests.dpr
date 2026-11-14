program CozyNHW_KernelTrust5C_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Win64 only'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.WinPointers in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WinPointers.pas',
  Cozy.NHW.Native in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Native.pas',
  Cozy.NHW.NativeSafety in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.NativeSafety.pas',
  Cozy.NHW.KernelTrust.Native in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.KernelTrust.Native.pas',
  Cozy.NHW.KernelTrust.EventLog in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.KernelTrust.EventLog.pas',
  Cozy.NHW.BootAttestationContinuity in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.BootAttestationContinuity.pas',
  Cozy.NHW.CodeIntegrityEventCorrelation in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.CodeIntegrityEventCorrelation.pas',
  Cozy.NHW.KernelTelemetryGap in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.KernelTelemetryGap.pas',
  Cozy.NHW.SessionTrustLadder in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SessionTrustLadder.pas',
  Cozy.NHW.ResponsePathMesh in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ResponsePathMesh.pas';

procedure Check(Value: Boolean);
begin
  if not Value then raise Exception.Create('KernelTrust5C validation failed');
end;

var
  A, B: TBootIdentity;
begin
  A := Default(TBootIdentity);
  B := Default(TBootIdentity);
  A.LowPart := 1; A.HighPart := 2;
  B := A;
  Check(not BootAttestationContinuityCandidate(A, B, 3));
  B.LowPart := 3;
  Check(not BootAttestationContinuityCandidate(A, B, 2));
  Check(BootAttestationContinuityCandidate(A, B, 3));

  Check(not CodeIntegrityEventCorrelationCandidate(CIE_DRIVER_SIGNATURE,
    False, 2));
  Check(not CodeIntegrityEventCorrelationCandidate(CIE_DRIVER_SIGNATURE,
    True, 1));
  Check(CodeIntegrityEventCorrelationCandidate(CIE_DRIVER_SIGNATURE,
    True, 2));

  Check(not KernelTelemetryGapCandidate(KTG_NATIVE_MODULE, 3));
  Check(not KernelTelemetryGapCandidate(KTG_NATIVE_MODULE or KTG_PSAPI_MODULE,
    2));
  Check(not KernelTelemetryGapCandidate(KTG_NATIVE_MODULE or KTG_PSAPI_MODULE,
    3));
  Check(KernelTelemetryGapCandidate(KTG_NATIVE_MODULE or KTG_CODE_INTEGRITY,
    3));
  Check(KernelTelemetryGapCandidate(KTG_PSAPI_MODULE or KTG_BOOT_TRUST or
    KTG_CODE_INTEGRITY or KTG_CI_EVENT_LOG, 3));

  Check(DesiredKernelSessionTrust(0) = kstNormal);
  Check(DesiredKernelSessionTrust($01) = kstGuarded);
  Check(DesiredKernelSessionTrust($03) = kstDegraded);
  Check(DesiredKernelSessionTrust($07) = kstUntrusted);
  Check(DesiredKernelSessionTrust($11) = kstUntrusted);

  Check(not ResponsePathQuorum(RESPONSE_VOTE_TRUST));
  Check(ResponsePathQuorum(RESPONSE_VOTE_TRUST or RESPONSE_VOTE_DRIVER));
  Check(ResponsePathQuorum(RESPONSE_VOTE_DRIVER or RESPONSE_VOTE_INTEGRITY));
end.
