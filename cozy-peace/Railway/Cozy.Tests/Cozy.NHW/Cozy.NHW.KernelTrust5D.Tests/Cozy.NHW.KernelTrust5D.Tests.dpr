program CozyNHW_KernelTrust5D_Tests;

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
  Cozy.NHW.KernelTrust.PlatformNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.KernelTrust.PlatformNative.pas',
  Cozy.NHW.DriverLoadProvenance in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.DriverLoadProvenance.pas',
  Cozy.NHW.DriverSignerAttestation in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.DriverSignerAttestation.pas',
  Cozy.NHW.DriverServiceTimeline in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.DriverServiceTimeline.pas',
  Cozy.NHW.HypervisorVBSCrossView in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.HypervisorVBSCrossView.pas',
  Cozy.NHW.KernelDMAIOMMUTrust in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.KernelDMAIOMMUTrust.pas';

procedure Check(Value: Boolean);
begin
  if not Value then raise Exception.Create('KernelTrust5D validation failed');
end;

var
  P: TPlatformSecuritySnapshot;
  CI: TCodeIntegritySnapshot;
  Mask: Byte;
begin
  Check(not DriverLoadProvenanceCandidate(False, False, 3));
  Check(not DriverLoadProvenanceCandidate(False, True, 2));
  Check(DriverLoadProvenanceCandidate(False, True, 3));
  Check(not DriverLoadProvenanceCandidate(True, True, 3));

  Check(not DriverSignerAttestationCandidate(True, False, True, True, 3));
  Check(not DriverSignerAttestationCandidate(True, True, True, False, 3));
  Check(DriverSignerAttestationCandidate(True, True, True, True, 3));

  Check(not DriverServiceTimelineCandidate(True, False, 1000, 2));
  Check(not DriverServiceTimelineCandidate(True, True, 1000, 1));
  Check(DriverServiceTimelineCandidate(True, True, 1000, 2));
  Check(not DriverServiceTimelineCandidate(True, True, 100000, 2));

  P := Default(TPlatformSecuritySnapshot);
  CI := Default(TCodeIntegritySnapshot);
  P.DeviceGuardValid := True;
  P.HypervisorViewValid := True;
  P.VirtFirmwareValid := True;
  P.VBSStatus := 0;
  P.HypervisorPresent := False;
  P.VirtFirmwareEnabled := True;
  CI.NativeValid := True;
  CI.Options := CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED;
  Mask := HypervisorVBSCrossViewMask(P, CI, True);
  Check(HypervisorVBSCrossViewCandidate(Mask, 3));

  Check(not KernelDMAIOMMUTrustCandidate(False, False, False, True, True, 3));
  Check(not KernelDMAIOMMUTrustCandidate(True, False, False, True, False, 3));
  Check(not KernelDMAIOMMUTrustCandidate(True, False, False, True, True, 2));
  Check(KernelDMAIOMMUTrustCandidate(True, False, False, True, True, 3));
end.
