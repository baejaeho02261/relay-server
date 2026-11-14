program CozyNHW_KernelTrust5A_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Win64 only'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.KernelTrust.Native in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.KernelTrust.Native.pas',
  Cozy.NHW.BootTrust in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.BootTrust.pas',
  Cozy.NHW.VBSHVCI in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.VBSHVCI.pas',
  Cozy.NHW.VulnerableDriver in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.VulnerableDriver.pas',
  Cozy.NHW.DriverIdentity in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.DriverIdentity.pas',
  Cozy.NHW.DriverCrossView in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.DriverCrossView.pas';

procedure Check(Value: Boolean);
begin
  if not Value then raise Exception.Create('KernelTrust5A validation failed');
end;

var CI: TCodeIntegritySnapshot;
begin
  Check(not BootTrustDowngradeCandidate(False, True, False, 3));
  Check(not BootTrustDowngradeCandidate(True, False, False, 3));
  Check(not BootTrustDowngradeCandidate(True, True, False, 2));
  Check(BootTrustDowngradeCandidate(True, True, False, 3));

  CI := Default(TCodeIntegritySnapshot);
  CI.NativeValid := True;
  CI.Options := CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED;
  Check(HVCIRuntimeEnabled(CI));
  Check(not HVCIDowngradeCandidate(False, True, False, 3));
  Check(HVCIDowngradeCandidate(True, True, False, 3));

  Check(not VulnerableDriverCandidate(False, 2));
  Check(not VulnerableDriverCandidate(True, 1));
  Check(VulnerableDriverCandidate(True, 2));

  Check(not DriverIdentityCandidate(0, 3));
  Check(not DriverIdentityCandidate(1, 2));
  Check(DriverIdentityCandidate(1, 3));

  Check(not DriverCrossViewCandidate(0, 3));
  Check(not DriverCrossViewCandidate(1, 2));
  Check(DriverCrossViewCandidate(1, 3));
end.
