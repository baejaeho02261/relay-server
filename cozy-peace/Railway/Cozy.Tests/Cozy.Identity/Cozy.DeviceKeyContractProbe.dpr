program Cozy_DeviceKeyContractProbe;
{$APPTYPE CONSOLE}
{$R+}
{$Q+}
{$IFNDEF GAME_DEVICE_IDENTITY_PROBE}
  {$MESSAGE FATAL 'This isolated test requires GAME_DEVICE_IDENTITY_PROBE.'}
{$ENDIF}
uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Identity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Identity.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.Security in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Security.pas',
  Cozy.Strings.TestsIdentity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsIdentity.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}
 System.SysUtils, Cozy.Api.Pointer, Cozy.DeviceKey;
begin
  try
    SealApiPointerStorage;
    RunDeviceKeyConstructionContracts;
    Writeln(CozyText_DeviceKeyContractProbe_PASS_device_key_partial_construction_ownership_c_84e24df0);
  except
    on E: Exception do
    begin
      Writeln(E.ClassName, CozyText_DeviceKeyContractProbe_Text_f28e0094, E.Message);
      ExitCode := 1;
    end;
  end;
end.
