program Cozy_ClientFaultTest;
{$DEFINE GAME_PRODUCT_FAULT_TESTS}
{$I ..\..\Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc}
{$APPTYPE GUI}
uses
{ Cozy central text imports. }
  Cozy.Strings.Application in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Application.pas',
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Handoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Handoff.pas',
  Cozy.Strings.Identity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Identity.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.License in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.License.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Network in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Network.pas',
  Cozy.Strings.Overlay in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Overlay.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.Protection in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Protection.pas',
  Cozy.Strings.Security in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Security.pas',
  Cozy.Strings.TestsFaultInjection in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsFaultInjection.pas',
{$IF (Defined(GAME_HANDOFF_CONTRACT_TESTS))}
  Cozy.Strings.TestsHandoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsHandoff.pas',
{$ENDIF}
{$IF (Defined(GAME_DEVICE_IDENTITY_PROBE))}
  Cozy.Strings.TestsIdentity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsIdentity.pas',
{$ENDIF}
{$IF ((Defined(GAME_RELAY_SOCKET_CONTRACT_TESTS))) or (((Defined(GAME_NATIVE_ABI_TESTS))) or ((Defined(GAME_TLS_CONTRACT_TESTS))))}
  Cozy.Strings.TestsNetwork in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsNetwork.pas',
{$ENDIF}
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}

  Cozy.Api.Pointer in '..\..\Cozy.Source\Cozy.Platform\Cozy.Api.Pointer.pas',
  Cozy.ProductFaults in '..\..\Cozy.Source\Cozy.Application\Cozy.ProductFaults.pas',
  Cozy.Hashes in '..\..\Cozy.Source\Cozy.Crypto\Cozy.Hashes.pas',
  Cozy.Startup in '..\..\Cozy.Source\Cozy.Application\Cozy.Startup.pas',
  Cozy.License.Session in '..\..\Cozy.Source\Cozy.License\Cozy.License.Session.pas';
{$R '..\..\Cozy.Projects\Cozy.Client\Cozy.ClientResources.res'}
const TestBuildMarker: AnsiString = CozyText_ClientFaultTest_GAME_PRODUCT_FAULT_TEST_V1_a047a37f;
function GameBuildConfiguration: LongWord; stdcall;
begin Result := 2; end;
function GameProductFaultBuildMarker: PAnsiChar; stdcall;
begin Result := PAnsiChar(TestBuildMarker); end;
exports
  GameBuildConfiguration name 'GAME_BUILD_RELEASE_V1',
  GameProductFaultBuildMarker name 'GAME_PRODUCT_FAULT_TEST_V1';
begin
  try
    SealApiPointerStorage;
    RequireNativeStartup(gcrConnect);
    ExitCode := RunLicenseClient;
  except
    ExitCode := 1;
  end;
end.
