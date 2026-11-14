program Cozy_TlsContractProbe;

{$APPTYPE CONSOLE}
{$R+}
{$Q+}
{$IFNDEF GAME_TLS_CONTRACT_TESTS}
  {$MESSAGE FATAL 'Compile this probe with -DGAME_TLS_CONTRACT_TESTS.'}
{$ENDIF}

uses
{ Cozy central text imports. }
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Network in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Network.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.TestsNetwork in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsNetwork.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}

  System.SysUtils, Cozy.Tls, Cozy.Api.Guid;

var
  Guid: TGUID;
  EmptyGuid: TGUID;
begin
  try
    RunTlsContractTests;
    FillChar(Guid, SizeOf(Guid), $A5);
    FillChar(EmptyGuid, SizeOf(EmptyGuid), 0);
    if WindowsApiCreateGUID(Guid) <> 0 then
      raise Exception.Create(CozyText_TlsContractProbe_CoCreateGuid_failed_in_native_ABI_probe_9609819c);
    if CompareMem(@Guid, @EmptyGuid, SizeOf(Guid)) then
      raise Exception.Create(CozyText_TlsContractProbe_CoCreateGuid_returned_an_empty_GUID_5e2010d9);
    System.Writeln(CozyText_TlsContractProbe_PASS_real_Windows_GUID_ABI_and_success_output_a469591d);
    System.Writeln(CozyText_TlsContractProbe_Controlled_TLS_provider_faults_are_separate_from_b4871ab4);
    System.Writeln(CozyText_TlsContractProbe_This_suite_does_not_claim_a_real_server_handshak_0a46fc18);
  except
    on E: Exception do
    begin
      System.Writeln(E.ClassName, CozyText_TlsContractProbe_Text_547d5bb7, E.Message);
      Halt(1);
    end;
  end;
end.
