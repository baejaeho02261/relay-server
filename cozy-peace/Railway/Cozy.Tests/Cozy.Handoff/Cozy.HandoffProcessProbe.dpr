program Cozy_HandoffProcessProbe;
{$APPTYPE CONSOLE}
{$R+}
{$Q+}
{$IFNDEF GAME_HANDOFF_CONTRACT_TESTS}
  {$MESSAGE FATAL 'This probe requires GAME_HANDOFF_CONTRACT_TESTS.'}
{$ENDIF}
uses
{ Cozy central text imports. }
  Cozy.Strings.Application in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Application.pas',
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Handoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Handoff.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Network in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Network.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.Security in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Security.pas',
  Cozy.Strings.TestsHandoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsHandoff.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}
 System.SysUtils, Cozy.Api.Pointer, Cozy.Handoff;
begin
  try
    SealApiPointerStorage;
    if not TryRunHandoffProcessChild then
    begin
      Writeln(CozyText_HandoffProcessProbe_PASS_a1181870, RunHandoffProcessContracts,
        CozyText_HandoffProcessProbe_actual_handoff_ownership_readiness_file_identity_352f6226);
      Writeln(CozyText_HandoffProcessProbe_Server_receipt_revocation_checks_run_separately__2c98cbcb);
    end;
  except on E: Exception do
    begin Writeln(CozyText_HandoffProcessProbe_FAIL_59ea8206, E.ClassName, CozyText_HandoffProcessProbe_Text_7567e595, E.Message); ExitCode := 1; end;
  end;
end.
