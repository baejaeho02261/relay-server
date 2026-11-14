program Cozy_HandoffPipeProbe;
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
    Writeln(CozyText_HandoffPipeProbe_PASS_f2f8c9a1, RunHandoffPipeContracts, CozyText_HandoffPipeProbe_production_anonymous_pipe_range_fragment_deadlin_1f868d51);
    Writeln(CozyText_HandoffPipeProbe_Fragment_writers_were_cancelled_joined_and_owned_52340e00);
    Writeln(CozyText_HandoffPipeProbe_This_does_not_test_child_processes_the_server_or_e8fa09c0);
  except on E: Exception do begin
    Writeln(CozyText_HandoffPipeProbe_FAIL_f2314237, E.ClassName, CozyText_HandoffPipeProbe_Text_553a537a, E.Message); ExitCode := 1;
  end; end;
end.
