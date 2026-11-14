program Cozy_NativeAbiProbe;
{$APPTYPE CONSOLE}
{$R+}
{$Q+}
{$IFNDEF GAME_NATIVE_ABI_TESTS}
  {$MESSAGE FATAL 'Compile only this probe with -DGAME_NATIVE_ABI_TESTS.'}
{$ENDIF}
uses
{ Cozy central text imports. }
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Network in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Network.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
{$IF ((Defined(GAME_NATIVE_ABI_TESTS))) or ((Defined(GAME_TLS_CONTRACT_TESTS)))}
  Cozy.Strings.TestsNetwork in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsNetwork.pas',
{$ENDIF}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
 System.SysUtils, Cozy.WinApi, Cozy.Tls;
begin
  try
    if not Win64ApiLayoutValid then raise Exception.Create(CozyText_NativeAbiProbe_Win64_API_ABI_validation_failed_5a171dc3);
    WriteWin64AbiContract;
    WriteTlsAbiContract;
  except
    on E: Exception do
    begin
      System.Writeln(E.ClassName, CozyText_NativeAbiProbe_Text_5e4f0046, E.Message);
      Halt(1);
    end;
  end;
end.
