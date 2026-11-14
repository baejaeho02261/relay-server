program Cozy_StartupProbe;
{$IFDEF FPC}{$MODE DELPHI}{$ELSE}{$APPTYPE CONSOLE}{$ENDIF}
uses
{ Cozy central text imports. }
  Cozy.Strings.Application in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Application.pas',
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}
  Cozy.Strings.TestsStartup in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsStartup.pas',

  {$IFDEF FPC}SysUtils,{$ELSE}System.SysUtils, Cozy.Api.Pointer,{$ENDIF}
  Cozy.Startup;
{$IFNDEF FPC}
procedure Check(Value: Boolean; const Code: string);
begin
  if not Value then raise EInvalidOpException.Create(Code);
end;
procedure CheckNotRun(Role: TGameComponentRole);
var Observation: TNativeStartupObservation;
begin
  Observation := CaptureNativeStartupObservation(Role);
  Check((Observation.Version = 1) and (Observation.Role = Role) and
    (Observation.State = nssNotRun) and (Observation.CompletedChecks = []) and
    (Observation.FailureStage = 0) and
    not NativeStartupObservationComplete(Observation), CozyText_StartupProbe_ROLE_WAS_NOT_RUN_96039276);
end;
procedure StandaloneGateNegatives;
var Rejected: Boolean; Stage: Integer; Observation: TNativeStartupObservation;
begin
  { This executable intentionally lacks the complete production role closure.
    The real gate must reject it; no resource or authentication bypass exists. }
  CheckNotRun(gcrLauncher); CheckNotRun(gcrConnect); CheckNotRun(gcrOverlay);
  Rejected := False; Stage := 0;
  try RequireNativeStartup(gcrLauncher, @Stage);
  except
    on E: EInvalidOpException do
      if E.Message = CozyText_StartupProbe_STARTUP_API_BINDINGS_INCOMPLETE_fcd640ac then Rejected := True
      else raise;
  end;
  Observation := CaptureNativeStartupObservation(gcrLauncher);
  Check(Rejected and (Stage = 31005) and (Observation.State = nssFailed) and
    (Observation.FailureStage = 31005) and (Observation.CompletedChecks = [nscAbi]) and
    not NativeStartupObservationComplete(Observation), CozyText_StartupProbe_UNSEALED_GATE_OBSERVATION_c0d925af);
  SealApiPointerStorage;
  Rejected := False; Stage := 0;
  try RequireNativeStartup(gcrLauncher, @Stage);
  except
    on E: EInvalidOpException do
      if E.Message = CozyText_StartupProbe_STARTUP_ROLE_API_CONTRACT_MISMATCH_b59f86bf then Rejected := True
      else raise;
  end;
  Observation := CaptureNativeStartupObservation(gcrLauncher);
  Check(Rejected and (Stage = 31006) and (Observation.State = nssFailed) and
    (Observation.FailureStage = 31006) and
    (Observation.CompletedChecks = [nscAbi, nscSealedPointers]) and
    not NativeStartupObservationComplete(Observation), CozyText_StartupProbe_PARTIAL_ROLE_GATE_OBSERVATION_0e195bbb);
  CheckNotRun(gcrConnect); CheckNotRun(gcrOverlay);
  Writeln(CozyText_StartupProbe_PASS_two_actual_local_gate_failures_recorded_sta_67246594);
end;
{$ENDIF}
begin
  try
    if not StartupAlgorithmsValid then
      raise Exception.Create(CozyText_StartupProbe_Startup_algorithm_known_answer_checks_failed_24491bd2);
    Writeln(CozyText_StartupProbe_PASS_standalone_startup_algorithm_known_answer_c_910f70a6);
    {$IFNDEF FPC}StandaloneGateNegatives;{$ENDIF}
    Writeln(CozyText_StartupProbe_Full_A_B_O_local_gates_require_their_separate_ro_cb86e2a3);
  except
    on E: Exception do
    begin
      Writeln(E.ClassName, CozyText_StartupProbe_Text_0d8a5adf, E.Message);
      ExitCode := 1;
    end;
  end;
end.
