program CozyNHW_Scheduler_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Delphi Win64 only'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.Scheduler in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Scheduler.pas',
  Cozy.NHW.SchedulerNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SchedulerNative.pas',
  Cozy.NHW.WinPointers in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WinPointers.pas',
  Cozy.NHW.Types in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Types.pas',
  Cozy.NHW.Lifecycle in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Lifecycle.pas',
  Cozy.NHW.Native in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Native.pas',
  Cozy.NHW.Process in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Process.pas';

procedure Check(Condition: Boolean);
begin
  if not Condition then raise Exception.Create('Scheduler regression check failed');
end;

var
  A, B: TProcessScheduleState;
  T1, T2: TThreadScheduleState;
  Events: TDetectionKinds;
begin
  try
    A := Default(TProcessScheduleState);
    B := A;
    B.PriorityClass := 64;
    Check(CompareProcessSchedule(A, B) = []); // unknown => no detection

    A.ClassKnown := True; B.ClassKnown := True;
    A.PriorityClass := 32; B.PriorityClass := 64;
    A.AffinityKnown := True; B.AffinityKnown := True;
    A.ProcessMask := 3; B.ProcessMask := 1;
    A.GroupsKnown := True; B.GroupsKnown := True;
    A.Groups := '0'; B.Groups := '0,1';
    A.BoostKnown := True; B.BoostKnown := True;
    A.BoostDisabled := False; B.BoostDisabled := True;
    A.MitigationKnown[2] := True; B.MitigationKnown[2] := True;
    A.MitigationFlags[2] := 1; B.MitigationFlags[2] := 2;
    Events := CompareProcessSchedule(A, B);
    Check(dkProcessPriority in Events);
    Check(dkAffinity in Events);
    Check(dkCPUGroup in Events);
    Check(dkScheduling in Events);
    Check(dkMitigation in Events);
    Check(not (dkThreadPriority in Events));

    T1 := Default(TThreadScheduleState);
    T2 := Default(TThreadScheduleState);
    T2.Priority := 5;
    Check(CompareThreadSchedule(T1, T2) = []);
    T1.PriorityKnown := True; T2.PriorityKnown := True;
    T1.Priority := 0; T2.Priority := 2;
    T1.GroupKnown := True; T2.GroupKnown := True;
    T1.Group := 0; T2.Group := 1;
    T1.AffinityMask := 3; T2.AffinityMask := 7;
    T1.PowerKnown := True; T2.PowerKnown := True;
    T1.PowerControl := 0; T2.PowerControl := 1;
    T1.PowerState := 0; T2.PowerState := 1;
    Events := CompareThreadSchedule(T1, T2);
    Check(dkThreadPriority in Events);
    Check(dkAffinity in Events);
    Check(dkCPUGroup in Events);
    Check(dkScheduling in Events);
    Check(not (dkMitigation in Events));
    ExitCode := 0;
  except
    ExitCode := 1; // No console/file output, even in tests.
  end;
end.
