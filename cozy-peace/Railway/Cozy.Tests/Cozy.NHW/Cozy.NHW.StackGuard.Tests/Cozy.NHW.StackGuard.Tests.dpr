program CozyNHW_StackGuard_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Win64 only'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.StackGuard in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.StackGuard.pas',
  Cozy.NHW.StackNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.StackNative.pas';

procedure Require(Condition: Boolean);
begin
  if not Condition then Halt(1);
end;

var
  A, B: TNativeStackSnapshot;
  S: TThreadStackState;
  D: TStackSignals;
begin
  A := Default(TNativeStackSnapshot);
  A.Known := True;
  A.BoundsValid := True;
  A.CreateTime := 12345;
  A.StackBase := $300000;
  A.StackLimit := $2F0000;
  A.AllocationBase := $200000;
  A.ReservedBytes := $100000;
  A.CommittedBytes := $10000;
  A.HasGuard := True;
  S := Default(TThreadStackState);
  S.Snapshot := A;
  S.WindowTick := 1000;
  S.WindowCommit := A.CommittedBytes;

  B := A;
  D := AnalyzeStackTransition(S, B, 1200);
  Require(D = []);

  B.HasExecutablePage := True;
  D := AnalyzeStackTransition(S, B, 1300);
  Require(ssExecute in D);
  D := AnalyzeStackTransition(S, B, 1400);
  Require(not (ssExecute in D));

  B.HasGuard := False;
  D := AnalyzeStackTransition(S, B, 1500);
  Require(not (ssGuard in D));
  D := AnalyzeStackTransition(S, B, 1600);
  Require(not (ssGuard in D));
  D := AnalyzeStackTransition(S, B, 1700);
  Require(ssGuard in D);
  D := AnalyzeStackTransition(S, B, 1800);
  Require(not (ssGuard in D));

  B.HasGuard := True;
  B.CommittedBytes := $60000;
  D := AnalyzeStackTransition(S, B, 1900);
  Require(ssGrowth in D);
  Require(not (ssGuard in D));

  B.StackBase := $380000;
  B.ReservedBytes := $180000;
  D := AnalyzeStackTransition(S, B, 2100);
  Require(ssAllocation in D);

  B.BoundsValid := False;
  D := AnalyzeStackTransition(S, B, 2200);
  Require(not (ssBounds in D));
  D := AnalyzeStackTransition(S, B, 2300);
  Require(not (ssBounds in D));
  D := AnalyzeStackTransition(S, B, 2400);
  Require(ssBounds in D);
  D := AnalyzeStackTransition(S, B, 2500);
  Require(not (ssBounds in D));

  B.CreateTime := 99;
  D := AnalyzeStackTransition(S, B, 2600);
  Require(D = []);
end.
