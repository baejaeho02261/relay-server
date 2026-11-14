program CozyNHW_ReadRulesTests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build with dcc64.'}
{$ENDIF}
uses
  System.SysUtils,
  Cozy.NHW.Types in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Types.pas',
  Cozy.NHW.ReadRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ReadRules.pas';

procedure Require(Condition: Boolean);
begin
  if not Condition then Halt(1);
end;

begin
  Require(ReadCapable(False, ACCESS_VM_READ));
  Require(not ReadCapable(True, ACCESS_VM_READ));
  Require(not ReadCapable(False, ACCESS_QUERY_LIMITED));
  Require(NewlyReadCapable(False, True, False, 0, ACCESS_VM_READ));
  Require(NewlyReadCapable(False, False, True, ACCESS_VM_READ, ACCESS_VM_READ));
  Require(NewlyReadCapable(False, False, False, ACCESS_QUERY_LIMITED,
    ACCESS_QUERY_LIMITED or ACCESS_VM_READ));
  Require(not NewlyReadCapable(False, False, False, ACCESS_VM_READ,
    ACCESS_VM_READ or ACCESS_QUERY_INFORMATION));
  Require(RecentObservation(4000, 2000, 3000));
  Require(not RecentObservation(2000, 4000, 3000));
  Require(SamplingGapRelevant(501, 0, 500));
  Require(SamplingGapRelevant(0, 1001, 500));
  Require(not SamplingGapRelevant(500, 1000, 500));
  Require(CanaryGuardLost(True, True, True, False));
  Require(not CanaryGuardLost(True, True, False, False));
  Require(not CanaryGuardLost(False, True, True, False));
  Require(not CanaryGuardLost(True, False, True, False));
end.
