program CozyNHW_PathRules_Tests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build with Win64 (dcc64).'}
{$ENDIF}
uses
  System.SysUtils,
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.PathRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.PathRules.pas';
var
  R: TPathSignalRules;
  D: TDetectionKinds;
begin
  R := TPathSignalRules.Create;
  try
    D := [];
    R.Signal(pcRoute, 1000, D);
    if D <> [] then Halt(1);
    R.Signal(pcDNSPolicy, 2000, D);
    if not (dkPathCorrelation in D) then Halt(2);
    D := [];
    R.Signal(pcWinsock, 3000, D);
    if not (dkNetworkIntegrity in D) then Halt(3);
    D := [];
    R.Signal(pcInterface, 4000, D);
    if D <> [] then Halt(4); // single burst suppression
    R.Reset;
    D := [];
    R.Signal(pcRoute, 1000, D);
    R.Signal(pcDNSServer, 35000, D);
    if dkPathCorrelation in D then Halt(5); // too far apart
  finally
    R.Free;
  end;
end.
