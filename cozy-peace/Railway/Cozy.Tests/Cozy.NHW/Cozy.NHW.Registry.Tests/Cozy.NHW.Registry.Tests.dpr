program CozyNHW_Registry_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build as Windows 64-bit.'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.RegistryNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.RegistryNative.pas',
  Cozy.NHW.Registry in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Registry.pas';

procedure Expect(Condition: Boolean);
begin
  if not Condition then raise Exception.Create('Registry evidence regression test failed.');
end;

procedure RunTests;
var
  State: TRegistryEvidenceState;
  E: TRegistryEvidence;
  Events: TDetectionKinds;
begin
  State.Reset;
  E := Default(TRegistryEvidence);
  E.ValuesKnown := True;
  E.ValuesHash := 100;
  E.KeysKnown := True;
  E.KeysHash := 200;
  E.DaclKnown := True;
  E.DaclHash := 300;
  Events := [];
  State.Observe(E, True, Events);
  Expect(Events = []);
  State.Observe(E, False, Events);
  Expect(Events = []);

  E.ValuesHash := 101;
  State.Observe(E, False, Events);
  Expect(Events = [dkRegistryValue]);
  Events := [];
  State.Observe(E, False, Events);
  Expect(Events = []); // no duplicate detection

  E.KeysKnown := False; // unavailable is UNKNOWN, not deletion
  E.KeysHash := 999;
  State.Observe(E, False, Events);
  Expect(Events = []);
  E.KeysKnown := True;
  E.KeysHash := 201;
  State.Observe(E, False, Events);
  Expect(Events = [dkRegistryKey]);
  Events := [];

  E.DaclKnown := False;
  E.DaclHash := 444;
  State.Observe(E, False, Events);
  Expect(Events = []);
  E.DaclKnown := True;
  State.Observe(E, False, Events);
  Expect(Events = [dkRegistrySecurity]);
  Events := [];
  State.Observe(E, False, Events);
  Expect(Events = []);
end;

begin
  try
    RunTests;
  except
    Halt(1);
  end;
end.
