program CozyNHW_Refactor10AB_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Win64 only.'}
{$ENDIF}
{$IFNDEF NHW_REFACTOR10AB_TESTS}
  {$MESSAGE FATAL 'Build Cozy.NHW.Refactor10AB.Tests.dproj with its fixture defines.'}
{$ENDIF}

uses
  Winapi.Windows,
  System.SysUtils,
  Cozy.NHW.WinPointers,
  Cozy.NHW.Native,
  Cozy.NHW.SchedulerNative,
  Cozy.NHW.HeapTLSNative,
  Cozy.NHW.WCTNative,
  Cozy.NHW.ObserverAuthenticator,
  Cozy.NHW.StableIdentity,
  Cozy.NHW.ThreadStackProvenance,
  Cozy.NHW.ReadCanaryNative,
  Cozy.NHW.SensorTamperHealth,
  Cozy.NHW.Logging;

type
  TFixture = function(out Failure: string; out Checks: Integer): Boolean;

var
  DirectChecks, FixtureChecks, Groups: Integer;

procedure Check(Value: Boolean; const Why: string);
begin
  Inc(DirectChecks);
  if not Value then raise Exception.Create(Why);
end;

procedure Existing(const Name: string; Test: TFixture);
var
  Failure: string;
  Checks: Integer;
begin
  Failure := '';
  Checks := 0;
  if not Test(Failure, Checks) then
    raise Exception.Create(Name + ': ' + Failure);
  Check(Checks > 0, Name + ': fixture performed no checks');
  Inc(FixtureChecks, Checks);
end;

procedure Done(const Name: string);
begin
  Inc(Groups);
  Writeln('PASS: ', Name);
end;

procedure NativeResolverGroup;
var
  N, W: TArray<NativeUInt>;
begin
  ResolveWinPointers;
  W := SnapshotWinFunctionPointers;
  Check(Length(W) = 14, 'WinPointers: snapshot length');
  Check((W[0] <> 0) and (W[1] <> 0) and (W[2] <> 0),
    'WinPointers: bootstrap pointers');
  ResolveNativeAPIs;
  N := SnapshotNativeFunctionPointers;
  Check(Length(N) = 8, 'Native: snapshot length');
  Check((N[0] <> 0) and (N[1] <> 0) and (N[2] <> 0) and (N[7] <> 0),
    'Native: required pointers');
  Done('Native + WinPointers');
end;

procedure SchedulerGroup;
begin
  Existing('SchedulerNative', TestSchedulerHardening);
  Done('SchedulerNative');
end;

procedure HeapTLSGroup;
begin
  Existing('HeapTLSNative', TestHeapTLSNativeHardening);
  Done('HeapTLSNative');
end;

procedure WCTGroup;
begin
  Existing('WCTNative', TestWCTNativeHardening);
  Done('WCTNative');
end;

procedure AuthenticatorGroup;
begin
  Existing('ObserverAuthenticator', TestObserverAuthenticator10O);
  Done('ObserverAuthenticator');
end;

procedure StableIdentityGroup;
begin
  Existing('StableIdentity', TestStableIdentityHardening);
  Done('StableIdentity');
end;

procedure StackGroup;
begin
  Existing('ThreadStackProvenance', TestThreadStackHardening);
  Done('ThreadStackProvenance');
end;

procedure CanaryGroup;
begin
  Existing('ReadCanaryNative', TestReadCanaryHardening);
  Done('ReadCanaryNative');
end;

procedure TamperHealthGroup;
begin
  Existing('SensorTamperHealth', TestSensorTamperHealth10Q);
  Done('SensorTamperHealth');
end;

begin
  DirectChecks := 0;
  FixtureChecks := 0;
  Groups := 0;
  try
    NativeResolverGroup;
    SchedulerGroup;
    HeapTLSGroup;
    WCTGroup;
    AuthenticatorGroup;
    StableIdentityGroup;
    StackGroup;
    CanaryGroup;
    TamperHealthGroup;
    Check(Groups = 9, 'group count');
    Writeln('PASS: Refactor10AB groups=', Groups,
      ' direct=', DirectChecks, ' fixture=', FixtureChecks);
  except
    on E: Exception do
    begin
      Writeln('FAIL: ', E.ClassName, ': ', E.Message);
      Halt(1);
    end;
  end;
end.
