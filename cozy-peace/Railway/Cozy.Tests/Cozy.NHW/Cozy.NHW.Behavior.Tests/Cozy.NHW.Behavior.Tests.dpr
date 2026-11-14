program CozyNHW_Behavior_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build with Delphi Win64 (dcc64).'}
{$ENDIF}

// Synthetic snapshots only. No process enumeration and no console output.
// ExitCode 0 = all checks passed, 1 = check failed.
uses
  System.SysUtils,
  Cozy.NHW.Types in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Types.pas',
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.Behavior in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Behavior.pas';

procedure Ensure(Condition: Boolean);
begin
  if not Condition then
    raise Exception.Create('Snapshot test failed');
end;

function MakeHolder(PID: Cardinal; ObjectNo: NativeUInt; Count: Integer;
  IsThread: Boolean): TTargetHolder;
begin
  Result := Default(TTargetHolder);
  Result.PID := PID;
  Result.CreateTime := 123450;
  Result.HandleCount := Count;
  Result.ObjectIdentity := ObjectNo;
  Result.IsThread := IsThread;
  Result.Level := 1;
  if IsThread then Result.RightsUnion := THREAD_GET_CONTEXT_RIGHT
  else Result.RightsUnion := ACCESS_VM_READ;
end;

procedure TestThreadBurst;
var
  M: TBehaviorMonitor;
  D: TDetectionKinds;
  H: TTargetHolder;
  I: Integer;
begin
  M := TBehaviorMonitor.Create;
  try
    M.BeginSnapshot(100, True, True, True);
    H := MakeHolder(1000, 1, 1, True);
    M.Observe(H, True, False, False, True);
    D := [];
    M.EndSnapshot(D);
    Ensure(D = []);

    M.BeginSnapshot(1000, False, False, True);
    for I := 1 to 7 do
    begin
      H := MakeHolder(1000, NativeUInt(100 + I), 1, True);
      M.Observe(H, True, False, False, False);
    end;
    // Duplicated observation of the same thread is not a distinct object.
    M.Observe(H, True, False, False, False);
    D := [];
    M.EndSnapshot(D);
    Ensure(not (dkThreadBurst in D));

    M.BeginSnapshot(1500, False, False, True);
    H := MakeHolder(1000, 108, 1, True);
    M.Observe(H, True, False, False, False);
    D := [];
    M.EndSnapshot(D);
    Ensure(dkThreadBurst in D);

    M.BeginSnapshot(1600, False, False, True);
    M.Observe(H, False, False, False, False);
    D := [];
    M.EndSnapshot(D);
    Ensure(not (dkThreadBurst in D));
  finally
    M.Free;
  end;
end;

procedure TestChurn;
var
  M: TBehaviorMonitor;
  D: TDetectionKinds;
  H: TTargetHolder;
  I: Integer;
begin
  M := TBehaviorMonitor.Create;
  try
    H := MakeHolder(2000, 1, 1, False);
    for I := 1 to 3 do
    begin
      M.BeginSnapshot(UInt64(I * 1000), False, False, False);
      M.Observe(H, False, True, False, False);
      D := [];
      M.EndSnapshot(D);
      Ensure((dkHandleChurn in D) = (I = 3));
    end;
  finally
    M.Free;
  end;
end;

procedure TestCrossAccessWithoutThreadCoverage;
var
  M: TBehaviorMonitor;
  D: TDetectionKinds;
  H: TTargetHolder;
  I: Integer;
begin
  M := TBehaviorMonitor.Create;
  try
    M.BeginSnapshot(100, True, True, False);
    H := MakeHolder(3000, 1, 1, False);
    M.Observe(H, True, False, False, True);
    D := [];
    M.EndSnapshot(D);
    Ensure(D = []);
    for I := 1 to 3 do
    begin
      M.BeginSnapshot(UInt64(1000 + I * 300), False, True, False);
      H := MakeHolder(3000 + Cardinal(I), 1, 1, False);
      M.Observe(H, True, False, False, False);
      D := [];
      M.EndSnapshot(D);
      Ensure((dkCrossAccess in D) = (I = 3));
    end;
  finally
    M.Free;
  end;
end;

procedure TestAccessBurst;
var
  M: TBehaviorMonitor;
  D: TDetectionKinds;
  H: TTargetHolder;
begin
  M := TBehaviorMonitor.Create;
  try
    H := MakeHolder(4000, 1, 2, False);
    M.BeginSnapshot(100, True, True, False);
    M.Observe(H, True, False, False, True);
    D := [];
    M.EndSnapshot(D);
    Ensure(D = []);

    M.BeginSnapshot(1000, False, True, False);
    H.HandleCount := 3;
    M.Observe(H, False, False, False, False);
    D := [];
    M.EndSnapshot(D);
    Ensure(not (dkAccessBurst in D));

    M.BeginSnapshot(1300, False, True, False);
    H.HandleCount := 11;
    M.Observe(H, False, False, False, False);
    D := [];
    M.EndSnapshot(D);
    Ensure(dkAccessBurst in D);

    M.BeginSnapshot(1500, False, True, False);
    M.Observe(H, False, False, False, False);
    D := [];
    M.EndSnapshot(D);
    Ensure(not (dkAccessBurst in D));
  finally
    M.Free;
  end;
end;

begin
  try
    TestThreadBurst;
    TestChurn;
    TestCrossAccessWithoutThreadCoverage;
    TestAccessBurst;
    ExitCode := 0;
  except
    ExitCode := 1;
  end;
end.
