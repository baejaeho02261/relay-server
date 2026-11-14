program CozyNHW_Lifecycle_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build with Delphi Win64 (dcc64).'}
{$ENDIF}

// Synthetic lifecycle and handle-inheritance snapshots only.
// ExitCode 0 = passed; ExitCode 1 = failed. No console messages.
uses
  System.SysUtils,
  System.Generics.Collections,
  Cozy.NHW.Types in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Types.pas',
  Cozy.NHW.Native in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Native.pas',
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.Lifecycle in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Lifecycle.pas';

procedure Ensure(Value: Boolean);
begin
  if not Value then
    raise Exception.Create('Synthetic lifecycle snapshot check failed');
end;

function MakeThread(ID, State, Reason: Cardinal): TThreadSample;
begin
  Result := Default(TThreadSample);
  Result.ThreadID := ID;
  Result.StartAddress := NativeUInt($10000 + ID * 16);
  Result.ThreadState := State;
  Result.WaitReason := Reason;
end;

procedure TestLifecycle;
var
  M: TLifecycleMonitor;
  Threads: TThreadSampleMap;
  D: TDetectionKinds;
begin
  M := TLifecycleMonitor.Create;
  Threads := TThreadSampleMap.Create;
  try
    Threads.Add(101, MakeThread(101, 2, 0));
    Threads.Add(102, MakeThread(102, 5, 0));
    D := [];
    M.ExamineThreads(Threads, 100, True, False, D);
    Ensure(D = []);
    // Without external access, a normal thread creation stays silent.
    Threads.Add(103, MakeThread(103, 2, 0));
    D := [];
    M.ExamineThreads(Threads, 600, False, False, D);
    Ensure(D = []);
    // A new external access followed by creation is correlated.
    Threads.Add(104, MakeThread(104, 2, 0));
    D := [];
    M.ExamineThreads(Threads, 1100, False, True, D);
    Ensure((dkThreadCreation in D) and (dkLifecycle in D));
    // A stable snapshot must not duplicate notifications.
    D := [];
    M.ExamineThreads(Threads, 1300, False, False, D);
    Ensure(not (dkThreadCreation in D));
    // Only observed, stable (>=2 snapshots) thread disappearances are used.
    Threads.Remove(104);
    D := [];
    M.ExamineThreads(Threads, 1500, False, False, D);
    Ensure((dkThreadExit in D) and (dkLifecycle in D));
    // Suspended wait reason, not arbitrary scheduler transitions.
    Threads.AddOrSetValue(101, MakeThread(101, 5, 12));
    D := [];
    M.ExamineThreads(Threads, 1700, False, True, D);
    Ensure((dkThreadState in D) and (dkLifecycle in D));
    D := [];
    M.ExamineThreads(Threads, 1800, False, False, D);
    Ensure(not (dkThreadState in D));
  finally
    Threads.Free;
    M.Free;
  end;
end;

function MakeHandle(PID: Cardinal; Attr: Cardinal): TObservedHandle;
begin
  Result := Default(TObservedHandle);
  Result.OwnerPID := PID;
  Result.ObjectIdentity := NativeUInt($123400);
  Result.HandleValue := NativeUInt($210);
  Result.GrantedAccess := ACCESS_VM_READ;
  Result.Attributes := Attr;
end;

procedure TestInheritance;
var
  M: TLifecycleMonitor;
  Items: TList<TObservedHandle>;
  Parents: TProcessParentMap;
  Creations: TCreationTimeMap;
  D: TDetectionKinds;
  H: TObservedHandle;
begin
  M := TLifecycleMonitor.Create;
  Items := TList<TObservedHandle>.Create;
  Parents := TProcessParentMap.Create;
  Creations := TCreationTimeMap.Create;
  try
    Parents.Add(5000, 4000);
    Creations.Add(4000, 1000000);
    Creations.Add(5000, 2000000);
    Items.Add(MakeHandle(4000, 2)); // parent has inheritable handle
    Items.Add(MakeHandle(5000, 0)); // child refers to same object/value
    D := [];
    M.ExamineInheritance(Items, Parents, Creations, True, True, D);
    Ensure(D = []); // seed prior state
    D := [];
    M.ExamineInheritance(Items, Parents, Creations, False, False, D);
    Ensure(not (dkHandleInherit in D));
    // A new same-object/value pair is a fresh inheritance candidate.
    H := MakeHandle(4000, 2);
    H.HandleValue := NativeUInt($220);
    Items.Add(H);
    H := MakeHandle(5000, 0);
    H.HandleValue := NativeUInt($220);
    Items.Add(H);
    D := [];
    M.ExamineInheritance(Items, Parents, Creations, False, False, D);
    Ensure(dkHandleInherit in D);
    D := [];
    M.ExamineInheritance(Items, Parents, Creations, False, False, D);
    Ensure(not (dkHandleInherit in D));
    // Changing access rights in child must not resemble inheritance.
    H := MakeHandle(4000, 2);
    H.HandleValue := NativeUInt($230);
    Items.Add(H);
    H := MakeHandle(5000, 0);
    H.HandleValue := NativeUInt($230);
    H.GrantedAccess := ACCESS_VM_WRITE;
    Items.Add(H);
    D := [];
    M.ExamineInheritance(Items, Parents, Creations, False, False, D);
    Ensure(not (dkHandleInherit in D));
  finally
    Creations.Free;
    Parents.Free;
    Items.Free;
    M.Free;
  end;
end;

begin
  try
    TestLifecycle;
    TestInheritance;
    ExitCode := 0;
  except
    ExitCode := 1;
  end;
end.
