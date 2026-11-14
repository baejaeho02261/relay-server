program Cozy_LifecycleContractsProbe;
{$APPTYPE CONSOLE}
{$I ..\..\Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc}
uses
{ Cozy central text imports. }
  Cozy.Strings.Application in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Application.pas',
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Handoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Handoff.pas',
  Cozy.Strings.Identity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Identity.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Network in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Network.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.Protection in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Protection.pas',
  Cozy.Strings.Security in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Security.pas',
{$IF (Defined(GAME_HANDOFF_CONTRACT_TESTS))}
  Cozy.Strings.TestsHandoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsHandoff.pas',
{$ENDIF}
{$IF (Defined(GAME_DEVICE_IDENTITY_PROBE))}
  Cozy.Strings.TestsIdentity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsIdentity.pas',
{$ENDIF}
  Cozy.Strings.TestsLifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsLifecycle.pas',
{$IF ((Defined(GAME_RELAY_SOCKET_CONTRACT_TESTS))) or (((Defined(GAME_NATIVE_ABI_TESTS))) or ((Defined(GAME_TLS_CONTRACT_TESTS))))}
  Cozy.Strings.TestsNetwork in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsNetwork.pas',
{$ENDIF}
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}
 System.SysUtils, System.Classes, System.JSON, System.SyncObjs,
  System.Diagnostics, System.IOUtils, Cozy.Handoff,
  Cozy.Lifecycle in '..\..\Cozy.Source\Cozy.Lifecycle\Cozy.Lifecycle.pas',
  Cozy.Lifecycle.Contracts in '..\..\Cozy.Source\Cozy.Lifecycle\Cozy.Lifecycle.Contracts.pas';
var Passed: Integer;
procedure Check(Value: Boolean; const Code: string);
begin if not Value then raise Exception.Create(Code); Inc(Passed); end;
procedure Rules;
var S: TLifecycleBatchState;
begin
  S := Default(TLifecycleBatchState);
  Check(not LifecycleCombinationAllowed(lrB,lrB,leProcessExit,lsObserved),CozyText_LifecycleContractsProbe_SELF_EXIT_330e3c69);
  Check(not LifecycleCombinationAllowed(lrO,lrA,leFileCleanup,lsFailed),CozyText_LifecycleContractsProbe_WRONG_PARENT_d2899e46);
  Check(not LifecycleCanAppend(S,lrB,lrA,leFileCleanup,lsRemoved),CozyText_LifecycleContractsProbe_UNOBSERVED_PARENT_REMOVAL_d1e25c21);
  Check(LifecycleCanAppend(S,lrB,lrA,leProcessExit,lsObserved),CozyText_LifecycleContractsProbe_PARENT_EXIT_132dbddc);
  LifecycleAppend(S,leProcessExit,lsObserved);
  Check(not LifecycleCanAppend(S,lrB,lrA,leProcessExit,lsTimeout),CozyText_LifecycleContractsProbe_DUPLICATE_EVENT_c6240cd8);
  Check(LifecycleCanAppend(S,lrB,lrA,leFileCleanup,lsRemoved),CozyText_LifecycleContractsProbe_ORDERED_PARENT_REMOVAL_b9351219);
  S.Submitted := True;
  Check(not LifecycleCanAppend(S,lrB,lrA,leFileCleanup,lsRemoved),CozyText_LifecycleContractsProbe_LATE_EVENT_302b313e);
  S := Default(TLifecycleBatchState); LifecycleAppend(S,leFileCleanup,lsFailed);
  Check(not LifecycleCanAppend(S,lrB,lrA,leProcessExit,lsObserved),CozyText_LifecycleContractsProbe_BACKWARD_PARENT_ORDER_4340cc6d);
  Check(not LifecycleCanAppend(S,lrB,lrB,leShutdownBegin,lsRequested),CozyText_LifecycleContractsProbe_BACKWARD_SELF_ORDER_4f7f93e2);
  S := Default(TLifecycleBatchState); LifecycleAppend(S,leCloseResponse,lsAcknowledged);
  Check(LifecycleCanAppend(S,lrB,lrB,leShutdownBegin,lsRequested),CozyText_LifecycleContractsProbe_TRANSFER_BEFORE_SHUTDOWN_86e221bd);
end;
function FailedPost(Body: TJSONObject; Deadline: UInt64): TJSONObject;
begin raise EInvalidOp.Create(CozyText_LifecycleContractsProbe_SIMULATED_TRANSPORT_FAILURE_25509264); end;
procedure NoFalseSuccess;
var R: TLifecycleReporter; O: THandoffCleanupObservation; A: TJSONArray;
begin
  R := TLifecycleReporter.CreateForTest('B',FailedPost); A := nil;
  try
    R.Note('B',CozyText_LifecycleContractsProbe_PROCESS_EXIT_f1acf170,CozyText_LifecycleContractsProbe_OBSERVED_e4c9911b,10);
    R.Note('A',CozyText_LifecycleContractsProbe_FILE_CLEANUP_20747a42,CozyText_LifecycleContractsProbe_REMOVED_612f68ca,10);
    R.Note('B',CozyText_LifecycleContractsProbe_SERVER_CONFIRMED_61a0699c,CozyText_LifecycleContractsProbe_ACKNOWLEDGED_e3fbc2ce);
    A := R.SnapshotForTest('A'); Check(A.Count=0,CozyText_LifecycleContractsProbe_INVALID_NOTE_SERIALIZED_108040df); FreeAndNil(A);
    O := Default(THandoffCleanupObservation);
    O.ProcessID:=10; O.ExitObserved:=True; O.ExitTimedOut:=True;
    O.FileRemoved:=True; O.CleanupAttempted:=True; O.Win32Error:=32;
    R.ObserveCleanup('A',O,True);
    A:=R.SnapshotForTest('A'); Check(A.Count=2,CozyText_LifecycleContractsProbe_EXPECTED_OBSERVATION_COUNT_5367b05c);
    Check(TJSONObject(A.Items[0]).GetValue(CozyText_LifecycleContractsProbe_status_2623dc33).Value=CozyText_LifecycleContractsProbe_TIMEOUT_0def29f1,CozyText_LifecycleContractsProbe_CONTRADICTORY_EXIT_SUCCESS_cb47320f);
    Check(TJSONObject(A.Items[1]).GetValue(CozyText_LifecycleContractsProbe_status_2623dc33).Value=CozyText_LifecycleContractsProbe_FAILED_5444d33f,CozyText_LifecycleContractsProbe_CONTRADICTORY_FILE_SUCCESS_a0cc61f4);
  finally A.Free; R.Free; end;
end;
procedure DiagnosticFailureAndLateSubmit;
var R: TLifecycleReporter; Requests: Integer; FileName: string; Watch: TStopwatch;
  Hook: TLifecycleTestPost; DelayReply: Boolean;
begin
  Requests:=0; DelayReply:=False;
  Hook:=function(Body:TJSONObject; Deadline:UInt64):TJSONObject
    begin
      Inc(Requests);
      if Body.GetValue(CozyText_LifecycleContractsProbe_action_87a70e17).Value=CozyText_LifecycleContractsProbe_lifecycleReport_460903a8 then raise EInvalidOp.Create(CozyText_LifecycleContractsProbe_LOST_RESPONSE_a7b1bdee);
      if DelayReply then
        while TLifecycleReporter.Tick <= Deadline do TThread.Sleep(1);
      Result:=TJSONObject.Create;
      Result.AddPair(CozyText_LifecycleContractsProbe_version_410bb1aa,TJSONNumber.Create(1)); Result.AddPair(CozyText_LifecycleContractsProbe_permitId_cfbb73e2,StringOfChar('a',32));
      Result.AddPair(CozyText_LifecycleContractsProbe_nonce_056552dd,StringOfChar('b',48)); Result.AddPair(CozyText_LifecycleContractsProbe_expiresAt_d25c6756,TJSONNumber.Create(180100));
      Result.AddPair(CozyText_LifecycleContractsProbe_serverTime_0844c317,TJSONNumber.Create(100)); Result.AddPair(CozyText_LifecycleContractsProbe_flowId_53c02827,StringOfChar('A',24));
      Result.AddPair(CozyText_LifecycleContractsProbe_reporterRole_69effeed,'B'); Result.AddPair(CozyText_LifecycleContractsProbe_targetRole_062de784,'B');
      Result.AddPair(CozyText_LifecycleContractsProbe_targetSessionId_85715bab,StringOfChar('B',24));
    end;
  FileName:=TPath.GetTempFileName;
  R:=TLifecycleReporter.CreateForTest('B',Hook);
  try
    R.Prepare('B',StringOfChar('B',24),CozyText_LifecycleContractsProbe_probe_token_e7b3a54a,TLifecycleReporter.Tick);
    Check(Requests=0,CozyText_LifecycleContractsProbe_EXPIRED_DEADLINE_SENT_d9403ab3);
    R.Prepare('B',StringOfChar('B',24),CozyText_LifecycleContractsProbe_probe_token_e7b3a54a);
    R.Note('B',CozyText_LifecycleContractsProbe_SHUTDOWN_BEGIN_06d2c0c3,CozyText_LifecycleContractsProbe_REQUESTED_26d05d11,10);
    Watch:=TStopwatch.StartNew; R.Submit('B');
    Check(Watch.ElapsedMilliseconds<1500,CozyText_LifecycleContractsProbe_DIAGNOSTIC_FAILURE_DELAY_df96caa7);
    Check(System.SysUtils.DeleteFile(FileName),CozyText_LifecycleContractsProbe_REAL_FILE_CLEANUP_BLOCKED_38b8a288);
    Check(not FileExists(FileName),CozyText_LifecycleContractsProbe_FILE_NOT_REMOVED_5f295a97);
    Check(Requests=2,CozyText_LifecycleContractsProbe_EXPECTED_PREPARE_AND_REPORT_145d2ebb);
    R.Note('B',CozyText_LifecycleContractsProbe_FILE_CLEANUP_20747a42,CozyText_LifecycleContractsProbe_REMOVED_612f68ca,10); R.Submit('B');
    Check(Requests=2,CozyText_LifecycleContractsProbe_LATE_REPORT_RETRIED_80f437f5);
  finally R.Free; if FileExists(FileName) then System.SysUtils.DeleteFile(FileName); end;
  Requests:=0; DelayReply:=True; R:=TLifecycleReporter.CreateForTest('B',Hook);
  try
    R.Prepare('B',StringOfChar('B',24),CozyText_LifecycleContractsProbe_probe_token_e7b3a54a,TLifecycleReporter.Tick+200);
    Check(Requests=1,CozyText_LifecycleContractsProbe_LATE_REPLY_PROBE_NOT_ENTERED_d9ebcc31);
    R.Note('B',CozyText_LifecycleContractsProbe_SHUTDOWN_BEGIN_06d2c0c3,CozyText_LifecycleContractsProbe_REQUESTED_26d05d11,10); R.Submit('B');
    Check(Requests=1,CozyText_LifecycleContractsProbe_LATE_GRANT_INSTALLED_00ca5234);
  finally R.Free; Hook:=nil; end;
  R:=TLifecycleReporter.CreateForTest('B',FailedPost); FileName:=TPath.GetTempFileName;
  try
    R.Prepare('B',StringOfChar('B',24),CozyText_LifecycleContractsProbe_probe_token_e7b3a54a);
    Check(System.SysUtils.DeleteFile(FileName),CozyText_LifecycleContractsProbe_CHALLENGE_FAILURE_BLOCKED_CLEANUP_9cc13046);
    R.Note('B',CozyText_LifecycleContractsProbe_FILE_CLEANUP_20747a42,CozyText_LifecycleContractsProbe_FAILED_5444d33f,10,32); R.Submit('B');
  finally R.Free; if FileExists(FileName) then System.SysUtils.DeleteFile(FileName); end;
end;
procedure ContendedNote;
var R: TLifecycleReporter; Entered, ReleaseGate: TEvent; Thread: TThread;
  Watch: TStopwatch; A:TJSONArray; Started:Boolean;
begin
  R:=TLifecycleReporter.CreateForTest('B',FailedPost); Thread:=nil; A:=nil; Started:=False;
  Entered:=TEvent.Create(nil,True,False,''); ReleaseGate:=TEvent.Create(nil,True,False,'');
  try
    Thread:=TThread.CreateAnonymousThread(procedure begin
      R.HoldEventLockForTest(procedure begin Entered.SetEvent; ReleaseGate.WaitFor(3000); end);
    end); Thread.FreeOnTerminate:=False; Thread.Start; Started:=True;
    Check(Entered.WaitFor(3000)=wrSignaled,CozyText_LifecycleContractsProbe_LOCK_PROBE_START_6db69d99);
    Watch:=TStopwatch.StartNew; R.Note('B',CozyText_LifecycleContractsProbe_SHUTDOWN_BEGIN_06d2c0c3,CozyText_LifecycleContractsProbe_REQUESTED_26d05d11,10);
    Check(Watch.ElapsedMilliseconds<1000,CozyText_LifecycleContractsProbe_NOTE_BLOCKED_ON_DIAGNOSTIC_LOCK_384c4136);
    ReleaseGate.SetEvent; Thread.WaitFor;
    A:=R.SnapshotForTest('B'); Check(A.Count=0,CozyText_LifecycleContractsProbe_CONTENDED_NOTE_NOT_DROPPED_2d71fc84);
  finally
    ReleaseGate.SetEvent;
    if Thread<>nil then begin if Started then Thread.WaitFor; Thread.Free; end;
    A.Free; R.Free; Entered.Free; ReleaseGate.Free;
  end;
end;
begin
  Passed:=0;
  try Rules; NoFalseSuccess; DiagnosticFailureAndLateSubmit; ContendedNote;
    Writeln(CozyText_LifecycleContractsProbe_LIFECYCLE_CONTRACTS_PASS_2d323cde,Passed);
  except on E:Exception do begin Writeln(CozyText_LifecycleContractsProbe_LIFECYCLE_CONTRACTS_FAIL_cd009e02,E.Message); Halt(1); end; end;
end.
