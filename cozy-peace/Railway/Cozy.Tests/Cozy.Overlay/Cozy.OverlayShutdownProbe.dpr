program Cozy_OverlayShutdownProbe;
{$APPTYPE CONSOLE}
{$I ..\..\Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc}
{$IFNDEF GAME_OVERLAY_CONTRACT_TESTS}{$MESSAGE FATAL 'Isolated overlay probe build required.'}{$ENDIF}
uses
{ Cozy central text imports. }
  Cozy.Strings.Application in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Application.pas',
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Handoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Handoff.pas',
  Cozy.Strings.Identity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Identity.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Network in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Network.pas',
  Cozy.Strings.Overlay in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Overlay.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.Protection in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Protection.pas',
  Cozy.Strings.Security in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Security.pas',
{$IF (Defined(GAME_HANDOFF_CONTRACT_TESTS))}
  Cozy.Strings.TestsHandoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsHandoff.pas',
{$ENDIF}
{$IF (Defined(GAME_DEVICE_IDENTITY_PROBE))}
  Cozy.Strings.TestsIdentity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsIdentity.pas',
{$ENDIF}
{$IF ((Defined(GAME_RELAY_SOCKET_CONTRACT_TESTS))) or (((Defined(GAME_NATIVE_ABI_TESTS))) or ((Defined(GAME_TLS_CONTRACT_TESTS))))}
  Cozy.Strings.TestsNetwork in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsNetwork.pas',
{$ENDIF}
  Cozy.Strings.TestsOverlay in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsOverlay.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}
 Cozy.Clock, Winapi.Windows, System.SysUtils, System.Classes, Cozy.ShutdownBudget, Cozy.Overlay, Cozy.Api.Pointer, Cozy.Overlay.ShutdownGuard;
procedure Require(Value: Boolean; const Name: string);
begin if not Value then raise Exception.Create(CozyText_OverlayShutdownProbe_OVERLAY_SHUTDOWN_0f9ce2fe+Name); end;
procedure BudgetContracts;
var Budget: TShutdownBudget;
begin
  Budget.BeginAt(10000); Budget.ConstrainTo(12000);
  Require((Budget.Deadline=12000) and (Budget.JoinDeadline=11000), CozyText_OverlayShutdownProbe_earlier_worker_deadline_preserves_close_reserve_77d217fb);
  Budget.ConstrainTo(14000); Require(Budget.Deadline=12000, CozyText_OverlayShutdownProbe_UI_cannot_extend_worker_deadline_86528808);
  Budget.ConstrainTo(9000); Require(Budget.Remaining(10000)=0, CozyText_OverlayShutdownProbe_already_expired_deadline_grants_no_wait_ffa64d3b);
  Budget.ConstrainTo(8000); Require(Budget.Remaining(10000)=0, CozyText_OverlayShutdownProbe_repeat_expiry_cannot_underflow_into_new_lifetime_013e3931);
end;
procedure Child(Cancelled: Boolean);
var Guard: TOverlayShutdownGuard;
begin
  Guard := TOverlayShutdownGuard.Create; Guard.Start;
  Guard.Arm(CozyTick+500);
  Guard.Arm(CozyTick+120000); { must not extend the first deadline }
  if Cancelled then begin Guard.Cancel; Guard.Free; Exit; end;
  { Simulate an OS/driver call that never returns. Owner-owned resources stay
    live until own-process termination. No individual thread is killed. }
  Sleep(INFINITE);
end;
procedure BlockedUIWithWorkerFailure;
var Guard: TOverlayShutdownGuard; Worker: TThread;
begin
  Guard := TOverlayShutdownGuard.Create; Guard.Start;
  Guard.Arm(CozyTick+120000);
  Worker := TThread.CreateAnonymousThread(
    procedure
    begin
      Sleep(100);
      OverlayTestTerminalWorker(Guard);
    end);
  Worker.Start;
  { Only the worker's production terminal path can shorten/arm the guard.
    The UI/main thread never pumps a message or calls BeginShutdown. }
  Sleep(INFINITE);
end;
procedure Parent(const Mode: string; Expected: Cardinal);
var Startup: TStartupInfo; Process: TProcessInformation;
  Command: string; Code: DWORD; Started: UInt64;
begin
  FillChar(Startup,SizeOf(Startup),0); Startup.cb := SizeOf(Startup);
  FillChar(Process,SizeOf(Process),0);
  Command := '"'+ParamStr(0)+CozyText_OverlayShutdownProbe_Text_febbe197+Mode; UniqueString(Command);
  Started := CozyTick;
  Require(CreateProcess(nil,PChar(Command),nil,nil,False,0,nil,nil,Startup,Process),CozyText_OverlayShutdownProbe_start_test_owned_child_763a27ac);
  try
    Require(WaitForSingleObject(Process.hProcess,8000)=WAIT_OBJECT_0,CozyText_OverlayShutdownProbe_own_process_deadline_is_bounded_ff83e568);
    Require(GetExitCodeProcess(Process.hProcess,Code) and (Code=Expected),CozyText_OverlayShutdownProbe_expected_terminal_process_status_2b91cb1a);
    if Expected <> 0 then Require(CozyTick-Started>=400,CozyText_OverlayShutdownProbe_guard_does_not_terminate_before_deadline_77006835);
  finally
    { A failed test must not orphan its own deliberately blocked child. }
    if GetExitCodeProcess(Process.hProcess,Code) and (Code=STILL_ACTIVE) then
    begin TerminateProcess(Process.hProcess,$E0000010); WaitForSingleObject(Process.hProcess,3000); end;
    CloseHandle(Process.hThread); CloseHandle(Process.hProcess);
  end;
end;
begin
  try
    SealApiPointerStorage;
    if ParamStr(1)=CozyText_OverlayShutdownProbe_blocked_5db33749 then Child(False)
    else if ParamStr(1)=CozyText_OverlayShutdownProbe_cancel_b9bded32 then Child(True)
    else if ParamStr(1)=CozyText_OverlayShutdownProbe_worker_ui_blocked_27a3c050 then BlockedUIWithWorkerFailure
    else begin
      BudgetContracts;
      Parent(CozyText_OverlayShutdownProbe_blocked_5db33749,$E0000009); Parent(CozyText_OverlayShutdownProbe_cancel_b9bded32,0);
      Parent(CozyText_OverlayShutdownProbe_worker_ui_blocked_27a3c050,$E0000009);
      WriteLn(CozyText_OverlayShutdownProbe_PASS_actual_process_shutdown_deadline_and_cancel_730d544d);
    end;
  except on E: Exception do begin WriteLn(E.ClassName,CozyText_OverlayShutdownProbe_Text_ea3ec7fb,E.Message); Halt(1); end; end;
end.
