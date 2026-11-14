program Cozy_LifetimeProbe;
{$IFDEF FPC}{$MODE DELPHI}{$ELSE}{$APPTYPE CONSOLE}{$ENDIF}
{$R+}{$Q+}
uses
{ Cozy central text imports. }
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.TestsLifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsLifecycle.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}

  {$IFDEF FPC}cthreads, SysUtils, Classes,{$ELSE}System.SysUtils, System.Classes,
    System.SyncObjs, Cozy.Api.Pointer,{$ENDIF}
  Cozy.Lifetime;

type
  TCloser = class(TThread)
  private FGate: TGameCallGate;
  protected procedure Execute; override;
  public Done: Integer; Failure: string;
    constructor Create(Gate: TGameCallGate);
  end;

function Atomic(var Value: Integer; NewValue, Expected: Integer): Integer;
begin
  {$IFDEF FPC}Result := InterlockedCompareExchange(Value, NewValue, Expected);
  {$ELSE}Result := TInterlocked.CompareExchange(Value, NewValue, Expected);{$ENDIF}
end;

constructor TCloser.Create(Gate: TGameCallGate);
begin
  inherited Create(True); FreeOnTerminate := False; FGate := Gate;
end;

procedure TCloser.Execute;
begin
  try FGate.CloseAndWait;
  except on E: Exception do Failure := E.Message; end;
  Atomic(Done, 1, 0);
end;

procedure Check(Value: Boolean; const Text: string);
begin if not Value then raise Exception.Create(CozyText_LifetimeProbe_Lifetime_36c9400c + Text); end;

procedure Run;
var State: TGameCallState; Gate: TGameCallGate; Closer, Closer2: TCloser;
  I: Integer; Held, Rejected: Boolean;
begin
  State.Initialize;
  Check(State.TryEnter and State.TryEnter, CozyText_LifetimeProbe_two_admissions_d3e7c631);
  Check(not State.Close and State.IsClosing, CozyText_LifetimeProbe_close_waits_for_admitted_calls_e30f657a);
  Check(not State.TryEnter, CozyText_LifetimeProbe_closed_gate_refuses_new_admission_ce0dd9c5);
  Check(not State.Leave, CozyText_LifetimeProbe_first_caller_does_not_signal_drain_5d9b7b1c);
  Check(State.Leave and (State.ActiveCount = 0), CozyText_LifetimeProbe_last_caller_owns_drain_signal_7c8bfc5d);
  Check(not State.Close, CozyText_LifetimeProbe_closer_cannot_steal_the_last_caller_signal_befor_aff8bc87);
  Rejected := False;
  try State.Leave; except on E: EInvalidOpException do Rejected := True; end;
  Check(Rejected, CozyText_LifetimeProbe_unbalanced_leave_rejected_82e55baf);
  Gate := TGameCallGate.Create; Closer := nil; Closer2 := nil; Held := False;
  try
    Gate.Enter; Held := True;
    Closer := TCloser.Create(Gate); Closer.Start;
    Closer2 := TCloser.Create(Gate); Closer2.Start;
    for I := 1 to 500 do
    begin
      if Gate.IsClosing then Break;
      Sleep(2);
    end;
    Check(Gate.IsClosing, CozyText_LifetimeProbe_other_thread_closes_admission_679690a1);
    Check((Atomic(Closer.Done, 0, 0) = 0) and (Atomic(Closer2.Done, 0, 0) = 0),
      CozyText_LifetimeProbe_concurrent_joins_cannot_finish_while_caller_rema_f29c3f6c);
    Check(not Gate.TryEnter, CozyText_LifetimeProbe_admission_rejected_while_destructor_drains_84dc35ec);
    Gate.Leave; Held := False;
    Closer.WaitFor; Closer2.WaitFor;
    Check((Atomic(Closer.Done, 0, 0) = 1) and (Closer.Failure = '') and
      (Atomic(Closer2.Done, 0, 0) = 1) and (Closer2.Failure = ''), CozyText_LifetimeProbe_last_leave_wakes_both_concurrent_joins_cf0c9cc7);
    Gate.CloseAndWait;
    Check(Gate.ActiveCount = 0, CozyText_LifetimeProbe_repeated_close_is_idempotent_0bdcab46);
    Rejected := False;
    try Gate.Enter; except on E: EInvalidOpException do Rejected := True; end;
    Check(Rejected, CozyText_LifetimeProbe_throwing_admission_rejects_terminal_object_035c3e6f);
  finally
    if Held then Gate.Leave;
    if Closer <> nil then begin Closer.WaitFor; Closer.Free; end;
    if Closer2 <> nil then begin Closer2.WaitFor; Closer2.Free; end;
    Gate.Free;
  end;
  Writeln(CozyText_LifetimeProbe_PASS_actual_atomic_gate_admission_close_race_ord_5d735e7a);
end;

begin
  try
    {$IFNDEF FPC}SealApiPointerStorage;{$ENDIF}
    Run;
  except on E: Exception do begin Writeln(E.ClassName, CozyText_LifetimeProbe_Text_b74d555d, E.Message); Halt(1); end; end;
end.
