program Cozy_DeterministicStateProbe;
{$APPTYPE CONSOLE}
{$I ..\..\Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
uses
{ Cozy central text imports. }
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Overlay in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Overlay.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}
  Cozy.Strings.TestsProtocol in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsProtocol.pas',
 System.SysUtils, System.Classes, System.SyncObjs,
  Cozy.Lifetime, Cozy.Overlay.State;

type
  PGameCallState = ^TGameCallState;
  TAdmissionThread = class(TThread)
  private
    FState: PGameCallState;
    FStartGate, FObservedGate, FReleaseGate, FCompletedGate: TEvent;
    FAdmitted, FDrained: Boolean;
    FErrorText: string;
  protected
    procedure Execute; override;
  public
    constructor Create(State: PGameCallState);
    destructor Destroy; override;
    property StartGate: TEvent read FStartGate;
    property ObservedGate: TEvent read FObservedGate;
    property ReleaseGate: TEvent read FReleaseGate;
    property CompletedGate: TEvent read FCompletedGate;
    property Admitted: Boolean read FAdmitted;
    property Drained: Boolean read FDrained;
    property ErrorText: string read FErrorText;
  end;

procedure Require(Value: Boolean; const Name: string);
begin
  if not Value then raise Exception.Create(CozyText_DeterministicStateProbe_DETERMINISTIC_PROBE_c8b6d9dc + Name);
end;

constructor TAdmissionThread.Create(State: PGameCallState);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FState := State;
  FStartGate := TEvent.Create(nil, True, False, '');
  FObservedGate := TEvent.Create(nil, True, False, '');
  FReleaseGate := TEvent.Create(nil, True, False, '');
  FCompletedGate := TEvent.Create(nil, True, False, '');
end;

destructor TAdmissionThread.Destroy;
begin
  { The controller has already joined. Never free events underneath a caller. }
  FCompletedGate.Free;
  FReleaseGate.Free;
  FObservedGate.Free;
  FStartGate.Free;
  inherited;
end;

procedure TAdmissionThread.Execute;
begin
  try
    try
      Require(FStartGate.WaitFor(5000) = wrSignaled, CozyText_DeterministicStateProbe_worker_start_barrier_timeout_15324ea8);
      FAdmitted := FState^.TryEnter;
      FObservedGate.SetEvent;
      if FAdmitted then begin
        Require(FReleaseGate.WaitFor(5000) = wrSignaled, CozyText_DeterministicStateProbe_worker_release_barrier_timeout_10588f33);
        FDrained := FState^.Leave;
      end;
    except
      on E: Exception do begin FErrorText := E.Message; FObservedGate.SetEvent; end;
    end;
  finally
    FCompletedGate.SetEvent;
  end;
end;

procedure Schedule(CloseFirst: Boolean);
var State: TGameCallState; Worker: TAdmissionThread;
begin
  State.Initialize;
  Worker := TAdmissionThread.Create(@State);
  Worker.Start;
  try
    if CloseFirst then Require(State.Close, CozyText_DeterministicStateProbe_empty_close_must_drain_d40f117b);
    Worker.StartGate.SetEvent;
    Require(Worker.ObservedGate.WaitFor(5000) = wrSignaled, CozyText_DeterministicStateProbe_admission_barrier_timeout_3dae3194);
    Require(Worker.ErrorText = '', Worker.ErrorText);
    if CloseFirst then begin
      Require(not Worker.Admitted, CozyText_DeterministicStateProbe_late_caller_was_admitted_after_close_774042ed);
      Require(State.ActiveCount = 0, CozyText_DeterministicStateProbe_late_caller_changed_active_count_8aa3188b);
    end else begin
      Require(Worker.Admitted and (State.ActiveCount = 1), CozyText_DeterministicStateProbe_caller_not_held_at_barrier_ce447d25);
      Require(not State.Close, CozyText_DeterministicStateProbe_close_drained_an_active_caller_dff4ae91);
      Require(State.IsClosing and not State.TryEnter, CozyText_DeterministicStateProbe_new_caller_entered_closing_gate_4cf88fae);
      Require(State.ActiveCount = 1, CozyText_DeterministicStateProbe_close_altered_admitted_count_932416f5);
    end;
    Worker.ReleaseGate.SetEvent;
    Require(Worker.CompletedGate.WaitFor(5000) = wrSignaled, CozyText_DeterministicStateProbe_completion_barrier_timeout_b5cdf838);
    Worker.WaitFor;
    Require(Worker.ErrorText = '', Worker.ErrorText);
    Require(State.IsClosing and (State.ActiveCount = 0), CozyText_DeterministicStateProbe_final_state_not_drained_21e88f69);
    Require(Worker.Drained <> CloseFirst, CozyText_DeterministicStateProbe_last_caller_drain_notification_differs_5a4f8bba);
    Require(not State.TryEnter, CozyText_DeterministicStateProbe_closed_gate_reopened_0d56d33f);
  finally
    Worker.StartGate.SetEvent;
    Worker.ReleaseGate.SetEvent;
    if Worker.CompletedGate.WaitFor(5000) <> wrSignaled then begin
      WriteLn(ErrOutput, CozyText_DeterministicStateProbe_DETERMINISTIC_PROBE_JOIN_TIMEOUT_c5bec2a3);
      { Abort only this test process; do not free shared state or terminate a
        production worker. The Windows test runner also enforces an outer process deadline. }
      Halt(3);
    end;
    Worker.WaitFor;
    Worker.Free;
  end;
end;

procedure Run;
const ExpectedMasks: array[0..5] of Integer = (18, 20, 24, 16, 32, 0);
var I, J, StateChecks, ScheduleChecks: Integer; Observed: array[0..5] of Integer;
  Current: TOverlayState; Allowed, Rejected: Boolean; MasksJson: string;
begin
  StateChecks := 0; ScheduleChecks := 0; MasksJson := '';
  for I := 0 to 5 do begin
    Observed[I] := 0;
    for J := 0 to 5 do begin
      Current := TOverlayState(I); Rejected := False;
      Allowed := (ExpectedMasks[I] and (1 shl J)) <> 0;
      try OverlayTransition(Current, TOverlayState(J));
      except on E: EInvalidOpException do begin
        Require(E.Message = CozyText_DeterministicStateProbe_OVERLAY_STATE_TRANSITION_INVALID_f8db1c6d, CozyText_DeterministicStateProbe_incorrect_exception_code_a3b53c3b);
        Rejected := True;
      end; end;
      Require(Rejected <> Allowed, CozyText_DeterministicStateProbe_transition_disagrees_with_independent_matrix_726f354c);
      if Rejected then Require(Current = TOverlayState(I), CozyText_DeterministicStateProbe_rejection_modified_state_d4c04fb7)
      else begin
        Require(Current = TOverlayState(J), CozyText_DeterministicStateProbe_transition_failed_to_change_state_2f931336);
        Observed[I] := Observed[I] or (1 shl J);
      end;
      Inc(StateChecks);
    end;
    if I > 0 then MasksJson := MasksJson + ',';
    MasksJson := MasksJson + IntToStr(Observed[I]);
  end;
  for I := 1 to 256 do begin
    Schedule(True); Inc(ScheduleChecks);
    Schedule(False); Inc(ScheduleChecks);
  end;
  WriteLn(CozyText_DeterministicStateProbe_JsonFixture_8aaf6bff, MasksJson,
    CozyText_DeterministicStateProbe_stateChecks_5661d1e6, StateChecks, CozyText_DeterministicStateProbe_scheduleChecks_12043441, ScheduleChecks,
    CozyText_DeterministicStateProbe_gpuExecuted_false_scope_STATE_AND_THREAD_ADMISSI_2f75a035);
end;

begin
  try Run;
  except on E: Exception do begin WriteLn(ErrOutput, E.ClassName, CozyText_DeterministicStateProbe_Text_327c0545, E.Message); Halt(1); end; end;
end.
