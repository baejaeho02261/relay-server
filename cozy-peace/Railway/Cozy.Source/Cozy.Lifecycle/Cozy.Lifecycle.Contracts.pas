unit Cozy.Lifecycle.Contracts;
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
interface
type
  TLifecycleRole = (lrA, lrB, lrO);
  TLifecycleEvent = (leShutdownBegin,leCloseResponse,leProcessExit,leFileCleanup,leUiHidden,leLeaseExpired,leDownloadDeadline,leRenewalFailed,leUiRuntimeFailure);
  TLifecycleStatus = (lsRequested,lsAcknowledged,lsFailed,lsObserved,lsTimeout,lsUnknown,lsRemoved,lsNotAttempted,lsScheduled);
  TLifecycleStatuses = set of TLifecycleStatus;
  TLifecycleEvents = set of TLifecycleEvent;
  TLifecycleBatchState = record
    Seen: TLifecycleEvents;
    ParentExitObserved: Boolean;
    Submitted: Boolean;
  end;
{$I Cozy.Lifecycle.Events.inc}
function ParseLifecycleRole(const Text: string; out Value: TLifecycleRole): Boolean;
function ParseLifecycleEvent(const Text: string; out Value: TLifecycleEvent): Boolean;
function ParseLifecycleStatus(const Text: string; out Value: TLifecycleStatus): Boolean;
function LifecycleRoleAllowed(Reporter, Target: TLifecycleRole): Boolean;
function LifecycleCombinationAllowed(Reporter, Target: TLifecycleRole;
  Event: TLifecycleEvent; Status: TLifecycleStatus): Boolean;
function LifecycleCanAppend(const State: TLifecycleBatchState;
  Reporter, Target: TLifecycleRole; Event: TLifecycleEvent;
  Status: TLifecycleStatus): Boolean;
procedure LifecycleAppend(var State: TLifecycleBatchState;
  Event: TLifecycleEvent; Status: TLifecycleStatus);
implementation
function ParseLifecycleRole(const Text: string; out Value: TLifecycleRole): Boolean;
var R: TLifecycleRole;
begin for R := Low(R) to High(R) do if LifecycleRoleNames[R]=Text then begin Value:=R; Exit(True); end; Result:=False; end;
function ParseLifecycleEvent(const Text: string; out Value: TLifecycleEvent): Boolean;
var E: TLifecycleEvent;
begin for E := Low(E) to High(E) do if LifecycleEventNames[E]=Text then begin Value:=E; Exit(True); end; Result:=False; end;
function ParseLifecycleStatus(const Text: string; out Value: TLifecycleStatus): Boolean;
var S: TLifecycleStatus;
begin for S := Low(S) to High(S) do if LifecycleStatusNames[S]=Text then begin Value:=S; Exit(True); end; Result:=False; end;
function LifecycleRoleAllowed(Reporter, Target: TLifecycleRole): Boolean;
begin Result := (Reporter=Target) or ((Reporter=lrB) and (Target=lrA)) or ((Reporter=lrO) and (Target=lrB)); end;
function LifecycleCombinationAllowed(Reporter, Target: TLifecycleRole;
  Event: TLifecycleEvent; Status: TLifecycleStatus): Boolean;
begin
  Result := False;
  if not LifecycleRoleAllowed(Reporter,Target) or not (Status in LifecycleEventStatuses[Event]) then Exit;
  if (Reporter<>Target) and not (Event in [leProcessExit,leFileCleanup]) then Exit;
  if (Reporter=Target) and (Event=leProcessExit) and (Status=lsObserved) then Exit;
  if (Event=leDownloadDeadline) and ((Reporter<>lrA) or (Target<>lrA)) then Exit;
  Result := True;
end;
function LifecycleCanAppend(const State: TLifecycleBatchState;
  Reporter, Target: TLifecycleRole; Event: TLifecycleEvent;
  Status: TLifecycleStatus): Boolean;
begin
  Result := False;
  if State.Submitted or (Event in State.Seen) or
    not LifecycleCombinationAllowed(Reporter,Target,Event,Status) then Exit;
  if Reporter<>Target then
  begin
    if (Event=leProcessExit) and (leFileCleanup in State.Seen) then Exit;
    if (Event=leFileCleanup) and (Status=lsRemoved) and not State.ParentExitObserved then Exit;
  end
  else if (Event=leShutdownBegin) and (leFileCleanup in State.Seen) then Exit;
  Result := True;
end;
procedure LifecycleAppend(var State: TLifecycleBatchState;
  Event: TLifecycleEvent; Status: TLifecycleStatus);
begin Include(State.Seen,Event); if Event=leProcessExit then State.ParentExitObserved:=Status=lsObserved; end;
end.
