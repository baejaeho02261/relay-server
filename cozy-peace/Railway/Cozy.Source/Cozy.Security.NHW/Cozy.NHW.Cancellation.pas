unit Cozy.NHW.Cancellation;

interface

// The flag remains owned by the guard until its worker has joined. It is
// thread-local so one role or test cannot cancel an unrelated worker.
procedure NHWSetCancellationFlag(Flag: PLongInt);
function NHWCancellationRequested: Boolean;
function NHWEnableComCancellation: Boolean;
procedure NHWDisableComCancellation;
procedure NHWCancelComCall(ThreadID: Cardinal);

implementation

uses
  Winapi.Windows,
  System.SyncObjs,
  Cozy.NHW.WinPointers;

type
  TCoChangeCancellation = function(Reserved: Pointer): HRESULT; stdcall;
  TCoCancelCall = function(ThreadID, TimeoutSeconds: Cardinal): HRESULT; stdcall;

threadvar
  CancellationFlag: PLongInt;

procedure NHWSetCancellationFlag(Flag: PLongInt);
begin
  CancellationFlag := Flag;
end;

function NHWCancellationRequested: Boolean;
begin
  if CancellationFlag = nil then Exit(False);
  Result := TInterlocked.CompareExchange(CancellationFlag^, 0, 0) <> 0;
end;

function NHWEnableComCancellation: Boolean;
var
  Enable: TCoChangeCancellation;
begin
  Enable := TCoChangeCancellation(WinExport(WinModule('ole32.dll'),
    'CoEnableCallCancellation'));
  if not Assigned(Enable) then Exit(False);
  Result := Enable(nil) >= 0;
end;

procedure NHWDisableComCancellation;
var
  Disable: TCoChangeCancellation;
begin
  Disable := TCoChangeCancellation(WinExport(WinModule('ole32.dll'),
    'CoDisableCallCancellation'));
  if Assigned(Disable) then Disable(nil);
end;

procedure NHWCancelComCall(ThreadID: Cardinal);
var
  Cancel: TCoCancelCall;
begin
  if ThreadID = 0 then Exit;
  Cancel := TCoCancelCall(WinExport(WinModule('ole32.dll'), 'CoCancelCall'));
  // Zero means request cancellation without delaying the server/session close.
  // This is cooperative RPC cancellation, not a forced thread termination or
  // proof that the provider has exited. The owner still joins the worker.
  if Assigned(Cancel) then Cancel(ThreadID, 0);
end;

end.
