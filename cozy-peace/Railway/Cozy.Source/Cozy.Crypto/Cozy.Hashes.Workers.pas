unit Cozy.Hashes.Workers;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}

interface

uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto,
 Cozy.Hashes;

{ Synchronous bounded executor: ALL started threads join before return/raise.
  Input, callback state and contexts remain borrowed until then. Cancellation
  is cooperative; OS suspension is not execution and a timeout is not exit. }
procedure ExecuteBlake3Workers(Work: TBlake3Work; const Contexts: array of Pointer);
procedure ExecuteBlake3WorkersCancellable(Work: TBlake3Work;
  const Contexts: array of Pointer; const Cancellation: THashCancellation);
{$IFDEF COZY_HASH_WORKER_TESTS}
{ Native probe only; Cozy.Metadata.inc rejects this in a product build.
  Fault positions are one-based attempt numbers, zero disables a fault.
  Configure/Clear require an idle executor and reset all probe counters. }
procedure ConfigureHashWorkerFaults(CreateFailAt, WorkFailAt, CloseFailAt: Integer);
procedure ClearHashWorkerFaults;
procedure HashWorkerTestSnapshot(out Created, Joined, Closed, Active,
  PendingClose: Integer);
{$ENDIF}

implementation

uses Cozy.Clock,
  Winapi.Windows, System.SysUtils, System.SyncObjs, Cozy.WinApi, Cozy.Api.Pointer,
  Cozy.Api.ROR13, Cozy.Platform.ExportResolver;

type
  TWorker = record
    Work: TBlake3Work;
    Context: Pointer;
    Cancellation: THashCancellation;
    Completed, Cancelled: Boolean;
    AbortFlag: PInteger;
    {$IFDEF COZY_HASH_WORKER_TESTS}
    InjectWorkFailure: Boolean;
    {$ENDIF}
  end;
  PWorker = ^TWorker;

var
  ApiSlot_CreateThread, ApiSlot_WaitForSingleObject,
    ApiSlot_CloseHandle: TEncodedApiPointer;
  { One executor batch is admitted at a time. This caps process-wide workers
    and also caps retained completed-thread handles at four if the OS refuses
    CloseHandle. A new batch cannot allocate until that ledger is empty. }
  ExecutorGate: TCriticalSection;
  PendingHandles: array[0..3] of THandle;
  {$IFDEF COZY_HASH_WORKER_TESTS}
  FaultCreateAt, FaultWorkAt, FaultCloseAt: Integer;
  CreateAttempts, WorkAttempts, CloseAttempts: Integer;
  TestCreated, TestJoined, TestClosed, TestActive: Integer;
  {$ENDIF}

threadvar
  ExecutorActiveOnThread: Boolean;

function IsCancelled(const Cancellation: THashCancellation): Boolean;
begin
  Result := Assigned(Cancellation.Check) and Cancellation.Check(Cancellation.Context);
end;

function WorkerEntry(Context: Pointer): DWORD; stdcall;
var Worker: PWorker; WasActive: Boolean;
begin
  Result := 1;
  Worker := PWorker(Context);
  WasActive := ExecutorActiveOnThread;
  ExecutorActiveOnThread := True;
  {$IFDEF COZY_HASH_WORKER_TESTS}
  TInterlocked.Increment(TestActive);
  {$ENDIF}
  try
    try
      Worker^.Cancelled := IsCancelled(Worker^.Cancellation);
      if Worker^.Cancelled then Exit;
      if TInterlocked.CompareExchange(Worker^.AbortFlag^, 0, 0) <> 0 then Exit;
      {$IFDEF COZY_HASH_WORKER_TESTS}
      if Worker^.InjectWorkFailure then
        raise EInvalidOp.Create(CozyText_Hashes_Workers_Injected_hash_worker_failure_a2942a85);
      {$ENDIF}
      Worker^.Work(Worker^.Context);
      Worker^.Cancelled := IsCancelled(Worker^.Cancellation);
      Worker^.Completed := not Worker^.Cancelled;
      if Worker^.Completed then Result := 0;
    except
      on E: EHashCancelled do
      begin
        Worker^.Cancelled := True;
        TInterlocked.Exchange(Worker^.AbortFlag^, 1);
      end;
      on E: Exception do
        TInterlocked.Exchange(Worker^.AbortFlag^, 1);
      else TInterlocked.Exchange(Worker^.AbortFlag^, 1);
    end;
  finally
    ExecutorActiveOnThread := WasActive;
    { Exceptions never cross the OS thread boundary; completion is inspected
      only after a successful join or this synchronous fallback returns. }
    {$IFDEF COZY_HASH_WORKER_TESTS}
    TInterlocked.Decrement(TestActive);
    {$ENDIF}
  end;
end;

procedure JoinWorker(Handle: THandle; Wait: TApiWaitForSingleObject; DelayHandle: THandle);
var Status: DWORD;
begin
  repeat
    Status := Wait(Handle, INFINITE);
    if Status = WAIT_OBJECT_0 then Break;
    { Never infer exit from WAIT_FAILED/timeout. Borrowed memory must remain
      alive even if the OS cannot confirm exit; no unsafe bounded free. }
    { Delay on a process-owned never-signaled event with the already resolved
      wait pointer. No exception or cancellation may release borrowed worker
      memory before thread exit is positively observed. }
    Wait(DelayHandle, 1);
  until False;
  {$IFDEF COZY_HASH_WORKER_TESTS}
  Inc(TestJoined);
  {$ENDIF}
end;

function ReleaseHandle(Handle: THandle; Close: TApiCloseHandle;
  var CloseFailed: Boolean): Boolean;
var FirstClosed: Boolean;
begin
  {$IFDEF COZY_HASH_WORKER_TESTS}
  Inc(CloseAttempts);
  if (FaultCloseAt > 0) and (CloseAttempts = FaultCloseAt) then
    FirstClosed := False
  else
  {$ENDIF}
    FirstClosed := Close(Handle);
  if not FirstClosed then
  begin
    CloseFailed := True;
    { An injected/transient failure is surfaced even if this retry succeeds. }
    Result := Close(Handle);
  end
  else Result := True;
  {$IFDEF COZY_HASH_WORKER_TESTS}
  if Result then Inc(TestClosed);
  {$ENDIF}
end;

procedure DrainPendingHandles(Close: TApiCloseHandle);
var I: Integer; Failed: Boolean;
begin
  Failed := False;
  for I := 0 to High(PendingHandles) do
    if PendingHandles[I] <> 0 then
      if Close(PendingHandles[I]) then
      begin
        PendingHandles[I] := 0;
        {$IFDEF COZY_HASH_WORKER_TESTS}
        Inc(TestClosed);
        {$ENDIF}
      end
      else Failed := True;
  if Failed then raise EInvalidOp.Create(CozyText_Hashes_Workers_Hash_worker_handle_cleanup_pending_854d2d7d);
end;

procedure ExecuteBlake3Workers(Work: TBlake3Work; const Contexts: array of Pointer);
var Cancellation: THashCancellation;
begin
  FillChar(Cancellation, SizeOf(Cancellation), 0);
  ExecuteBlake3WorkersCancellable(Work, Contexts, Cancellation);
end;

procedure ExecuteBlake3WorkersCancellable(Work: TBlake3Work;
  const Contexts: array of Pointer; const Cancellation: THashCancellation);
var
  Workers: array[0..3] of TWorker;
  Handles: array[0..3] of THandle;
  I, N, AbortFlag: Integer;
  AllCompleted, Cancelled, CloseFailed: Boolean;
  Create: TApiCreateThread;
  Wait: TApiWaitForSingleObject;
  Close: TApiCloseHandle;
  DelayHandle: THandle;
begin
  N := Length(Contexts);
  if (not Assigned(Work)) or (N < 1) or (N > Length(Workers)) then
    raise EArgumentException.Create(CozyText_Hashes_Workers_Invalid_BLAKE3_worker_batch_8bd9d13f);
  if ExecutorActiveOnThread then
    raise EInvalidOp.Create(CozyText_Hashes_Workers_Hash_worker_executor_is_not_reentrant_ba08b5b8);
  { Resolve every join/release target before borrowing caller state. }
  Create := TApiCreateThread(DecodeApiPointer(ApiSlot_CreateThread));
  Wait := TApiWaitForSingleObject(DecodeApiPointer(ApiSlot_WaitForSingleObject));
  Close := TApiCloseHandle(DecodeApiPointer(ApiSlot_CloseHandle));
  DelayHandle := THandle(CozyClockDelayHandle);
  FillChar(Workers, SizeOf(Workers), 0);
  FillChar(Handles, SizeOf(Handles), 0);
  AbortFlag := 0;
  CloseFailed := False;
  Cancelled := False;
  System.IsMultiThread := True;
  ExecutorGate.Acquire;
  ExecutorActiveOnThread := True;
  try
    DrainPendingHandles(Close);
    try
      try
        for I := 0 to N - 1 do
        begin
          { No further job is admitted after observed cancellation/failure. }
          if IsCancelled(Cancellation) then
          begin Cancelled := True; Break; end;
          if TInterlocked.CompareExchange(AbortFlag, 0, 0) <> 0 then Break;
          Workers[I].Work := Work; Workers[I].Context := Contexts[I];
          Workers[I].Cancellation := Cancellation;
          Workers[I].AbortFlag := @AbortFlag;
          {$IFDEF COZY_HASH_WORKER_TESTS}
          Inc(WorkAttempts);
          Workers[I].InjectWorkFailure := (FaultWorkAt > 0) and
            (WorkAttempts = FaultWorkAt);
          {$ENDIF}
          if I < N - 1 then
          begin
            {$IFDEF COZY_HASH_WORKER_TESTS}
            Inc(CreateAttempts);
            if (FaultCreateAt = 0) or (CreateAttempts <> FaultCreateAt) then
            {$ENDIF}
              Handles[I] := Create(nil, 0, WorkerEntry, @Workers[I], 0, nil);
            {$IFDEF COZY_HASH_WORKER_TESTS}
            if Handles[I] <> 0 then Inc(TestCreated);
            {$ENDIF}
          end;
          { Resource pressure changes parallelism, never digest semantics. }
          if Handles[I] = 0 then WorkerEntry(@Workers[I]);
        end;
      finally
        for I := 0 to N - 1 do
          if Handles[I] <> 0 then JoinWorker(Handles[I], Wait, DelayHandle);
      end;
      AllCompleted := True;
      for I := 0 to N - 1 do
      begin
        AllCompleted := AllCompleted and Workers[I].Completed;
        Cancelled := Cancelled or Workers[I].Cancelled;
      end;
      Cancelled := Cancelled or IsCancelled(Cancellation);
      if Cancelled then raise EHashCancelled.Create(CozyText_Hashes_Workers_Hash_operation_cancelled_e99dfbd6);
      if not AllCompleted then raise EInvalidOp.Create(CozyText_Hashes_Workers_BLAKE3_worker_failed_bf245f4e);
    finally
      { ALL joins precede ANY close or wipe. A persistent close failure retains
        only a completed OS handle, never a caller buffer/context. The bounded
        ledger refuses later work until cleanup succeeds. }
      for I := 0 to N - 1 do
        if Handles[I] <> 0 then
        begin
          if not ReleaseHandle(Handles[I], Close, CloseFailed) then
            PendingHandles[I] := Handles[I];
          Handles[I] := 0;
        end;
      FillChar(Workers, SizeOf(Workers), 0);
      if CloseFailed then raise EInvalidOp.Create(CozyText_Hashes_Workers_BLAKE3_worker_handle_close_failed_207993b0);
    end;
  finally
    ExecutorActiveOnThread := False;
    ExecutorGate.Release;
    FillChar(PByte(@@Create)^, SizeOf(TApiCreateThread), 0);
    FillChar(PByte(@@Wait)^, SizeOf(TApiWaitForSingleObject), 0);
    FillChar(PByte(@@Close)^, SizeOf(TApiCloseHandle), 0);
  end;
end;

{$IFDEF COZY_HASH_WORKER_TESTS}
procedure ConfigureHashWorkerFaults(CreateFailAt, WorkFailAt, CloseFailAt: Integer);
var I: Integer;
begin
  if (CreateFailAt < 0) or (WorkFailAt < 0) or (CloseFailAt < 0) then
    raise EArgumentException.Create(CozyText_Hashes_Workers_Invalid_hash_worker_fault_position_fb8cac9f);
  ExecutorGate.Acquire;
  try
    for I := 0 to High(PendingHandles) do
      if PendingHandles[I] <> 0 then
        raise EInvalidOp.Create(CozyText_Hashes_Workers_Cannot_reset_probe_while_cleanup_is_pending_62aeacc7);
    FaultCreateAt := CreateFailAt; FaultWorkAt := WorkFailAt; FaultCloseAt := CloseFailAt;
    CreateAttempts := 0; WorkAttempts := 0; CloseAttempts := 0;
    TestCreated := 0; TestJoined := 0; TestClosed := 0; TestActive := 0;
  finally ExecutorGate.Release; end;
end;

procedure ClearHashWorkerFaults;
begin ConfigureHashWorkerFaults(0, 0, 0); end;

procedure HashWorkerTestSnapshot(out Created, Joined, Closed, Active,
  PendingClose: Integer);
var I: Integer;
begin
  ExecutorGate.Acquire;
  try
    Created := TestCreated; Joined := TestJoined; Closed := TestClosed;
    Active := TInterlocked.CompareExchange(TestActive, 0, 0);
    PendingClose := 0;
    for I := 0 to High(PendingHandles) do
      if PendingHandles[I] <> 0 then Inc(PendingClose);
  finally ExecutorGate.Release; end;
end;
{$ENDIF}

procedure FinalizeWorkerHandles;
var I: Integer; Close: TApiCloseHandle;
begin
  { Unit finalization requires callers to have joined their application threads.
    No started hash thread is ever detached by this executor. }
  if ExecutorGate = nil then Exit;
  ExecutorGate.Acquire;
  try
    Close := TApiCloseHandle(DecodeApiPointer(ApiSlot_CloseHandle));
    for I := 0 to High(PendingHandles) do
      if (PendingHandles[I] <> 0) and Close(PendingHandles[I]) then
        PendingHandles[I] := 0;
  finally ExecutorGate.Release; end;
end;

initialization
  BindApiPointer(ApiSlot_CreateThread, RequireProcAddressHash64(CozyText_Hashes_Workers_kernel32_dll_adca97e9, HASH_CreateThread));
  BindApiPointer(ApiSlot_WaitForSingleObject, RequireProcAddressHash64(CozyText_Hashes_Workers_kernel32_dll_adca97e9, HASH_WaitForSingleObject));
  BindApiPointer(ApiSlot_CloseHandle, RequireProcAddressHash64(CozyText_Hashes_Workers_kernel32_dll_adca97e9, HASH_CloseHandle));
  ExecutorGate := TCriticalSection.Create;
finalization
  FinalizeWorkerHandles;
  ExecutorGate.Free;
end.
