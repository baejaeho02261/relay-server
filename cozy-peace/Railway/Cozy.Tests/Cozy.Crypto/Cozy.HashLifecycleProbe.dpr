program Cozy_HashLifecycleProbe;
{$APPTYPE CONSOLE}
{$IFNDEF COZY_HASH_WORKER_TESTS}
  {$MESSAGE FATAL 'Build this test with COZY_HASH_WORKER_TESTS only in its isolated probe DCU directory.'}
{$ENDIF}
{ Native Win64 ownership, cancellation, join and injected failure contracts.
  Only this isolated test build enables worker faults; no network or secrets. }
uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.TestsCrypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsCrypto.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}

  Winapi.Windows, System.SysUtils, Cozy.Hashes, Cozy.Hashes.Workers;
type
  PControl = ^TControl;
  TControl = record
    Cancelled, Checks, CancelAt, Starts, Finishes, Alive, BadAccess: Integer;
  end;
  TWorkContext = record Control: PControl; CancelDuringWork: Boolean; end;
  PWorkContext = ^TWorkContext;
  TOwnerContext = record
    Common: TIntegrityHasher;
    Blake: TBlake3Hasher;
    Rejections: Integer;
    Unexpected: Boolean;
  end;
  POwnerContext = ^TOwnerContext;
var
  Cases: Integer;
  ReentrantHash: TIntegrityHasher;
  ReentrantBlake: TBlake3Hasher;

procedure Require(Value: Boolean; const Text: string);
begin
  if not Value then raise Exception.Create(Text);
end;

function IsCancelled(Context: Pointer): Boolean;
var C: PControl; N: Integer;
begin
  C := PControl(Context);
  N := InterlockedIncrement(C^.Checks);
  if (C^.CancelAt > 0) and (N >= C^.CancelAt) then
    InterlockedExchange(C^.Cancelled, 1);
  Result := InterlockedCompareExchange(C^.Cancelled, 0, 0) <> 0;
end;

procedure BoundedWork(Context: Pointer);
var C: PControl; I: Integer;
begin
  C := PWorkContext(Context)^.Control;
  InterlockedIncrement(C^.Starts);
  try
    for I := 0 to 4095 do
    begin
      if InterlockedCompareExchange(C^.Alive, 0, 0) = 0 then
        InterlockedExchange(C^.BadAccess, 1);
      if InterlockedCompareExchange(C^.Cancelled, 0, 0) <> 0 then Break;
      if PWorkContext(Context)^.CancelDuringWork and (I = 31) then
        InterlockedExchange(C^.Cancelled, 1);
    end;
  finally
    InterlockedIncrement(C^.Finishes);
  end;
end;

procedure RequireJoined(const LabelText: string);
var Created, Joined, Closed, Active, PendingClose: Integer;
begin
  HashWorkerTestSnapshot(Created, Joined, Closed, Active, PendingClose);
  if Active <> 0 then
  begin
    { Do not unwind borrowed stack records while a broken executor has workers. }
    WriteLn(CozyText_HashLifecycleProbe_FAIL_d6c7a88e, LabelText, CozyText_HashLifecycleProbe_worker_remains_active_55c6470f);
    Halt(1);
  end;
  Require(Created = Joined, LabelText + CozyText_HashLifecycleProbe_borrowed_context_returned_before_join_0813eac0);
  Require(Created = Closed, LabelText + CozyText_HashLifecycleProbe_thread_handle_not_closed_3b22372e);
  Require(PendingClose = 0, LabelText + CozyText_HashLifecycleProbe_pending_close_remained_418dcc38);
end;

procedure WorkerFaultContracts;
var
  C: TControl;
  Jobs: array[0..3] of TWorkContext;
  Contexts: array[0..3] of Pointer;
  Cancellation: THashCancellation;
  I, Trial, Scenario, FaultAt: Integer;
  Rejected: Boolean;
begin
  FillChar(Cancellation, SizeOf(Cancellation), 0);
  Cancellation.Check := IsCancelled;
  Cancellation.Context := @C;
  { Repeat create/work/close faults at each possible spawned-thread index.
    Create failures must use synchronous fallback; work/close faults must fail. }
  for Trial := 0 to 15 do
    for Scenario := 0 to 4 do
    begin
      FillChar(C, SizeOf(C), 0); C.Alive := 1;
      for I := 0 to High(Jobs) do
      begin
        Jobs[I].Control := @C;
        Jobs[I].CancelDuringWork := Scenario = 4;
        Contexts[I] := @Jobs[I];
      end;
      FaultAt := 1 + Trial mod 3;
      case Scenario of
        0: ConfigureHashWorkerFaults(FaultAt, 0, 0);
        1: ConfigureHashWorkerFaults(0, 1 + Trial mod 4, 0);
        2: ConfigureHashWorkerFaults(0, 0, FaultAt);
        else ConfigureHashWorkerFaults(0, 0, 0);
      end;
      if Scenario = 3 then C.Cancelled := 1;
      Rejected := False;
      try
        ExecuteBlake3WorkersCancellable(BoundedWork, Contexts, Cancellation);
      except
        on E: EInvalidOp do Rejected := True;
      end;
      Require(Rejected = (Scenario <> 0), CozyText_HashLifecycleProbe_Worker_fault_returned_wrong_success_failure_30d2de34);
      RequireJoined(CozyText_HashLifecycleProbe_Worker_fault_ec280d28);
      Require(C.Starts = C.Finishes, CozyText_HashLifecycleProbe_A_borrowed_job_returned_before_completion_9703caa0);
      Require(C.BadAccess = 0, CozyText_HashLifecycleProbe_Borrowed_context_used_after_its_lifetime_92fbf9e0);
      if Scenario = 0 then Require(C.Starts = 4, CozyText_HashLifecycleProbe_Create_failure_dropped_work_e156a907);
      if Scenario = 3 then Require(C.Starts = 0, CozyText_HashLifecycleProbe_Precancelled_batch_started_work_bc131cb6);
      { Borrowed records remain alive until all workers have joined. }
      InterlockedExchange(C.Alive, 0);
      ClearHashWorkerFaults;
      Inc(Cases);
    end;
end;

procedure NestedExecutorWork(Context: Pointer);
var Rejected: Boolean;
begin
  Rejected := False;
  try ExecuteBlake3Workers(BoundedWork, [Context]);
  except on E: EInvalidOp do Rejected := True; end;
  if not Rejected then raise Exception.Create(CozyText_HashLifecycleProbe_Nested_executor_was_admitted_e312e289);
  InterlockedIncrement(PWorkContext(Context)^.Control^.Finishes);
end;

procedure WorkerReentrancyContract;
var
  C: TControl;
  Jobs: array[0..3] of TWorkContext;
  Contexts: array[0..3] of Pointer;
  I: Integer;
begin
  FillChar(C, SizeOf(C), 0); C.Alive := 1;
  FillChar(Jobs, SizeOf(Jobs), 0);
  for I := 0 to High(Jobs) do
  begin Jobs[I].Control := @C; Contexts[I] := @Jobs[I]; end;
  ConfigureHashWorkerFaults(0, 0, 0);
  try
    ExecuteBlake3Workers(NestedExecutorWork, Contexts);
    RequireJoined(CozyText_HashLifecycleProbe_Nested_executor_rejection_e4c90c7e);
    Require(C.Finishes = 4, CozyText_HashLifecycleProbe_Worker_callback_reentry_was_not_rejected_8fbbad3a);
    Require(C.Starts = 0, CozyText_HashLifecycleProbe_Nested_executor_ran_borrowed_work_12903e37);
    Inc(Cases);
  finally ClearHashWorkerFaults; end;
end;

procedure CancellationAndRecovery;
var
  C: TControl;
  Cancellation: THashCancellation;
  Data: TBytes;
  H: TIntegrityHasher;
  B: TBlake3Hasher;
  Expected, Actual: TIntegrityHashResult;
  I, Kind: Integer;
  Rejected: Boolean;
begin
  SetLength(Data, 2097153);
  for I := 0 to High(Data) do Data[I] := Byte(I mod 251);
  Expected := IntegrityHashesBytes(Data);
  Cancellation.Check := IsCancelled; Cancellation.Context := @C;
  try
    for Kind := 0 to 2 do
    begin
      FillChar(C, SizeOf(C), 0);
      if Kind = 0 then C.Cancelled := 1 else C.CancelAt := 3;
      ConfigureHashWorkerFaults(0, 0, 0);
      H := TIntegrityHasher.Create;
      try
        Rejected := False;
        try
          H.UpdateParallelCancellable(Data[0], Length(Data),
            ExecuteBlake3WorkersCancellable, Cancellation, 2 + Kind);
        except on E: EHashCancelled do Rejected := True; end;
        Require(Rejected, CozyText_HashLifecycleProbe_Integrated_cancellation_was_ignored_50927984);
        RequireJoined(CozyText_HashLifecycleProbe_Integrated_cancellation_c8129e42);
        Rejected := False;
        try H.Finish; except on E: EInvalidOp do Rejected := True; end;
        Require(Rejected, CozyText_HashLifecycleProbe_Cancelled_integrated_digest_remained_readable_dbed404d);
        Rejected := False;
        try H.Update(Data[0], 1); except on E: EInvalidOp do Rejected := True; end;
        Require(Rejected, CozyText_HashLifecycleProbe_Cancelled_integrated_digest_accepted_Update_6ac53968);
        H.Reset;
        FillChar(C, SizeOf(C), 0);
        H.UpdateParallelCancellable(Data[0], Length(Data),
          ExecuteBlake3WorkersCancellable, Cancellation, 2 + Kind);
        Actual := H.Finish;
        Require((Actual.SHA512 = Expected.SHA512) and
          (Actual.XXH3_128 = Expected.XXH3_128) and
          (Actual.Blake3 = Expected.Blake3) and (Actual.Size = Expected.Size),
          CozyText_HashLifecycleProbe_Reset_after_cancellation_did_not_recover_exact_d_2e071062);
        RequireJoined(CozyText_HashLifecycleProbe_Reset_after_cancellation_d7d1c81e);
        Inc(Cases);
      finally H.Free; ClearHashWorkerFaults; end;
    end;
    { Cancel inside a real BLAKE3 leaf batch, after enough checks for dispatch. }
    FillChar(C, SizeOf(C), 0); C.CancelAt := 128;
    ConfigureHashWorkerFaults(0, 0, 0);
    B := TBlake3Hasher.Create;
    try
      Rejected := False;
      try
        B.UpdateParallelCancellable(Data[0], Length(Data),
          ExecuteBlake3WorkersCancellable, Cancellation, 4);
      except on E: EHashCancelled do Rejected := True; end;
      Require(Rejected, CozyText_HashLifecycleProbe_BLAKE3_leaf_cancellation_was_ignored_3c68f076);
      Require(C.Checks >= C.CancelAt, CozyText_HashLifecycleProbe_Leaf_cancellation_was_not_exercised_a3fed2e5);
      RequireJoined(CozyText_HashLifecycleProbe_BLAKE3_leaf_cancellation_e0a5b75d);
      Rejected := False;
      try B.FinishHex; except on E: EInvalidOp do Rejected := True; end;
      Require(Rejected, CozyText_HashLifecycleProbe_Cancelled_BLAKE3_digest_remained_readable_3b2b9eb8);
      Inc(Cases);
    finally B.Free; ClearHashWorkerFaults; end;
  finally FillChar(Data[0], Length(Data), 0); end;
end;

procedure DigestFaultContracts;
var
  Data: TBytes;
  H: TIntegrityHasher;
  Expected, Actual: TIntegrityHashResult;
  Scenario, FaultAt, I: Integer;
  Rejected: Boolean;
begin
  SetLength(Data, 524289);
  for I := 0 to High(Data) do Data[I] := Byte(I mod 251);
  Expected := IntegrityHashesBytes(Data);
  try
    for Scenario := 0 to 2 do
      for FaultAt := 1 to 3 do
      begin
        case Scenario of
          0: ConfigureHashWorkerFaults(FaultAt, 0, 0);
          1: ConfigureHashWorkerFaults(0, FaultAt, 0);
          2: ConfigureHashWorkerFaults(0, 0, FaultAt);
        end;
        H := TIntegrityHasher.Create;
        try
          Rejected := False;
          try H.UpdateParallel(Data[0], Length(Data), ExecuteBlake3Workers, 4);
          except on E: EInvalidOp do Rejected := True; end;
          Require(Rejected = (Scenario <> 0), CozyText_HashLifecycleProbe_Digest_fault_returned_wrong_success_failure_3ac64b6c);
          RequireJoined(CozyText_HashLifecycleProbe_Digest_fault_7fef52f9);
          if Rejected then
          begin
            Rejected := False;
            try H.Finish; except on E: EInvalidOp do Rejected := True; end;
            Require(Rejected, CozyText_HashLifecycleProbe_Faulted_digest_remained_readable_1f645184);
            ClearHashWorkerFaults;
            H.Reset;
            H.UpdateParallel(Data[0], Length(Data), ExecuteBlake3Workers, 4);
          end;
          Actual := H.Finish;
          Require((Actual.SHA512 = Expected.SHA512) and
            (Actual.XXH3_128 = Expected.XXH3_128) and
            (Actual.Blake3 = Expected.Blake3) and (Actual.Size = Expected.Size),
            CozyText_HashLifecycleProbe_Thread_fault_fallback_reset_changed_exact_digest_921f6e78);
          RequireJoined(CozyText_HashLifecycleProbe_Digest_fault_recovered_a39724c6);
          Inc(Cases);
        finally H.Free; ClearHashWorkerFaults; end;
      end;
  finally FillChar(Data[0], Length(Data), 0); end;
end;

function ForeignOwnerEntry(Parameter: Pointer): DWORD; stdcall;
var C: POwnerContext; Value: Byte;
begin
  Result := 1; C := POwnerContext(Parameter); Value := 0;
  try
    try C^.Common.Update(Value, 1); except on E: EInvalidOp do Inc(C^.Rejections); end;
    try C^.Common.Finish; except on E: EInvalidOp do Inc(C^.Rejections); end;
    try C^.Common.Reset; except on E: EInvalidOp do Inc(C^.Rejections); end;
    try C^.Blake.Update(Value, 1); except on E: EInvalidOp do Inc(C^.Rejections); end;
    try C^.Blake.FinishHex; except on E: EInvalidOp do Inc(C^.Rejections); end;
    try C^.Blake.Reset; except on E: EInvalidOp do Inc(C^.Rejections); end;
    Result := 0;
  except C^.Unexpected := True; end;
end;

procedure ReentrantExecutor(Work: TBlake3Work; const Contexts: array of Pointer);
var Rejected: Integer; Value: Byte;
begin
  Rejected := 0; Value := 0;
  if ReentrantHash <> nil then
  begin
    try ReentrantHash.Update(Value, 1); except on E: EInvalidOp do Inc(Rejected); end;
    try ReentrantHash.Finish; except on E: EInvalidOp do Inc(Rejected); end;
    try ReentrantHash.Reset; except on E: EInvalidOp do Inc(Rejected); end;
  end
  else
  begin
    try ReentrantBlake.Update(Value, 1); except on E: EInvalidOp do Inc(Rejected); end;
    try ReentrantBlake.FinishHex; except on E: EInvalidOp do Inc(Rejected); end;
    try ReentrantBlake.Reset; except on E: EInvalidOp do Inc(Rejected); end;
  end;
  Require(Rejected = 3, CozyText_HashLifecycleProbe_Reentrant_wrapper_access_was_not_rejected_2b7c099e);
  ExecuteBlake3Workers(Work, Contexts);
end;

procedure OwnershipContracts;
var
  C: TOwnerContext;
  Thread: THandle;
  ThreadID: DWORD;
  Data: TBytes;
  Expected, Actual: TIntegrityHashResult;
  I: Integer;
begin
  FillChar(C, SizeOf(C), 0);
  C.Common := TIntegrityHasher.Create;
  C.Blake := TBlake3Hasher.Create;
  try
    System.IsMultiThread := True;
    Thread := CreateThread(nil, 0, @ForeignOwnerEntry, @C, 0, ThreadID);
    Require(Thread <> 0, CozyText_HashLifecycleProbe_Ownership_probe_thread_could_not_start_09eda10e);
    try
      Require(WaitForSingleObject(Thread, INFINITE) = WAIT_OBJECT_0,
        CozyText_HashLifecycleProbe_Ownership_probe_join_failed_f4be1009);
    finally CloseHandle(Thread); end;
    Require(not C.Unexpected, CozyText_HashLifecycleProbe_Unexpected_foreign_owner_exception_e2441699);
    Require(C.Rejections = 6, CozyText_HashLifecycleProbe_Foreign_owner_accessed_a_shared_stream_3f515c62);
    Actual := C.Common.Finish;
    Require(Actual.Size = 0, CozyText_HashLifecycleProbe_Foreign_owner_modified_integrated_state_dd783d86);
    Require(C.Blake.FinishHex = Blake3Bytes(nil), CozyText_HashLifecycleProbe_Foreign_owner_modified_BLAKE3_state_29f4dbda);
    SetLength(Data, 524289);
    for I := 0 to High(Data) do Data[I] := Byte(I mod 251);
    Expected := IntegrityHashesBytes(Data);
    ReentrantHash := C.Common;
    C.Common.UpdateParallel(Data[0], Length(Data), ReentrantExecutor, 4);
    Actual := C.Common.Finish;
    Require((Actual.SHA512 = Expected.SHA512) and
      (Actual.XXH3_128 = Expected.XXH3_128) and
      (Actual.Blake3 = Expected.Blake3) and (Actual.Size = Expected.Size),
      CozyText_HashLifecycleProbe_Rejected_reentrancy_modified_wrapper_state_6e02c40c);
    ReentrantHash := nil;
    ReentrantBlake := C.Blake;
    C.Blake.UpdateParallel(Data[0], Length(Data), ReentrantExecutor, 4);
    Require(C.Blake.FinishHex = Expected.Blake3,
      CozyText_HashLifecycleProbe_Rejected_reentrancy_modified_BLAKE3_state_ec4635e6);
    Inc(Cases, 3);
  finally
    ReentrantHash := nil; ReentrantBlake := nil;
    if Length(Data) <> 0 then FillChar(Data[0], Length(Data), 0);
    C.Blake.Free; C.Common.Free;
  end;
end;

begin
  try
    WorkerFaultContracts;
    WorkerReentrancyContract;
    CancellationAndRecovery;
    DigestFaultContracts;
    OwnershipContracts;
    WriteLn(CozyText_HashLifecycleProbe_PASS_hash_lifecycle_cases_22108fd9, Cases,
      CozyText_HashLifecycleProbe_cancellation_exact_reset_owner_reentrancy_create_0008f9e0);
  except
    on E: Exception do
    begin
      WriteLn(E.ClassName, CozyText_HashLifecycleProbe_Text_412c2a9c, E.Message);
      Halt(1);
    end;
  end;
end.
