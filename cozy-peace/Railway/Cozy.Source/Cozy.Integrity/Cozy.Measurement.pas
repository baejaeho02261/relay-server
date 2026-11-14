unit Cozy.Measurement;
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
interface
uses
{ Cozy central text imports. }
  Cozy.Strings.Integrity,
 Winapi.Windows, System.SysUtils;
type
  TMeasurementStatus = (msNotMeasured, msMeasured, msChanged, msReadError, msCoverageInsufficient,
    msCancelled, msDeadlineExceeded);
  EMeasurement = class(Exception)
  private
    FStatus: TMeasurementStatus;
  public
    constructor Create(Status: TMeasurementStatus; const Detail: string);
    property Status: TMeasurementStatus read FStatus;
  end;
  TMeasurementCancelled = reference to function: Boolean;
  TMeasurementBudget = record
    MaxBytes, DeadlineTick: UInt64;
    Cancelled: TMeasurementCancelled;
    class function Start(MaximumBytes: UInt64; Milliseconds: Cardinal;
      const IsCancelled: TMeasurementCancelled = nil): TMeasurementBudget; static;
    function WithCancellation(const Additional: TMeasurementCancelled): TMeasurementBudget;
    procedure Check(NextOffset, Count: UInt64);
  end;
function MeasurementTick: UInt64;
function MeasurementStatusName(Status: TMeasurementStatus): string;
function MeasurementFailureStatus(Error: Exception): TMeasurementStatus;
{ Reopens the SAME underlying file by handle, never by its mutable path.
  The new FILE_FLAG_OVERLAPPED handle has no shared synchronous file position.
  Retain this handle BEFORE unlinking an own image; never reopen by pathname. }
function OpenMeasurementHandle(Source: THandle): THandle;
procedure CloseMeasurementHandle(var Handle: THandle);
function ReadMeasurementBytes(Source: THandle; const Budget: TMeasurementBudget): TBytes;
{ An explicit finite module-file cap. The two-argument reader remains capped
  at 64 MiB even when its caller supplies a larger byte budget. }
function ReadMeasurementBytesBounded(Source: THandle;
  const Budget: TMeasurementBudget; MaximumBytes: UInt64): TBytes;
function ReadMeasurementAt(Handle: THandle; Offset: UInt64; Buffer: Pointer;
  Count: Cardinal; const Budget: TMeasurementBudget): Cardinal;
{$IFDEF GAME_MEASUREMENT_TESTS}
procedure ExerciseDrainStartFailureForTest(Source: THandle);
function OutstandingMeasurementReadsForTest: Integer;
procedure StartMeasurementDrainForTest(Source, TailEntered, TailResume: THandle);
procedure FinalizeMeasurementDrainsForTest;
{$ENDIF}
implementation
uses Cozy.Clock, System.SyncObjs, Cozy.WinApi, Cozy.Api.Pointer,
  Cozy.Api.ROR13, Cozy.Platform.ExportResolver, Cozy.Api.Contracts;
const
{$I Cozy.ModuleLimits.inc}
type
  TRead = function(Handle: THandle; Buffer: Pointer; Count: DWORD;
    BytesRead: PDWORD; Operation: POverlapped): BOOL; stdcall;
  TOpen = function(Handle: THandle; Access, Share, Flags: DWORD): THandle; stdcall;
  TResult = function(Handle: THandle; var Operation: TOverlapped;
    out Count: DWORD; Wait: BOOL): BOOL; stdcall;
  TCancel = function(Handle: THandle; Operation: POverlapped): BOOL; stdcall;
  TDrainLockCall = procedure(Lock: Pointer); stdcall;
var
  Slot_Open, Slot_Result, Slot_Cancel, Slot_Read, Slot_Close, Slot_Duplicate, Slot_Event, Slot_Wait, Slot_Error, Slot_Info, Slot_DrainLock, Slot_DrainUnlock, Slot_TerminateProcess: TEncodedApiPointer;
  PendingCleanup, OutstandingReads, DrainsFinalizing: Integer;
  DrainLock: NativeUInt; { Zero-initialized SRWLOCK, outlives all owned workers. }
  DrainThreads: array[0..7] of THandle;
{$IFDEF GAME_MEASUREMENT_TESTS}
  ForceDrainStartFailure: Boolean;
  DrainTailEntered, DrainTailResume: THandle;
{$ENDIF}
function MeasurementTick: UInt64;
var P: TCozyClockRead;
begin P := @CozyTick; Result := P(); end;
function LastError: DWORD;
var P: TApiGetLastError;
begin P := TApiGetLastError(DecodeApiPointer(Slot_Error)); Result := P(); end;
function WaitEvent(Event: THandle; Milliseconds: Cardinal): DWORD;
var P: TApiWaitForSingleObject;
begin P := TApiWaitForSingleObject(DecodeApiPointer(Slot_Wait)); Result := P(Event, Milliseconds); end;
procedure CloseMeasurementHandle(var Handle: THandle);
var P: TApiCloseHandle;
begin
  if (Handle <> 0) and (Handle <> INVALID_HANDLE_VALUE) then
  begin P := TApiCloseHandle(DecodeApiPointer(Slot_Close)); P(Handle); end;
  Handle := 0;
end;
function OpenMeasurementHandle(Source: THandle): THandle;
var P: TOpen;
begin
  if (Source = 0) or (Source = INVALID_HANDLE_VALUE) then
    raise EMeasurement.Create(msReadError, CozyText_Measurement_SOURCE_HANDLE_INVALID_90ed60fa);
  P := TOpen(DecodeApiPointer(Slot_Open));
  Result := P(Source, GENERIC_READ, FILE_SHARE_READ or FILE_SHARE_WRITE or
    FILE_SHARE_DELETE, FILE_FLAG_OVERLAPPED or FILE_FLAG_SEQUENTIAL_SCAN);
  if Result = INVALID_HANDLE_VALUE then
    raise EMeasurement.Create(msReadError, CozyText_Measurement_REOPEN_FAILED_3fae02ca);
end;
constructor EMeasurement.Create(Status: TMeasurementStatus; const Detail: string);
begin
  FStatus := Status;
  inherited Create(MeasurementStatusName(Status) + ':' + Detail);
end;
function MeasurementStatusName(Status: TMeasurementStatus): string;
begin
  case Status of
    msNotMeasured: Result := CozyText_Measurement_NOT_MEASURED_8eeacf93;
    msMeasured: Result := CozyText_Measurement_MEASURED_92fc664d;
    msChanged: Result := CozyText_Measurement_FILE_CHANGED_d1f5d113;
    msReadError: Result := CozyText_Measurement_READ_ERROR_5acf186e;
    msCoverageInsufficient: Result := CozyText_Measurement_COVERAGE_INSUFFICIENT_36942cd2;
    msCancelled: Result := CozyText_Measurement_CANCELLED_83b14edf;
    msDeadlineExceeded: Result := CozyText_Measurement_DEADLINE_EXCEEDED_081447e2;
  else Result := CozyText_Measurement_READ_ERROR_5acf186e; end;
end;
function MeasurementFailureStatus(Error: Exception): TMeasurementStatus;
begin
  Result := msReadError;
  if Error is EMeasurement then Result := EMeasurement(Error).Status;
  { A thrown exception cannot be reported as a successful measurement. }
  if Result = msMeasured then Result := msReadError;
end;
class function TMeasurementBudget.Start(MaximumBytes: UInt64; Milliseconds: Cardinal;
  const IsCancelled: TMeasurementCancelled): TMeasurementBudget;
var NowTick: UInt64;
begin
  if (MaximumBytes = 0) or (Milliseconds = 0) then
    raise EArgumentException.Create(CozyText_Measurement_Measurement_requires_finite_byte_time_budgets_ef298ded);
  NowTick := MeasurementTick;
  if NowTick > High(UInt64) - Milliseconds then
    raise EMeasurement.Create(msDeadlineExceeded, CozyText_Measurement_CLOCK_OVERFLOW_8b3bab6a);
  Result.MaxBytes := MaximumBytes; Result.DeadlineTick := NowTick + Milliseconds;
  Result.Cancelled := IsCancelled;
end;
function TMeasurementBudget.WithCancellation(const Additional: TMeasurementCancelled): TMeasurementBudget;
var Previous, Extra: TMeasurementCancelled;
begin
  Result := Self;
  Previous := Cancelled; Extra := Additional;
  Result.Cancelled := function: Boolean
    begin
      Result := Assigned(Extra) and Extra();
      if not Result then Result := Assigned(Previous) and Previous();
    end;
end;

procedure TMeasurementBudget.Check(NextOffset, Count: UInt64);
begin
  if Assigned(Cancelled) and Cancelled() then
    raise EMeasurement.Create(msCancelled, CozyText_Measurement_REQUEST_STOPPED_2d0c8292);
  if (DeadlineTick = 0) or (MeasurementTick >= DeadlineTick) then
    raise EMeasurement.Create(msDeadlineExceeded, CozyText_Measurement_REQUEST_DEADLINE_ba96bc67);
  if (MaxBytes = 0) or (NextOffset > MaxBytes) or (Count > MaxBytes - NextOffset) then
    raise EMeasurement.Create(msCoverageInsufficient, CozyText_Measurement_BYTE_BUDGET_e289b2bb);
end;
type
  { A cancelled OS operation can complete after its caller returns. Only this
    bounded heap buffer, event and duplicate handle survive; no security object,
    caller buffer or callback is captured by the drain thread. }
  TPendingRead = class
    Handle: THandle;
    Operation: TOverlapped;
    Bytes: TBytes;
    Pending, Admitted: Boolean;
    constructor Create(Source: THandle; Offset: UInt64; Count: Cardinal);
    destructor Destroy; override;
    function Complete(Wait: Boolean; out Count: DWORD): Boolean;
    procedure Drain;
    procedure Abandon;
  end;
constructor TPendingRead.Create(Source: THandle; Offset: UInt64; Count: Cardinal);
var Dup: TApiDuplicateHandle; Event: TApiCreateEventW; Lock, Unlock: TDrainLockCall;
begin
  inherited Create;
  Lock := TDrainLockCall(DecodeApiPointer(Slot_DrainLock));
  Unlock := TDrainLockCall(DecodeApiPointer(Slot_DrainUnlock));
  Lock(@DrainLock);
  try
    { Admission and shutdown are serialized: a read cannot pass the shutdown
      check and acquire its resource charge after finalization has sealed it. }
    if TInterlocked.CompareExchange(DrainsFinalizing, 0, 0) <> 0 then
      raise EMeasurement.Create(msCancelled, CozyText_Measurement_MEASUREMENT_SHUTDOWN_3de7595b);
    if TInterlocked.CompareExchange(OutstandingReads, 0, 0) >= 8 then
      raise EMeasurement.Create(msCoverageInsufficient, CozyText_Measurement_IO_DRAIN_CAPACITY_7fc71938);
    TInterlocked.Increment(OutstandingReads); Admitted := True;
  finally Unlock(@DrainLock); end;
  Dup := TApiDuplicateHandle(DecodeApiPointer(Slot_Duplicate));
  if not Dup(THandle(High(NativeUInt)), Source, THandle(High(NativeUInt)),
    @Handle, 0, False, DUPLICATE_SAME_ACCESS) then
    raise EMeasurement.Create(msReadError, CozyText_Measurement_DUPLICATE_FAILED_9d4db059);
  Event := TApiCreateEventW(DecodeApiPointer(Slot_Event));
  Operation.hEvent := Event(nil, True, False, nil);
  if Operation.hEvent = 0 then raise EMeasurement.Create(msReadError, CozyText_Measurement_EVENT_FAILED_e3ddd76a);
  Operation.Offset := Cardinal(Offset and $FFFFFFFF);
  Operation.OffsetHigh := Cardinal(Offset shr 32);
  SetLength(Bytes, Count);
end;
destructor TPendingRead.Destroy;
begin
  { No caller frees an OVERLAPPED that the kernel can still reference. }
  if Pending then Drain;
  if Length(Bytes) > 0 then FillChar(Bytes[0], Length(Bytes), 0);
  Bytes := nil;
  CloseMeasurementHandle(Operation.hEvent); CloseMeasurementHandle(Handle);
  if Admitted then TInterlocked.Decrement(OutstandingReads);
  inherited;
end;
function TPendingRead.Complete(Wait: Boolean; out Count: DWORD): Boolean;
var P: TResult; Error: DWORD;
begin
  P := TResult(DecodeApiPointer(Slot_Result)); Count := 0;
  Result := P(Handle, Operation, Count, Wait);
  if Result then Pending := False
  else begin
    Error := LastError;
    if Error <> ERROR_IO_INCOMPLETE then Pending := False;
    if Error = ERROR_HANDLE_EOF then begin Count := 0; Result := True; end;
  end;
end;
procedure TPendingRead.Drain;
var P: TCancel; Count: DWORD;
begin
  if not Pending then Exit;
  P := TCancel(DecodeApiPointer(Slot_Cancel)); P(Handle, @Operation);
  Complete(True, Count);
end;
function DrainPendingRead(Parameter: Pointer): Integer;
var Held: TPendingRead;
begin
  Result := 0; Held := TPendingRead(Parameter);
  try
    try
      Held.Drain;
      if not Held.Pending then Held.Free;
    except
      { An unexpected API/RTL failure cannot establish kernel completion.
        Quarantine this bounded object until process exit rather than free an
        OVERLAPPED or buffer that Windows may still reference. Its admission
        remains charged, so repeated faults cannot allocate without limit. }
    end;
  finally TInterlocked.Decrement(PendingCleanup); end;
  {$IFDEF GAME_MEASUREMENT_TESTS}
  { The test holds the worker AFTER the pending-I/O counter reached zero.
    Shutdown must still join the actual thread, including its RTL cleanup tail. }
  if DrainTailEntered <> 0 then
  begin
    Winapi.Windows.SetEvent(DrainTailEntered);
    WaitEvent(DrainTailResume, INFINITE);
  end;
  {$ENDIF}
end;

procedure DrainOwnedMeasurementWorkers;
var Lock, Unlock: TDrainLockCall; Terminate: TApiTerminateProcess;
  Tick: TCozyClockRead; Wait: TApiWaitForSingleObject; Close: TApiCloseHandle;
  Threads: array[0..7] of THandle; I: Integer; Started, Elapsed: UInt64; Remaining: Cardinal;
begin
  { Resolve EVERY drain dependency before detaching any retained handle. No
    pointer-decoding exception may interrupt the joins after ownership moves. }
  Lock := TDrainLockCall(DecodeApiPointer(Slot_DrainLock));
  Unlock := TDrainLockCall(DecodeApiPointer(Slot_DrainUnlock));
  Terminate := TApiTerminateProcess(DecodeApiPointer(Slot_TerminateProcess));
  Tick := @CozyTick;
  Wait := TApiWaitForSingleObject(DecodeApiPointer(Slot_Wait));
  Close := TApiCloseHandle(DecodeApiPointer(Slot_Close));
  Lock(@DrainLock);
  try
    TInterlocked.Exchange(DrainsFinalizing, 1);
    { Admission, creation and handle publication use this same lock. A finalizer
      cannot overlook a started but unpublished worker. }
    for I := 0 to High(Threads) do
    begin Threads[I] := DrainThreads[I]; DrainThreads[I] := 0; end;
  finally Unlock(@DrainLock); end;
  Started := Tick();
  for I := 0 to High(Threads) do
    if Threads[I] <> 0 then
    begin
      Elapsed := Tick() - Started;
      Remaining := 0; if Elapsed < 2000 then Remaining := Cardinal(2000 - Elapsed);
      if Wait(Threads[I], Remaining) <> WAIT_OBJECT_0 then
      begin
        { Every worker cancels its I/O before draining. An uncooperative driver
          must not leave Delphi-managed cleanup running during dependency/RTL
          finalization. Terminate ONLY our process; remote cleanup may be lost.
          Never terminate an individual thread or free its pending buffer. }
        Terminate(THandle(High(NativeUInt)), ERROR_OPERATION_ABORTED);
        while Wait(Threads[I], INFINITE) <> WAIT_OBJECT_0 do
          Terminate(THandle(High(NativeUInt)), ERROR_OPERATION_ABORTED);
      end;
      Close(Threads[I]); Threads[I] := 0;
    end;
  { Application owners must join their own callers before RTL finalization.
    Also retain dependencies for already admitted, not-yet-abandoned reads;
    they drain synchronously after admission is sealed. This counter accounts
    for owned buffers/handles, NOT the termination of an application's thread.
    Owned drain threads above are always joined by their actual kernel handle. }
  while TInterlocked.CompareExchange(OutstandingReads, 0, 0) <> 0 do
  begin
    if Tick() - Started >= 2000 then
      Terminate(THandle(High(NativeUInt)), ERROR_OPERATION_ABORTED);
    { The current process cannot signal during this wait; use a bounded native
      wait without resolving additional API pointers during finalization. }
    Wait(THandle(High(NativeUInt)), 1);
  end;
end;

procedure TPendingRead.Abandon;
var ThreadHandle: THandle; ThreadId: System.TThreadID;
  Lock, Unlock: TDrainLockCall; I, Selected: Integer; OwnershipTransferred: Boolean;
begin
  OwnershipTransferred := False;
  try
    Lock := TDrainLockCall(DecodeApiPointer(Slot_DrainLock));
    Unlock := TDrainLockCall(DecodeApiPointer(Slot_DrainUnlock));
    Lock(@DrainLock);
    try
      if TInterlocked.CompareExchange(DrainsFinalizing, 0, 0) <> 0 then
        raise EMeasurement.Create(msCancelled, CozyText_Measurement_MEASUREMENT_SHUTDOWN_3de7595b);
      Selected := -1;
      for I := 0 to High(DrainThreads) do
      begin
        if (DrainThreads[I] <> 0) and (WaitEvent(DrainThreads[I], 0) = WAIT_OBJECT_0) then
          CloseMeasurementHandle(DrainThreads[I]);
        if (DrainThreads[I] = 0) and (Selected < 0) then Selected := I;
      end;
      if Selected < 0 then raise EMeasurement.Create(msCoverageInsufficient, CozyText_Measurement_IO_DRAIN_CAPACITY_7fc71938);
      TInterlocked.Increment(PendingCleanup);
      try
        {$IFDEF GAME_MEASUREMENT_TESTS}
        if ForceDrainStartFailure then raise EMeasurement.Create(msReadError, CozyText_Measurement_IO_DRAIN_START_3a33dedf);
        {$ENDIF}
        { RTL thread frame, immediate start, and no suspended thread object.
          The registry retains the kernel handle until ACTUAL thread exit. }
        ThreadHandle := System.BeginThread(nil, 0, DrainPendingRead, Self, 0, ThreadId);
        if (ThreadHandle = 0) or (ThreadHandle = INVALID_HANDLE_VALUE) then
          raise EMeasurement.Create(msReadError, CozyText_Measurement_IO_DRAIN_START_3a33dedf);
        OwnershipTransferred := True;
      except TInterlocked.Decrement(PendingCleanup); raise; end;
      DrainThreads[Selected] := ThreadHandle;
    finally Unlock(@DrainLock); end;
  except
    { A started worker may already have freed Self. Never touch it again after
      ownership transferred, even if a later unlock raises an exception. }
    if not OwnershipTransferred then
    begin
      { No worker exists after failed creation/admission. Drain synchronously
        before freeing; resource exhaustion can exceed the caller's deadline. }
      try Drain; finally if not Pending then Free; end;
    end;
    raise;
  end;
end;
{$IFDEF GAME_MEASUREMENT_TESTS}
function OutstandingMeasurementReadsForTest: Integer;
begin Result := TInterlocked.CompareExchange(OutstandingReads, 0, 0); end;
procedure StartMeasurementDrainForTest(Source, TailEntered, TailResume: THandle);
var Op: TPendingRead;
begin
  DrainTailEntered := TailEntered; DrainTailResume := TailResume;
  Op := TPendingRead.Create(Source, 0, 1); Op.Abandon;
end;
procedure FinalizeMeasurementDrainsForTest;
begin DrainOwnedMeasurementWorkers; end;
procedure ExerciseDrainStartFailureForTest(Source: THandle);
var Op: TPendingRead;
begin
  Op := TPendingRead.Create(Source, 0, 1);
  ForceDrainStartFailure := True;
  try Op.Abandon;
  finally ForceDrainStartFailure := False; end;
end;
{$ENDIF}
function ReadMeasurementAt(Handle: THandle; Offset: UInt64; Buffer: Pointer;
  Count: Cardinal; const Budget: TMeasurementBudget): Cardinal;
var Op, Detached: TPendingRead; P: TRead; Error, WaitResult: DWORD;
  Span: TApiBuffer;
  ReadTarget: Pointer;
begin
  Result := 0; Budget.Check(Offset, Count);
  if (Count = 0) or (Count > 65536) or (Buffer = nil) then
    raise EArgumentException.Create(CozyText_Measurement_Invalid_bounded_measurement_read_08e63d00);
  if (Offset > UInt64(High(Int64))) or (UInt64(Count) > UInt64(High(Int64)) - Offset) then
    raise EMeasurement.Create(msCoverageInsufficient, CozyText_Measurement_OFFSET_RANGE_28d6dab7);
  Op := TPendingRead.Create(Handle, Offset, Count);
  try
    ReadTarget := DecodeApiPointer(Slot_Read);
    RequireApiTarget(ReadTarget);
    P := TRead(ReadTarget);
    Span := TApiBuffer.WriteBytes(Op.Bytes);
    if not P(Op.Handle, Span.Write(0, Count), Count, nil, @Op.Operation) then
    begin
      Error := LastError;
      if Error = ERROR_HANDLE_EOF then
      begin Budget.Check(Offset, 0); Exit(0); end;
      if Error <> ERROR_IO_PENDING then raise EMeasurement.Create(msReadError, CozyText_Measurement_READ_FAILED_6a5c2653);
      Op.Pending := True;
      repeat
        Budget.Check(Offset, Count);
        WaitResult := WaitEvent(Op.Operation.hEvent, 25);
        if WaitResult = WAIT_OBJECT_0 then Break;
        if WaitResult <> WAIT_TIMEOUT then raise EMeasurement.Create(msReadError, CozyText_Measurement_WAIT_FAILED_5a0fc476);
      until False;
    end;
    { Get the actual byte count for BOTH immediate and pending completion. }
    if not Op.Complete(False, Result) then raise EMeasurement.Create(msReadError, CozyText_Measurement_READ_COMPLETION_FAILED_5853428e);
    Budget.Check(Offset, Result);
    if Result > Count then raise EMeasurement.Create(msReadError, CozyText_Measurement_INVALID_BYTE_COUNT_4209f3c4);
    Span.Completed(Count, Result);
    if Result > 0 then Move(Op.Bytes[0], Buffer^, Result);
  finally
    if Op.Pending then
    begin Detached := Op; Op := nil; Detached.Abandon; end;
    Op.Free;
  end;
end;
function ReadMeasurementBytes(Source: THandle; const Budget: TMeasurementBudget): TBytes;
begin
  Result := ReadMeasurementBytesBounded(Source, Budget, OwnPeFileLimit);
end;
function ReadMeasurementBytesBounded(Source: THandle;
  const Budget: TMeasurementBudget; MaximumBytes: UInt64): TBytes;
var Handle: THandle; Info, FinalInfo: TByHandleFileInformation;
  P: TApiGetFileInformationByHandle; Size, Offset: UInt64; Want, Count: Cardinal;
begin
  Result := nil; Budget.Check(0, 0);
  if (MaximumBytes = 0) or (MaximumBytes > InventoryPeFileLimit) then
    raise EMeasurement.Create(msCoverageInsufficient, CozyText_Measurement_PE_LIMIT_INVALID_459ff1c5);
  Handle := OpenMeasurementHandle(Source);
  try
   try
    P := TApiGetFileInformationByHandle(DecodeApiPointer(Slot_Info));
    if not P(Handle, Info) then raise EMeasurement.Create(msReadError, CozyText_Measurement_FILE_INFORMATION_ff31df67);
    Size := (UInt64(Info.nFileSizeHigh) shl 32) or Info.nFileSizeLow;
    Budget.Check(0, Size);
    { Check both caller cap and addressable array size BEFORE allocating. }
    if (Size > MaximumBytes) or (Size > UInt64(High(NativeInt))) then
      raise EMeasurement.Create(msCoverageInsufficient, CozyText_Measurement_PE_SIZE_a36ea6b7);
    SetLength(Result, NativeInt(Size)); Offset := 0;
    while Offset < Size do
    begin
      Want := 65536; if Size - Offset < Want then Want := Cardinal(Size - Offset);
      Count := ReadMeasurementAt(Handle, Offset, @Result[NativeInt(Offset)], Want, Budget);
      if Count = 0 then raise EMeasurement.Create(msChanged, CozyText_Measurement_EARLY_EOF_dbe96fd6);
      Inc(Offset, Count);
    end;
    Budget.Check(Offset, 0);
    if not P(Handle, FinalInfo) then raise EMeasurement.Create(msReadError, CozyText_Measurement_FINAL_INFORMATION_3eaa189f);
    if (Info.dwVolumeSerialNumber <> FinalInfo.dwVolumeSerialNumber) or
      (Info.nFileIndexHigh <> FinalInfo.nFileIndexHigh) or
      (Info.nFileIndexLow <> FinalInfo.nFileIndexLow) or
      (Info.nFileSizeHigh <> FinalInfo.nFileSizeHigh) or (Info.nFileSizeLow <> FinalInfo.nFileSizeLow) or
      (Info.ftLastWriteTime.dwHighDateTime <> FinalInfo.ftLastWriteTime.dwHighDateTime) or
      (Info.ftLastWriteTime.dwLowDateTime <> FinalInfo.ftLastWriteTime.dwLowDateTime) then
      raise EMeasurement.Create(msChanged, CozyText_Measurement_FILE_METADATA_CHANGED_4b386fb4);
    Budget.Check(Offset, 0);
  except
    if Length(Result) > 0 then FillChar(Result[0], Length(Result), 0);
    Result := nil;
    raise;
  end;
  finally CloseMeasurementHandle(Handle); end;
end;
initialization
  BindApiPointer(Slot_DrainLock, RequireProcAddressHash64(CozyText_Measurement_kernel32_dll_994db220, HASH_AcquireSRWLockExclusive));
  BindApiPointer(Slot_DrainUnlock, RequireProcAddressHash64(CozyText_Measurement_kernel32_dll_994db220, HASH_ReleaseSRWLockExclusive));
  BindApiPointer(Slot_TerminateProcess, RequireProcAddressHash64(CozyText_Measurement_kernel32_dll_994db220, HASH_TerminateProcess));
  BindApiPointer(Slot_Info, RequireProcAddressHash64(CozyText_Measurement_kernel32_dll_994db220, HASH_GetFileInformationByHandle));
  BindApiPointer(Slot_Open, RequireProcAddressHash64(CozyText_Measurement_kernel32_dll_994db220, HASH_ReOpenFile));
  BindApiPointer(Slot_Result, RequireProcAddressHash64(CozyText_Measurement_kernel32_dll_994db220, HASH_GetOverlappedResult));
  BindApiPointer(Slot_Cancel, RequireProcAddressHash64(CozyText_Measurement_kernel32_dll_994db220, HASH_CancelIoEx));
  BindApiPointer(Slot_Read, RequireProcAddressHash64(CozyText_Measurement_kernel32_dll_994db220, HASH_ReadFile));
  BindApiPointer(Slot_Close, RequireProcAddressHash64(CozyText_Measurement_kernel32_dll_994db220, HASH_CloseHandle));
  BindApiPointer(Slot_Duplicate, RequireProcAddressHash64(CozyText_Measurement_kernel32_dll_994db220, HASH_DuplicateHandle));
  BindApiPointer(Slot_Event, RequireProcAddressHash64(CozyText_Measurement_kernel32_dll_994db220, HASH_CreateEventW));
  BindApiPointer(Slot_Wait, RequireProcAddressHash64(CozyText_Measurement_kernel32_dll_994db220, HASH_WaitForSingleObject));
  BindApiPointer(Slot_Error, RequireProcAddressHash64(CozyText_Measurement_kernel32_dll_994db220, HASH_GetLastError));

finalization
  DrainOwnedMeasurementWorkers;
end.
