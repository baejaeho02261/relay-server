unit Cozy.DeviceSignals;
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
interface
uses
{ Cozy central text imports. }
  Cozy.Strings.Identity,
 System.JSON, Cozy.Measurement;
{ Set only after an accepted authenticated server observation. A request is
  consumed once, expires after 45 seconds and never changes PC/license binding. }
procedure ConfigureDeviceSignalsRequest(Requested: Boolean;
  const SessionID, ChallengeID, Nonce: string);
function CollectDeviceSignalsJSON(const Budget: TMeasurementBudget): TJSONObject;
implementation
uses Cozy.Clock, Winapi.Windows, System.SysUtils, System.SyncObjs, Cozy.WinApi,
  Cozy.Api.Pointer, Cozy.Api.ROR13, Cozy.Platform.ExportResolver, Cozy.Hashes, Cozy.DeviceSignals.Core;
type
  TLockCall = procedure(Lock: Pointer); stdcall;
  TDeviceControl = function(Device: THandle; Code: DWORD; Input: Pointer;
    InputBytes: DWORD; Output: Pointer; OutputBytes: DWORD;
    out Returned: DWORD; Overlapped: POverlapped): BOOL; stdcall;
  TGetIfTable = function(out Table: Pointer): DWORD; stdcall;
  TFreeIfTable = procedure(Table: Pointer); stdcall;
  TCancelSync = function(Thread: THandle): BOOL; stdcall;
  PMibRow = ^TGameMibIfRow2;
  PMibTable = ^TGameMibIfTable2;
  PDeviceWork = ^TDeviceWork;
  TDeviceWork = record
    References, Stop: Integer;
    Event, ThreadHandle: THandle;
    Deadline: UInt64;
    Key: TBytes;
    Digest: string;
    DiskCount, NicCount: Cardinal;
    Partial, Truncated: Boolean;
    Lock, Unlock: TLockCall;
    Open: TApiCreateFileW;
    Control: TDeviceControl;
    Error: TApiGetLastError;
    Close: TApiCloseHandle;
    Tick: TCozyClockRead;
    Signal: TApiSetEvent;
    Wait: TApiWaitForSingleObject;
    Cancel: TCancelSync;
    GetTable: TGetIfTable;
    FreeTable: TFreeIfTable;
  end;
var
  Slot_Lock, Slot_Unlock, Slot_Open, Slot_Control, Slot_Error, Slot_Close, Slot_Event, Slot_Signal, Slot_Wait, Slot_Thread, Slot_Cancel, Slot_GetIfTable2, Slot_FreeMibTable, Slot_TerminateProcess: TEncodedApiPointer;
  RequestLock: NativeUInt; { SRWLOCK_INIT: zero, process-lifetime storage. }
  RequestKey: array[0..31] of Byte;
  RequestScope: string;
  RequestDeadline: UInt64;
  Finalizing: Integer;
  RegisteredWorker: PDeviceWork;
const MaximumWaitMilliseconds = 1500;
procedure ConfigureDeviceSignalsRequest(Requested: Boolean;
  const SessionID, ChallengeID, Nonce: string);
var Lock, Unlock: TLockCall; Key, Domain, Material, ScopeInput: TBytes;
  Scope: string; Tick: TCozyClockRead; UntilTick, NowTick: UInt64;
begin
  Lock := TLockCall(DecodeApiPointer(Slot_Lock));
  Unlock := TLockCall(DecodeApiPointer(Slot_Unlock));
  UntilTick := 0;
  try
    if Requested then
    begin
      if (SessionID = '') or (Length(SessionID) > 100) or
        (Length(ChallengeID) <> 48) or (Length(Nonce) <> 48) then
        raise EArgumentException.Create(CozyText_DeviceSignals_DEVICE_SIGNAL_REQUEST_35e5873f);
      Domain := TEncoding.UTF8.GetBytes(CozyText_DeviceSignals_cozy_Client_DeviceSignals_Challenge_v1_dc2e0794);
      Material := TEncoding.UTF8.GetBytes(SessionID + #10 + Nonce);
      ScopeInput := TEncoding.UTF8.GetBytes(SessionID + #10 + ChallengeID);
      Key := Blake3DeriveKeyBytes(Domain, Material); Scope := SHA512Bytes(ScopeInput);
      Tick := @CozyTick; NowTick := Tick();
      if NowTick > High(UInt64) - 45000 then raise EArgumentException.Create(CozyText_DeviceSignals_DEVICE_SIGNAL_CLOCK_f4c6e8f5);
      UntilTick := NowTick + 45000;
    end;
    Lock(@RequestLock);
    try
      FillChar(RequestKey, SizeOf(RequestKey), 0); RequestScope := ''; RequestDeadline := 0;
      if Requested then
      begin Move(Key[0], RequestKey, 32); RequestScope := Scope; RequestDeadline := UntilTick; end;
    finally Unlock(@RequestLock); end;
  finally ClearDeviceBytes(Key); ClearDeviceBytes(Domain); ClearDeviceBytes(Material); ClearDeviceBytes(ScopeInput); end;
end;
function TakeRequest(out Key: TBytes; out Scope: string): Boolean;
var Lock, Unlock: TLockCall; Tick: TCozyClockRead;
begin
  Key := nil; Scope := '';
  Lock := TLockCall(DecodeApiPointer(Slot_Lock)); Unlock := TLockCall(DecodeApiPointer(Slot_Unlock));
  Tick := @CozyTick;
  Lock(@RequestLock);
  try
    Result := (RequestDeadline <> 0) and (Tick() < RequestDeadline);
    if Result then begin SetLength(Key, 32); Move(RequestKey, Key[0], 32); Scope := RequestScope; end;
    FillChar(RequestKey, SizeOf(RequestKey), 0); RequestScope := ''; RequestDeadline := 0;
  finally Unlock(@RequestLock); end;
end;
procedure ReleaseWork(Work: PDeviceWork);
begin
  if TInterlocked.Decrement(Work.References) <> 0 then Exit;
  if Work.ThreadHandle <> 0 then Work.Close(Work.ThreadHandle);
  if Work.Event <> 0 then Work.Close(Work.Event);
  ClearDeviceBytes(Work.Key); Work.Digest := ''; Dispose(Work);
end;
procedure DrainOwnedWorker;
var Work: PDeviceWork; Lock, Unlock: TLockCall; Terminate: TApiTerminateProcess;
begin
  TInterlocked.Exchange(Finalizing, 1);
  Lock := TLockCall(DecodeApiPointer(Slot_Lock)); Unlock := TLockCall(DecodeApiPointer(Slot_Unlock));
  Terminate := TApiTerminateProcess(DecodeApiPointer(Slot_TerminateProcess));
  Lock(@RequestLock);
  try
    Work := RegisteredWorker; RegisteredWorker := nil;
    FillChar(RequestKey, SizeOf(RequestKey), 0); RequestScope := ''; RequestDeadline := 0;
  finally Unlock(@RequestLock); end;
  if Work = nil then Exit;
  TInterlocked.Exchange(Work.Stop, 1); Work.Cancel(Work.ThreadHandle);
  if Work.Wait(Work.ThreadHandle, 2000) <> WAIT_OBJECT_0 then
  begin
    { Unit dependency ordering runs this before Hashes/RTL finalization, after
      ordinary application cleanup. An uncooperative driver must not leave a
      managed-code worker executing during RTL teardown. Only OUR process is
      terminated; later finalizers may be skipped and remote cleanup is not
      guaranteed. Never release the live worker or call TerminateThread. }
    Terminate(THandle(High(NativeUInt)), ERROR_OPERATION_ABORTED);
    while Work.Wait(Work.ThreadHandle, INFINITE) <> WAIT_OBJECT_0 do
      Terminate(THandle(High(NativeUInt)), ERROR_OPERATION_ABORTED);
  end;
  ReleaseWork(Work);
end;
function Stopped(Work: PDeviceWork): Boolean;
begin
  Result := (TInterlocked.CompareExchange(Work.Stop, 0, 0) <> 0) or
    (Work.Tick() >= Work.Deadline);
  if Result then Work.Truncated := True;
end;
procedure ReadDisks(Work: PDeviceWork; var Signals: TDeviceSignalSet);
var Index: Integer; Handle: THandle; Query: TGameStoragePropertyQuery;
  Buffer, Serial: TBytes; Returned, ErrorCode: DWORD; Path: string;
begin
  Query := Default(TGameStoragePropertyQuery); { StorageDeviceProperty / PropertyStandardQuery }
  SetLength(Buffer, 4096);
  try
    for Index := 0 to MaximumSignalDisks - 1 do
    begin
      if Stopped(Work) then Exit;
      Path := CozyText_DeviceSignals_PhysicalDrive_2cd56462 + IntToStr(Index);
      Handle := Work.Open(PWideChar(Path), 0, FILE_SHARE_READ or FILE_SHARE_WRITE or
        FILE_SHARE_DELETE, nil, OPEN_EXISTING, 0, 0);
      if Handle = INVALID_HANDLE_VALUE then
      begin
        ErrorCode := Work.Error();
        if (ErrorCode <> ERROR_FILE_NOT_FOUND) and (ErrorCode <> ERROR_PATH_NOT_FOUND) then Work.Partial := True;
        Continue;
      end;
      try
        Returned := 0; FillChar(Buffer[0], Length(Buffer), 0);
        if Work.Control(Handle, $002D1400, @Query, SizeOf(Query), @Buffer[0],
          Length(Buffer), Returned, nil) and ParseStorageSerial(Buffer, Returned, Serial) then
        begin
          if not Stopped(Work) then AddDeviceSignal(Signals, 1, Work.Key, Serial);
        end
        else Work.Partial := True;
      finally
        ClearDeviceBytes(Serial); FillChar(Buffer[0], Length(Buffer), 0);
        if not Work.Close(Handle) then Work.Partial := True;
      end;
    end;
  finally ClearDeviceBytes(Serial); ClearDeviceBytes(Buffer); FillChar(Query, SizeOf(Query), 0); end;
end;
procedure ReadNics(Work: PDeviceWork; var Signals: TDeviceSignalSet);
var Table: Pointer; Row: PMibRow; Count, I, WipeCount: Cardinal;
  Buffer, Address: TBytes;
begin
  if not Assigned(Work.GetTable) or not Assigned(Work.FreeTable) then
  begin Work.Partial := True; Exit; end;
  Table := nil; WipeCount := 0;
  try
    if Stopped(Work) then Exit;
    if (Work.GetTable(Table) <> NO_ERROR) or (Table = nil) then
    begin Work.Partial := True; Exit; end;
    Count := PMibTable(Table).NumEntries;
    { Bound parsing and wiping of the API allocation; its allocator owns any
      uninspected remainder. Only explicit working copies are guaranteed wiped. }
    WipeCount := Count; if WipeCount > 4096 then WipeCount := 0;
    if Count > MaximumSignalNics then begin Count := MaximumSignalNics; Work.Truncated := True; end;
    SetLength(Buffer, 32);
    if Count > 0 then for I := 0 to Count - 1 do
    begin
      if Stopped(Work) then Exit;
      Row := PMibRow(NativeUInt(Table) + 8 + NativeUInt(I) * SizeOf(TGameMibIfRow2));
      if ((Row.InterfaceAndOperStatusFlags and 1) = 0) or
        ((Row.InterfaceAndOperStatusFlags and 2) <> 0) or
        ((Row.InterfaceType <> 6) and (Row.InterfaceType <> 71)) then Continue;
      Move(Row.PermanentPhysicalAddress, Buffer[0], 32);
      try
        if ParsePermanentAddress(Buffer, Row.PhysicalAddressLength, Address) then
          AddDeviceSignal(Signals, 2, Work.Key, Address)
        else Work.Partial := True;
      finally ClearDeviceBytes(Address); FillChar(Buffer[0], Length(Buffer), 0); end;
    end;
  finally
    ClearDeviceBytes(Address); ClearDeviceBytes(Buffer);
    if Table <> nil then
    begin
      if WipeCount <> 0 then FillChar(PByte(Table)^, 8 + NativeUInt(WipeCount) * SizeOf(TGameMibIfRow2), 0);
      Work.FreeTable(Table);
    end;
  end;
end;
function DeviceWorker(Parameter: Pointer): DWORD; stdcall;
var Work: PDeviceWork; Signals: TDeviceSignalSet;
begin
  Result := 0; Work := PDeviceWork(Parameter); Signals := Default(TDeviceSignalSet);
  try
    try
      ReadDisks(Work, Signals); ReadNics(Work, Signals);
      if not Stopped(Work) then
      begin
        Work.Digest := FinishDeviceSignals(Signals, Work.Key);
        Work.DiskCount := Signals.DiskCount; Work.NicCount := Signals.NicCount;
      end;
    except Work.Partial := True; Work.Digest := ''; Work.DiskCount := 0; Work.NicCount := 0; end;
  finally
    FillChar(Signals, SizeOf(Signals), 0); ClearDeviceBytes(Work.Key);
    { Publish only after all raw input copies are cleaned. Both caller and
      worker own a reference; timeout never frees a live worker's context. }
    Work.Signal(Work.Event);
    ReleaseWork(Work);
  end;
end;
function RunCollection(const Key: TBytes; const Budget: TMeasurementBudget;
  out DiskCount, NicCount: Cardinal; out Digest: string; out Truncated: Boolean): string;
var Work, Previous: PDeviceWork; Thread: THandle; Event: TApiCreateEventW; Create: TApiCreateThread;
  Wait: TApiWaitForSingleObject; Cancel: TCancelSync; WaitResult: DWORD; Completed: Boolean;
begin
  Result := CozyText_DeviceSignals_UNAVAILABLE_6074f82c; DiskCount := 0; NicCount := 0; Digest := ''; Truncated := False;
  if TInterlocked.CompareExchange(Finalizing, 0, 0) <> 0 then begin Truncated := True; Exit; end;
  Work := nil; Previous := nil; Thread := 0; Completed := False; Cancel := nil;
  try
    Event := TApiCreateEventW(DecodeApiPointer(Slot_Event));
    Create := TApiCreateThread(DecodeApiPointer(Slot_Thread));
    Wait := TApiWaitForSingleObject(DecodeApiPointer(Slot_Wait));
    Cancel := TCancelSync(DecodeApiPointer(Slot_Cancel));
    New(Work); Work^ := Default(TDeviceWork); Work.References := 1;
    Work.Close := TApiCloseHandle(DecodeApiPointer(Slot_Close));
    Work.Open := TApiCreateFileW(DecodeApiPointer(Slot_Open));
    Work.Control := TDeviceControl(DecodeApiPointer(Slot_Control));
    Work.Error := TApiGetLastError(DecodeApiPointer(Slot_Error));
    Work.Tick := @CozyTick;
    Work.Signal := TApiSetEvent(DecodeApiPointer(Slot_Signal));
    Work.Wait := Wait; Work.Cancel := Cancel;
    Work.Lock := TLockCall(DecodeApiPointer(Slot_Lock));
    Work.Unlock := TLockCall(DecodeApiPointer(Slot_Unlock));
    if Slot_GetIfTable2.IsBound and Slot_FreeMibTable.IsBound then
    begin
      Work.GetTable := TGetIfTable(DecodeApiPointer(Slot_GetIfTable2));
      Work.FreeTable := TFreeIfTable(DecodeApiPointer(Slot_FreeMibTable));
    end;
    Work.Event := Event(nil, True, False, nil); if Work.Event = 0 then Exit;
    Work.Deadline := Work.Tick(); if Work.Deadline > High(UInt64) - MaximumWaitMilliseconds then Exit;
    Inc(Work.Deadline, MaximumWaitMilliseconds);
    Work.Key := Copy(Key);
    { Admission, thread creation and registry publication share the shutdown
      lock. A worker never reopens admission: only an observed thread EXIT may
      retire the registry, including the worker's managed-code cleanup tail. }
    Work.Lock(@RequestLock);
    try
      if TInterlocked.CompareExchange(Finalizing, 0, 0) <> 0 then
      begin Truncated := True; Exit; end;
      if RegisteredWorker <> nil then
      begin
        if RegisteredWorker.Wait(RegisteredWorker.ThreadHandle, 0) <> WAIT_OBJECT_0 then
        begin Truncated := True; Exit; end;
        Previous := RegisteredWorker; RegisteredWorker := nil;
      end;
      TInterlocked.Increment(Work.References); System.IsMultiThread := True;
      try Thread := Create(nil, 0, DeviceWorker, Work, 0, nil);
      except ReleaseWork(Work); raise; end;
      if Thread = 0 then begin ReleaseWork(Work); Exit; end;
      Work.ThreadHandle := Thread;
      TInterlocked.Increment(Work.References); RegisteredWorker := Work;
    finally Work.Unlock(@RequestLock); end;
    if Previous <> nil then begin ReleaseWork(Previous); Previous := nil; end;
    while True do
    begin
      try Budget.Check(0, 0);
      except on E: EMeasurement do Break; end;
      if Work.Tick() >= Work.Deadline then Break;
      WaitResult := Wait(Work.Event, 25);
      if WaitResult = WAIT_OBJECT_0 then
      begin
        Completed := True;
        DiskCount := Work.DiskCount; NicCount := Work.NicCount;
        Digest := Work.Digest; Truncated := Work.Truncated;
        if DiskCount + NicCount <> 0 then
        begin if Work.Partial or Truncated then Result := CozyText_DeviceSignals_PARTIAL_2dd3823c else Result := CozyText_DeviceSignals_MEASURED_69ee6edd; end;
        Exit;
      end;
      if WaitResult <> WAIT_TIMEOUT then Break;
    end;
    Truncated := True; TInterlocked.Exchange(Work.Stop, 1);
    { Cancel only synchronous I/O issued by this owned worker, never terminate
      it. A driver may ignore cancellation: one bounded worker/context remains
      owned until completion; no subsequent collector is admitted meanwhile. }
  finally
    if Thread <> 0 then
    begin
      if not Completed then
      begin
        TInterlocked.Exchange(Work.Stop, 1);
        if Assigned(Cancel) then Cancel(Thread);
      end;
    end;
    if Work <> nil then ReleaseWork(Work);
    if Previous <> nil then ReleaseWork(Previous);
  end;
end;
function CollectDeviceSignalsJSON(const Budget: TMeasurementBudget): TJSONObject;
var Key: TBytes; Scope, Status, Digest: string; DiskCount, NicCount: Cardinal; Truncated: Boolean;
begin
  Status := CozyText_DeviceSignals_NOT_REQUESTED_748f2d0f; Scope := ''; Digest := ''; DiskCount := 0; NicCount := 0; Truncated := False;
  try
    if TakeRequest(Key, Scope) then
      Status := RunCollection(Key, Budget, DiskCount, NicCount, Digest, Truncated);
  finally ClearDeviceBytes(Key); end;
  Result := TJSONObject.Create;
  try
    Result.AddPair(CozyText_DeviceSignals_version_1972d3a6, TJSONNumber.Create(1)); Result.AddPair(CozyText_DeviceSignals_status_0fb91469, Status);
    Result.AddPair(CozyText_DeviceSignals_scope_ee35fa13, Scope); Result.AddPair(CozyText_DeviceSignals_algorithm_22206de3, CozyText_DeviceSignals_BLAKE3_KEYED_256_5b11b2c0);
    Result.AddPair(CozyText_DeviceSignals_diskCount_49bd1344, TJSONNumber.Create(DiskCount)); Result.AddPair(CozyText_DeviceSignals_nicCount_ce666124, TJSONNumber.Create(NicCount));
    Result.AddPair(CozyText_DeviceSignals_digest_b675bd12, Digest); Result.AddPair(CozyText_DeviceSignals_truncated_3a47e69f, TJSONBool.Create(Truncated));
  except Result.Free; raise; end;
end;
procedure BindOptionalNics;
var Address: Pointer;
begin
  Address := OptionalSystemProcAddressHash64(CozyText_DeviceSignals_iphlpapi_dll_0ae4043e, HASH_GetIfTable2);
  if Address <> nil then BindApiPointer(Slot_GetIfTable2, Address);
  Address := OptionalSystemProcAddressHash64(CozyText_DeviceSignals_iphlpapi_dll_0ae4043e, HASH_FreeMibTable);
  if Address <> nil then BindApiPointer(Slot_FreeMibTable, Address);
end;
initialization
  BindApiPointer(Slot_Lock, RequireProcAddressHash64(CozyText_DeviceSignals_kernel32_dll_1f980235, HASH_AcquireSRWLockExclusive));
  BindApiPointer(Slot_Unlock, RequireProcAddressHash64(CozyText_DeviceSignals_kernel32_dll_1f980235, HASH_ReleaseSRWLockExclusive));
  BindApiPointer(Slot_Open, RequireProcAddressHash64(CozyText_DeviceSignals_kernel32_dll_1f980235, HASH_CreateFileW));
  BindApiPointer(Slot_Control, RequireProcAddressHash64(CozyText_DeviceSignals_kernel32_dll_1f980235, HASH_DeviceIoControl));
  BindApiPointer(Slot_Error, RequireProcAddressHash64(CozyText_DeviceSignals_kernel32_dll_1f980235, HASH_GetLastError));
  BindApiPointer(Slot_Close, RequireProcAddressHash64(CozyText_DeviceSignals_kernel32_dll_1f980235, HASH_CloseHandle));

  BindApiPointer(Slot_Event, RequireProcAddressHash64(CozyText_DeviceSignals_kernel32_dll_1f980235, HASH_CreateEventW));
  BindApiPointer(Slot_Signal, RequireProcAddressHash64(CozyText_DeviceSignals_kernel32_dll_1f980235, HASH_SetEvent));
  BindApiPointer(Slot_Wait, RequireProcAddressHash64(CozyText_DeviceSignals_kernel32_dll_1f980235, HASH_WaitForSingleObject));
  BindApiPointer(Slot_Thread, RequireProcAddressHash64(CozyText_DeviceSignals_kernel32_dll_1f980235, HASH_CreateThread));
  BindApiPointer(Slot_Cancel, RequireProcAddressHash64(CozyText_DeviceSignals_kernel32_dll_1f980235, HASH_CancelSynchronousIo));
  BindApiPointer(Slot_TerminateProcess, RequireProcAddressHash64(CozyText_DeviceSignals_kernel32_dll_1f980235, HASH_TerminateProcess));
  BindOptionalNics;
finalization
  DrainOwnedWorker;
end.
