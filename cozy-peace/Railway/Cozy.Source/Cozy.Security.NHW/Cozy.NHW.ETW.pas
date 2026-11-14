unit Cozy.NHW.ETW;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes,
  System.SyncObjs,
  System.Generics.Collections,
  Cozy.NHW.ETWTypes,
  Cozy.NHW.ETWNative,
  Cozy.NHW.FastEventRing;

type
  // Optional ETW observer. Does not write event data to disk, inject or
  // interact with other trace sessions. Failure leaves v18 monitoring alive.
  TETWMonitor = class
  private
    FGuard: TCriticalSection;
    FQueue: TQueue<TKernelEvent>;
    FFastRing: TFastEventRing;
    FNotifyEvent: THandle;
    FLastFastLoss: Cardinal;
    FOverflow: Boolean;
    FCallbackLoss: LongInt;
    FStopping: LongInt;
    FFastCallbackLoss: LongInt;
{$IFDEF NHW_NATIVE10O_TESTS}
    FTestFailEnqueue: Boolean;
    FTestFailEvent: Boolean;
    FTestFailBuffer: Boolean;
    FTestSkipStart: Boolean;
    FTestStartAttempts: Cardinal;
{$ENDIF}
    FLogger: TEtwTraceLogfileW;
    FTraceProps: TBytes;
    FSession: UInt64;
    FSessionName: string;
    FSessionGuid: TGUID;
    FConsumer: UInt64;
    FWorker: TThread;
    FReady: Boolean;
    FLastLost: UInt64;
    FLastRecoveryTick: UInt64;
    FRecoveryAttempted: Boolean;
    FHasLossBaseline: Boolean;
    FTargetPID: LongInt;
    FExeSuffix: string;
    FUserRegistryPath: string;
    procedure TryStartAt(Tick: UInt64);
    function RetireStoppedCollector: Boolean;
    procedure MarkCallbackLoss;
    procedure OnEvent(Rec: PEtwEventRecord);
    procedure OnBuffer(Log: PEtwTraceLogfileW);
    procedure Enqueue(const E: TKernelEvent);
  public
    constructor Create;
    destructor Destroy; override;
    procedure TryStart;
    { Called only by the NHW sensor worker. Returns True when a start retry
      was attempted, not a claim that ETW recovered or evidence was verified. }
    function TryRecover(Tick: UInt64): Boolean;
    procedure RequestStop;
    function Stopping: Boolean;
    procedure SetTarget(PID: Cardinal);
    procedure Drain(List: TKernelEventList; out LostEvents: Boolean);
    procedure DrainFast(List: TFastKernelSampleList;
      out LostEvents: Boolean);
    function WakeHandle: THandle;
    function FastDropTotal: Cardinal;
    procedure GetCallbackTargets(out RecordCallback, BufferCallback: NativeUInt);
    function ConsumerThreadID: Cardinal;
    function QueryLossCounters(out EventsLost, LogLost,
      RealTimeLost: Cardinal): Boolean;
    property Ready: Boolean read FReady;
  end;

{$IFDEF NHW_NATIVE10O_TESTS}
function TestETW10O(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  Cozy.NHW.WinPointers,
  Cozy.NHW.RegistryNative,
  Cozy.NHW.HighResolutionClock,
  Cozy.NHW.ETW.Consumer, Cozy.NHW.ETW.Decoder;

const
  MAX_EVENT_QUEUE = 4096;
  ETW_RECOVERY_BACKOFF_MS = 30000;
  ETW_ERROR_MORE_DATA = 234;
  ETW_ERROR_INSTANCE_NOT_FOUND = 4201;
  ETW_ERROR_CLOSE_PENDING = 7007;

procedure TETWMonitor.GetCallbackTargets(out RecordCallback, BufferCallback: NativeUInt);
begin
  // Pointers in the live registration record, not OS callback-ownership proof.
  RecordCallback := 0;
  BufferCallback := 0;
  if not FReady then Exit;
  RecordCallback := NativeUInt(FLogger.EventRecordCallback);
  BufferCallback := NativeUInt(FLogger.BufferCallback);
end;

function TETWMonitor.ConsumerThreadID: Cardinal;
begin
  Result := 0;
  if FWorker <> nil then Result := FWorker.ThreadID;
end;

procedure ETWEventCallback(Rec: PEtwEventRecord); stdcall;
begin
  if (Rec = nil) or (Rec^.UserContext = nil) then Exit;
  if TETWMonitor(Rec^.UserContext).Stopping then Exit;
  try
    TETWMonitor(Rec^.UserContext).OnEvent(Rec);
  except
    TETWMonitor(Rec^.UserContext).MarkCallbackLoss;
  end;
end;

function ETWBufferCallback(Log: PEtwTraceLogfileW): Cardinal; stdcall;
begin
  Result := 1;
  if (Log = nil) or (Log^.Context = nil) then Exit;
  if TETWMonitor(Log^.Context).Stopping then Exit(0);
  try
    TETWMonitor(Log^.Context).OnBuffer(Log);
  except
    TETWMonitor(Log^.Context).MarkCallbackLoss;
  end;
end;

constructor TETWMonitor.Create;
var
  Parent, FileName: string;
begin
  inherited Create;
  // Initialize before allocations; the destructor also handles constructor failure.
  FConsumer := ETW_INVALID_HANDLE;
  FCallbackLoss := 0;
  FFastCallbackLoss := 0;
  FGuard := TCriticalSection.Create;
  FQueue := TQueue<TKernelEvent>.Create;
  FFastRing := TFastEventRing.Create;
  FNotifyEvent := CreateEvent(nil, False, False, nil);
  FLastFastLoss := 0;
  FSession := 0;
  if CreateGUID(FSessionGuid) = 0 then
    FSessionName := 'Cozy.NHW.' + IntToHex(WinCurrentProcessId, 8) + '.' +
      GUIDToString(FSessionGuid);
  FConsumer := ETW_INVALID_HANDLE;
  FWorker := nil;
  FReady := False;
  FLastLost := 0;
  FLastRecoveryTick := 0;
  FRecoveryAttempted := False;
  FHasLossBaseline := False;
  FTargetPID := 0;
  FileName := ExpandFileName(ParamStr(0));
  Parent := ExtractFileName(ExtractFileDir(FileName));
  if Parent <> '' then
    FExeSuffix := NormalPath('\' + Parent + '\' + ExtractFileName(FileName))
  else
    FExeSuffix := '';
  FUserRegistryPath := '';
  try
    FUserRegistryPath := NormalPath(NativeCurrentUserRegistryRoot);
  except
  end;
end;

procedure TETWMonitor.RequestStop;
begin
  { Seal callback admission before asking Windows to drain its owned trace.
    Existing callbacks retain their owner until ProcessTrace has joined. }
  TInterlocked.Exchange(FStopping, 1);
  if FNotifyEvent <> 0 then SetEvent(FNotifyEvent);
end;

function TETWMonitor.Stopping: Boolean;
begin
  Result := TInterlocked.CompareExchange(FStopping, 0, 0) <> 0;
end;

function TETWMonitor.RetireStoppedCollector: Boolean;
var Err: Cardinal;
begin
  Result := False;
  { Never stop a healthy consumer to recover a transient dropped-event count.
    ProcessingStopped alone precedes RTL thread teardown, so also require a
    zero-time kernel wait before freeing any callback owner or logger record. }
  if FWorker <> nil then
  begin
    if not TETWConsumerThread(FWorker).ProcessingStopped then Exit;
    if WaitForSingleObject(FWorker.Handle, 0) <> WAIT_OBJECT_0 then Exit;
  end;
  if FConsumer <> ETW_INVALID_HANDLE then
  begin
    if not Assigned(EtwCloseTrace) then Exit;
    Err := EtwCloseTrace(FConsumer);
    if (Err <> ERROR_SUCCESS) and (Err <> ERROR_INVALID_HANDLE) and
      (Err <> ETW_ERROR_CLOSE_PENDING) then Exit;
    FConsumer := ETW_INVALID_HANDLE;
  end;
  if FSession <> 0 then
  begin
    if not Assigned(EtwControlTrace) or
      (Length(FTraceProps) < SizeOf(TEtwTraceProperties)) then Exit;
    Err := EtwControlTrace(FSession, nil,
      PEtwTraceProperties(@FTraceProps[0]), ETW_TRACE_CONTROL_STOP);
    { ERROR_MORE_DATA still means STOP succeeded; NOT_FOUND means the owned
      session is already gone. Other failures retain ownership for a retry. }
    if (Err <> ERROR_SUCCESS) and (Err <> ETW_ERROR_MORE_DATA) and
      (Err <> ETW_ERROR_INSTANCE_NOT_FOUND) then Exit;
    FSession := 0;
  end;
  FreeAndNil(FWorker);
  FLogger := Default(TEtwTraceLogfileW);
  FTraceProps := nil;
  FGuard.Acquire;
  try
    FLastLost := 0;
    FHasLossBaseline := False;
  finally FGuard.Release; end;
  Result := True;
end;

function TETWMonitor.TryRecover(Tick: UInt64): Boolean;
begin
  Result := False;
  if Stopping or (Tick = 0) then Exit;
  if FWorker <> nil then
  begin
    if not TETWConsumerThread(FWorker).ProcessingStopped then Exit;
    if WaitForSingleObject(FWorker.Handle, 0) <> WAIT_OBJECT_0 then Exit;
    FReady := False;
  end
  else if FReady then Exit;
  if FRecoveryAttempted then
    if (Tick < FLastRecoveryTick) or
      (Tick - FLastRecoveryTick < ETW_RECOVERY_BACKOFF_MS) then Exit;
  FLastRecoveryTick := Tick;
  FRecoveryAttempted := True;
  try
    if not RetireStoppedCollector or Stopping then Exit;
    { Preserve the discontinuity in both independent queues. Clearing a loss
      latch to appear healthy would turn recovery into a false attestation. }
    MarkCallbackLoss;
    TryStartAt(Tick);
    Result := True;
  except
    MarkCallbackLoss;
  end;
end;

procedure TETWMonitor.TryStart;
begin
  TryStartAt(WinTick64);
end;

procedure TETWMonitor.TryStartAt(Tick: UInt64);
var
  Props: PEtwTraceProperties;
  Err: Cardinal;
begin
  if Stopping or FReady or (FWorker <> nil) or (FSession <> 0) or
    (FConsumer <> ETW_INVALID_HANDLE) then Exit;
  FLastRecoveryTick := Tick;
  FRecoveryAttempted := True;
{$IFDEF NHW_NATIVE10O_TESTS}
  Inc(FTestStartAttempts);
  if FTestSkipStart then Exit;
{$ENDIF}
  if FSessionName = '' then
    if CreateGUID(FSessionGuid) = 0 then
      FSessionName := 'Cozy.NHW.' + IntToHex(WinCurrentProcessId, 8) + '.' +
        GUIDToString(FSessionGuid);
  if (FSessionName = '') or not ResolveETW then Exit;
  SetLength(FTraceProps, SizeOf(TEtwTraceProperties) + 256 * SizeOf(WideChar));
  FillChar(FTraceProps[0], Length(FTraceProps), 0);
  Props := PEtwTraceProperties(@FTraceProps[0]);
  Props^.Wnode.BufferSize := Cardinal(Length(FTraceProps));
  Props^.Wnode.Guid := FSessionGuid;
  Props^.Wnode.ClientContext := 2; // ETW system-clock timestamp
  Props^.Wnode.Flags := ETW_WNODE_TRACED_GUID;
  Props^.BufferSize := 64; // 64KB ETW buffer; no disk output.
  Props^.MinimumBuffers := 0;
  Props^.MaximumBuffers := 32;
  Props^.FlushTimer := 1;
  Props^.LogFileMode := ETW_REAL_TIME_MODE or ETW_SYSTEM_LOGGER_MODE;
  Props^.EnableFlags := ETW_PROCESS_FLAG or ETW_THREAD_FLAG or
    ETW_IMAGE_LOAD_FLAG or ETW_FILE_IO_FLAG or
    ETW_FILE_IO_INIT_FLAG or ETW_REGISTRY_FLAG;
  Props^.LoggerNameOffset := SizeOf(TEtwTraceProperties);
  Props^.LogFileNameOffset := 0;
  FSession := 0;
  Err := EtwStartTrace(FSession, PWideChar(FSessionName), Props);
  if Err <> 0 then
  begin
    FSession := 0;
    Exit;
  end;
  if Stopping then
  begin
    RetireStoppedCollector;
    Exit;
  end;
  FLogger := Default(TEtwTraceLogfileW);
  FLogger.LoggerName := PWideChar(FSessionName);
  FLogger.ProcessTraceMode := ETW_REAL_TIME_MODE or ETW_RECORD_MODE;
  FLogger.EventRecordCallback := @ETWEventCallback;
  FLogger.BufferCallback := @ETWBufferCallback;
  FLogger.Context := Self;
  FConsumer := EtwOpenTrace(@FLogger);
  if FConsumer = ETW_INVALID_HANDLE then
  begin
    RetireStoppedCollector;
    Exit;
  end;
  if Stopping then
  begin
    RetireStoppedCollector;
    Exit;
  end;
  try
    FWorker := TETWConsumerThread.Create(FConsumer);
    FReady := True;
  except
    RetireStoppedCollector;
  end;
end;

procedure TETWMonitor.SetTarget(PID: Cardinal);
begin
  TInterlocked.Exchange(FTargetPID, LongInt(PID));
  FGuard.Acquire;
  try
    FQueue.Clear;
    FOverflow := False;
    TInterlocked.Exchange(FCallbackLoss, 0);
    TInterlocked.Exchange(FFastCallbackLoss, 0);
    FLastFastLoss := FFastRing.DroppedTotal;
  finally
    FGuard.Release;
  end;
end;

procedure TETWMonitor.MarkCallbackLoss;
begin
  // Sticky latches, not exact loss counts. No allocation or queue lock here:
  // this path must remain usable after a callback-side allocation failure.
  // Independent latches ensure Drain cannot hide the gap from DrainFast.
  TInterlocked.Exchange(FCallbackLoss, 1);
  TInterlocked.Exchange(FFastCallbackLoss, 1);
  if FNotifyEvent <> 0 then SetEvent(FNotifyEvent);
end;

procedure TETWMonitor.Enqueue(const E: TKernelEvent);
begin
  if Stopping then Exit;
  try
    FGuard.Acquire;
    try
{$IFDEF NHW_NATIVE10O_TESTS}
      if FTestFailEnqueue then raise EOutOfMemory.Create('test enqueue failure');
{$ENDIF}
      if FQueue.Count >= MAX_EVENT_QUEUE then FOverflow := True
      else FQueue.Enqueue(E);
    finally
      FGuard.Release;
    end;
  except
    // Preserve the independent fast path even if the legacy queue failed.
    MarkCallbackLoss;
  end;
  FFastRing.Push(E, NHWQpcNow);
  if FNotifyEvent <> 0 then SetEvent(FNotifyEvent);
end;

procedure TETWMonitor.OnBuffer(Log: PEtwTraceLogfileW);
var
  Lost: UInt64;
begin
{$IFDEF NHW_NATIVE10O_TESTS}
  if FTestFailBuffer then raise Exception.Create('test buffer callback failure');
{$ENDIF}
  Lost := UInt64(Log^.LogfileHeader.LogInstanceCounters[2]) +
    UInt64(Log^.LogfileHeader.BuffersLost);
  FGuard.Acquire;
  try
    if not FHasLossBaseline then
    begin
      FLastLost := Lost;
      FHasLossBaseline := True;
    end
    else if Lost > FLastLost then
    begin
      FOverflow := True;
      FLastLost := Lost;
    end;
  finally
    FGuard.Release;
  end;
end;

procedure TETWMonitor.OnEvent(Rec: PEtwEventRecord);
var
  E: TKernelEvent;
  TargetPID: Cardinal;
begin
{$IFDEF NHW_NATIVE10O_TESTS}
  if FTestFailEvent then raise Exception.Create('test event callback failure');
{$ENDIF}
  TargetPID := Cardinal(TInterlocked.CompareExchange(FTargetPID, 0, 0));
  if TryDecodeKernelEvent(Rec, TargetPID, FExeSuffix, FUserRegistryPath, E) then
    Enqueue(E);
end;

function TETWMonitor.QueryLossCounters(out EventsLost, LogLost,
  RealTimeLost: Cardinal): Boolean;
var
  CopyProps: TBytes;
  P: PEtwTraceProperties;
  H: UInt64;
begin
  EventsLost := 0;
  LogLost := 0;
  RealTimeLost := 0;
  Result := False;
  if (FSession = 0) or (not FReady) or
     not Assigned(EtwControlTrace) or
     (Length(FTraceProps) < SizeOf(TEtwTraceProperties)) then Exit;
  // Query ONLY the session owned by this instance. Never query or stop
  // unrelated sessions and never overwrite the original stop properties.
  CopyProps := Copy(FTraceProps, 0, Length(FTraceProps));
  P := PEtwTraceProperties(@CopyProps[0]);
  H := FSession;
  if EtwControlTrace(H, nil, P, ETW_TRACE_CONTROL_QUERY) <> 0 then Exit;
  EventsLost := P^.EventsLost;
  LogLost := P^.LogBuffersLost;
  RealTimeLost := P^.RealTimeBuffersLost;
  Result := True;
end;

function TETWMonitor.WakeHandle: THandle;
begin
  Result := FNotifyEvent;
end;

function TETWMonitor.FastDropTotal: Cardinal;
begin
  Result := FFastRing.DroppedTotal;
end;

procedure TETWMonitor.DrainFast(List: TFastKernelSampleList;
  out LostEvents: Boolean);
var
  Item: TFastKernelSample;
  Dropped: Cardinal;
begin
  LostEvents := False;
  if List = nil then raise EArgumentNilException.Create('List');
  List.Clear;
  try
    while (List.Count < NHW_FAST_RING_CAPACITY - 1) and
          FFastRing.Pop(Item) do List.Add(Item);
    Dropped := FFastRing.DroppedTotal;
    LostEvents := Dropped <> FLastFastLoss;
    // Numeric total is bounded; the independent latch still reports new loss.
    if FFastRing.ConsumeLoss then LostEvents := True;
    if TInterlocked.Exchange(FFastCallbackLoss, 0) <> 0 then LostEvents := True;
    FLastFastLoss := Dropped;
  except
    List.Clear;
    LostEvents := True;
    MarkCallbackLoss;
    raise;
  end;
end;

procedure TETWMonitor.Drain(List: TKernelEventList; out LostEvents: Boolean);
begin
  LostEvents := False;
  if List = nil then raise EArgumentNilException.Create('List');
  List.Clear;
  FGuard.Acquire;
  try
    try
      while FQueue.Count > 0 do
      begin
        // Add may allocate: leave the item in the queue if it fails.
        List.Add(FQueue.Peek);
        FQueue.Dequeue;
      end;
      LostEvents := FOverflow;
      FOverflow := False;
      if TInterlocked.Exchange(FCallbackLoss, 0) <> 0 then LostEvents := True;
      if FReady and (FWorker <> nil) and
         TETWConsumerThread(FWorker).ProcessingStopped then
      begin
        LostEvents := True;
        FReady := False;
      end;
    except
      List.Clear;
      FOverflow := True;
      LostEvents := True;
      MarkCallbackLoss;
      raise;
    end;
  finally
    FGuard.Release;
  end;
end;

destructor TETWMonitor.Destroy;
begin
  RequestStop;
  // Stop ONLY the session this instance created. Never stop or reconfigure an
  // unrelated ETW session on failures or name collisions.
  if FSession <> 0 then
  begin
    try
      EtwControlTrace(FSession, nil,
        PEtwTraceProperties(@FTraceProps[0]), ETW_TRACE_CONTROL_STOP);
    except
    end;
    FSession := 0;
  end;
  // CloseTrace on a running real-time consumer requests a clean shutdown;
  // Windows returns ERROR_CTX_CLOSE_PENDING while ProcessTrace drains buffers.
  if FConsumer <> ETW_INVALID_HANDLE then
  begin
    try
      EtwCloseTrace(FConsumer);
    except
    end;
    FConsumer := ETW_INVALID_HANDLE;
  end;
  if FWorker <> nil then
  begin
    try
      FWorker.WaitFor;
    except
    end;
    FWorker.Free;
  end;
  if FNotifyEvent <> 0 then CloseHandle(FNotifyEvent);
  FFastRing.Free;
  FQueue.Free;
  FGuard.Free;
  inherited Destroy;
end;

{$IFDEF NHW_NATIVE10O_TESTS}
  {$I Cozy.NHW.Native10O.ETW.inc}
{$ENDIF}

end.
