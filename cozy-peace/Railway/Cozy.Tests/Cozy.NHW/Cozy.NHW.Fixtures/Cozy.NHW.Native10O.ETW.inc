var TestETWRecoveryGate: THandle;

function TestETWRecoveryProcess(Handles: PUInt64; Count: Cardinal;
  StartTime, EndTime: Pointer): Cardinal; stdcall;
begin
  { A bounded test worker substitutes ProcessTrace; no real ETW session or
    another application's collector is started, modified, or stopped. }
  if WaitForSingleObject(TestETWRecoveryGate, 5000) = WAIT_OBJECT_0 then
    Result := ERROR_SUCCESS
  else
    Result := WAIT_TIMEOUT;
end;

function TestETW10O(out Failure: string; out Checks: Integer): Boolean;
var
  G, Other: TETWMonitor;
  Items: TKernelEventList;
  Fast: TFastKernelSampleList;
  Lost: Boolean;
  Item: TKernelEvent;
  Rec: TEtwEventRecord;
  Log: TEtwTraceLogfileW;
  I: Integer;
  SavedProcessTrace: TProcessTrace;
  WorkerBefore: TThread;
  procedure Check(Value: Boolean; const Text: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Text);
  end;

begin
  Result := False; Failure := ''; Checks := 0;
  G := nil; Other := nil; Items := nil; Fast := nil;
  SavedProcessTrace := EtwProcessTrace; TestETWRecoveryGate := 0;
  try
    try
      G := TETWMonitor.Create;
      Other := TETWMonitor.Create;
      Check((G.FSessionName <> '') and (Other.FSessionName <> '') and
        (G.FSessionName <> Other.FSessionName), 'role instances own distinct trace names');
      Check(not CompareMem(@G.FSessionGuid, @Other.FSessionGuid, SizeOf(TGUID)),
        'role instances own distinct trace identifiers');
      Check((G.FSession = 0) and (Other.FSession = 0),
        'construction does not acquire or stop other ETW sessions');
      FreeAndNil(Other);
      Items := TKernelEventList.Create;
      Fast := TFastKernelSampleList.Create;
      G.Drain(Items, Lost); Check(not Lost and (Items.Count = 0), 'empty legacy drain');
      G.DrainFast(Fast, Lost); Check(not Lost and (Fast.Count = 0), 'empty fast drain');
      G.MarkCallbackLoss;
      G.Drain(Items, Lost); Check(Lost, 'callback gap reaches legacy drain');
      G.Drain(Items, Lost); Check(not Lost, 'legacy latch consumed once');
      G.DrainFast(Fast, Lost); Check(Lost, 'legacy cannot consume fast gap latch');
      G.DrainFast(Fast, Lost); Check(not Lost, 'fast latch consumed once');
      Item := Default(TKernelEvent); Item.Kind := keImageLoad; Item.PID := 123; Item.Tick := 1000;
      G.FTestFailEnqueue := True;
      G.Enqueue(Item);
      G.FTestFailEnqueue := False;
      G.Drain(Items, Lost); Check(Lost and (Items.Count = 0), 'queue allocation failure is visible');
      G.DrainFast(Fast, Lost);
      Check(Lost and (Fast.Count = 1) and (Fast[0].Event.PID = 123), 'fast event survives failed legacy enqueue');
      Rec := Default(TEtwEventRecord); Rec.UserContext := G;
      G.FTestFailEvent := True;
      ETWEventCallback(@Rec); G.FTestFailEvent := False;
      G.DrainFast(Fast, Lost); Check(Lost, 'event callback exception creates fast gap');
      G.Drain(Items, Lost); Check(Lost, 'event callback exception creates legacy gap');
      Log := Default(TEtwTraceLogfileW); Log.Context := G;
      G.FTestFailBuffer := True;
      Check(ETWBufferCallback(@Log) = 1, 'buffer callback does not abort session');
      G.FTestFailBuffer := False;
      G.Drain(Items, Lost); Check(Lost, 'buffer callback failure observable');
      G.DrainFast(Fast, Lost); Check(Lost, 'buffer callback fast gap observable');
      G.Enqueue(Item); G.Drain(Items, Lost);
      Check(not Lost and (Items.Count = 1), 'successful legacy enqueue unchanged');
      G.DrainFast(Fast, Lost); Check(not Lost and (Fast.Count = 1), 'successful fast enqueue unchanged');
      for I := 1 to MAX_EVENT_QUEUE do G.FQueue.Enqueue(Item);
      G.Enqueue(Item); G.Drain(Items, Lost);
      Check(Lost and (Items.Count = MAX_EVENT_QUEUE), 'legacy queue overflow remains visible');
      G.DrainFast(Fast, Lost); Check(not Lost and (Fast.Count = 1), 'legacy overflow does not invent fast overflow');
      G.MarkCallbackLoss; G.SetTarget(456);
      G.Drain(Items, Lost); Check(not Lost, 'target switch resets old legacy gap');
      G.DrainFast(Fast, Lost); Check(not Lost, 'target switch resets old fast gap');
      ETWEventCallback(nil); Check(ETWBufferCallback(nil) = 1, 'null callbacks safe');
      Other := TETWMonitor.Create;
      Other.FTestSkipStart := True;
      Check(not Other.TryRecover(0), 'zero recovery clock rejected');
      Check(Other.TryRecover(100) and (Other.FTestStartAttempts = 1), 'unavailable collector performs retry');
      Check(not Other.Ready, 'attempt does not claim recovery success');
      Check(not Other.TryRecover(30099) and (Other.FTestStartAttempts = 1), 'retry backoff enforced');
      Check(Other.TryRecover(30100) and (Other.FTestStartAttempts = 2), 'retry permitted after thirty seconds');
      Check(not Other.TryRecover(1), 'regressed clock cannot bypass backoff');
      Other.FReady := True; Other.MarkCallbackLoss;
      Check(not Other.TryRecover(90000) and (Other.FTestStartAttempts = 2), 'healthy trace not restarted for loss');
      Other.FReady := False;
      TestETWRecoveryGate := CreateEvent(nil, True, False, nil);
      Check(TestETWRecoveryGate <> 0, 'recovery test gate created');
      EtwProcessTrace := TestETWRecoveryProcess;
      Other.FWorker := TETWConsumerThread.Create(11);
      Other.FReady := True; WorkerBefore := Other.FWorker;
      Check(not Other.TryRecover(90100) and (Other.FWorker = WorkerBefore), 'live consumer is never reaped');
      SetEvent(TestETWRecoveryGate);
      Check(WaitForSingleObject(Other.FWorker.Handle, 2000) = WAIT_OBJECT_0, 'test consumer joined with bound');
      Check(Other.TryRecover(90100) and (Other.FWorker = nil) and
        (Other.FTestStartAttempts = 3), 'exited consumer safely reaped before retry');
      Other.Drain(Items, Lost); Check(Lost, 'recovery discontinuity remains visible in legacy path');
      Other.DrainFast(Fast, Lost); Check(Lost, 'recovery discontinuity remains visible in fast path');
      Other.RequestStop;
      Check(not Other.TryRecover(180000) and (Other.FTestStartAttempts = 3), 'shutdown permanently seals recovery');
      FreeAndNil(Other);
      EtwProcessTrace := SavedProcessTrace;
      CloseHandle(TestETWRecoveryGate); TestETWRecoveryGate := 0;
      G.RequestStop;
      G.FTestFailEvent := True; G.FTestFailBuffer := True;
      ETWEventCallback(@Rec);
      Check(ETWBufferCallback(@Log) = 0, 'stopped buffer callback asks ProcessTrace to exit');
      G.Enqueue(Item);
      G.Drain(Items, Lost); Check(not Lost and (Items.Count = 0), 'stop prevents new legacy events');
      G.DrainFast(Fast, Lost); Check(not Lost and (Fast.Count = 0), 'stop prevents new fast events');
      G.TryStart; Check(G.FSession = 0, 'stopped collector cannot restart');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    if TestETWRecoveryGate <> 0 then SetEvent(TestETWRecoveryGate);
    Fast.Free; Items.Free; Other.Free; G.Free;
    EtwProcessTrace := SavedProcessTrace;
    if TestETWRecoveryGate <> 0 then CloseHandle(TestETWRecoveryGate);
    TestETWRecoveryGate := 0;
  end;
end;
