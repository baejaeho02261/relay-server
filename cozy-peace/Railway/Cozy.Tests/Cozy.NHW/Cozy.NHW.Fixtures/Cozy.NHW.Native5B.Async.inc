var
  TestAsyncMode, TestAsyncWaits, TestAsyncCloses, TestAsyncOrder: Integer;

function TestAsyncGet(Port: THandle; out Bytes: Cardinal;
  out Key: NativeUInt; out Overlapped: Pointer; Timeout: Cardinal): BOOL; stdcall;
begin
  Bytes := 77; Key := 88; Overlapped := nil;
  Result := TestAsyncMode = 0;
  if TestAsyncMode = 2 then Overlapped := Pointer(NativeUInt($12340));
end;
procedure TestAsyncWait(Work: Pointer; CancelPending: BOOL); stdcall;
begin
  Inc(TestAsyncWaits);
end;
procedure TestAsyncClose(Work: Pointer); stdcall;
begin
  if TestAsyncWaits = 0 then raise Exception.Create('close before wait');
  Inc(TestAsyncCloses);
end;
procedure TestAsyncSetTimer(Timer, DueTime: Pointer;
  PeriodMS, WindowMS: Cardinal); stdcall;
begin
  if DueTime <> nil then raise Exception.Create('timer not disarmed');
  TestAsyncOrder := TestAsyncOrder * 10 + 1;
end;
procedure TestAsyncWaitTimer(Timer: Pointer; CancelPending: BOOL); stdcall;
begin
  TestAsyncOrder := TestAsyncOrder * 10 + 2;
end;
procedure TestAsyncCloseTimer(Timer: Pointer); stdcall;
begin
  TestAsyncOrder := TestAsyncOrder * 10 + 3;
end;
function TestAsyncNativeHardening(out Failure: string; out Checks: Integer): Boolean;
var
  SavedResolved: Integer;
  SavedGet: TGetCompletion;
  SavedWait: TWaitPoolWork;
  SavedClose: TClosePoolWork;
  SavedSetTimer: TSetPoolTimer;
  SavedWaitTimer: TWaitPoolTimer;
  SavedCloseTimer: TClosePoolTimer;
  Bytes: Cardinal;
  Key: NativeUInt;
  O: Pointer;
  procedure Check(V: Boolean; const Name: string);
  begin
    Inc(Checks);
    if not V then raise Exception.Create(Name);
  end;
begin
  Result := False; Failure := ''; Checks := 0;
  SavedResolved := AsyncResolved; SavedGet := GetPtr;
  SavedWait := WaitWorkPtr; SavedClose := CloseWorkPtr;
  SavedSetTimer := SetTimerPtr; SavedWaitTimer := WaitTimerPtr;
  SavedCloseTimer := CloseTimerPtr;
  try
    try
      AsyncResolved := 1; GetPtr := TestAsyncGet;
      TestAsyncMode := 0;
      Check(PollCompletionPacket(1, Bytes, Key, O), 'success packet');
      Check((Bytes = 77) and (Key = 88) and (O = nil), 'success payload');
      TestAsyncMode := 1;
      Check(not PollCompletionPacket(1, Bytes, Key, O), 'no packet failure');
      Check((Bytes = 0) and (Key = 0) and (O = nil), 'undefined values discarded');
      TestAsyncMode := 2;
      Check(not PollCompletionPacket(1, Bytes, Key, O), 'failed I/O status retained');
      Check((Bytes = 77) and (Key = 88) and (O <> nil), 'failed I/O payload retained');
      Check(not PollCompletionPacket(0, Bytes, Key, O), 'zero port rejected');
      Check((Bytes = 0) and (Key = 0) and (O = nil), 'zero port output reset');
      Check(not PollCompletionPacket(INVALID_HANDLE_VALUE, Bytes, Key, O), 'invalid port rejected');
      Check(not PostCompletionPacket(0, 1, 1), 'zero post rejected');
      Check(not PostCompletionPacket(INVALID_HANDLE_VALUE, 1, 1), 'invalid post rejected');
      Check(NewPoolWork(nil, nil) = nil, 'nil work callback rejected');
      Check(NewPoolTimer(nil, nil) = nil, 'nil timer callback rejected');
      TestAsyncWaits := 0; TestAsyncCloses := 0;
      WaitWorkPtr := TestAsyncWait; CloseWorkPtr := TestAsyncClose;
      StopPoolWork(Pointer(NativeUInt(1)));
      Check((TestAsyncWaits = 1) and (TestAsyncCloses = 1), 'wait before work close');
      WaitWorkPtr := nil;
      StopPoolWork(Pointer(NativeUInt(1)));
      Check(TestAsyncCloses = 1, 'never close work without drain API');
      SetTimerPtr := TestAsyncSetTimer; WaitTimerPtr := TestAsyncWaitTimer;
      CloseTimerPtr := TestAsyncCloseTimer; TestAsyncOrder := 0;
      StopPoolTimer(Pointer(NativeUInt(1)));
      Check(TestAsyncOrder = 123, 'disarm-drain-close order');
      WaitTimerPtr := nil; TestAsyncOrder := 0;
      StopPoolTimer(Pointer(NativeUInt(1)));
      Check(TestAsyncOrder = 0, 'incomplete timer shutdown API rejected');
      StopPoolTimer(nil); StopPoolWork(nil);
      Check(TestAsyncOrder = 0, 'nil shutdown no-op');
      GetPtr := nil;
      Check(not PollCompletionPacket(1, Bytes, Key, O), 'unsupported poll rejected');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    AsyncResolved := SavedResolved; GetPtr := SavedGet;
    WaitWorkPtr := SavedWait; CloseWorkPtr := SavedClose;
    SetTimerPtr := SavedSetTimer; WaitTimerPtr := SavedWaitTimer;
    CloseTimerPtr := SavedCloseTimer;
  end;
end;
