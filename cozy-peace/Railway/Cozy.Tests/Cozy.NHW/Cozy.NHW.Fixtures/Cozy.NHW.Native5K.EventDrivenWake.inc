var
  WakeTestClock: UInt64;
  WakeTestMode: Cardinal;
  WakeTestWaits, WakeTestSleeps: Integer;
  WakeTestStop: LongInt;
  WakeTestStopAfter: Integer;
  WakeTestBackwards: Boolean;
function MockWakeTick5K: UInt64;
begin Result := WakeTestClock; end;
function MockWakeWait5K(Handle: THandle; Timeout: Cardinal): Cardinal;
begin
  Inc(WakeTestWaits);
  if (Timeout = 0) or (Timeout > 50) then raise Exception.Create('unbounded/zero wait chunk');
  if WakeTestWaits > 30 then raise Exception.Create('busy-loop wait regression');
  if WakeTestBackwards then
  begin WakeTestClock := WakeTestClock - 100; WakeTestBackwards := False; end
  else if WakeTestMode = WAIT_TIMEOUT then Inc(WakeTestClock, Timeout);
  Result := WakeTestMode;
end;
procedure MockWakeSleep5K(Timeout: Cardinal);
begin
  if (Timeout = 0) or (Timeout > 50) then raise Exception.Create('unbounded/zero sleep chunk');
  Inc(WakeTestSleeps); Inc(WakeTestClock, Timeout);
  if (WakeTestStopAfter > 0) and (WakeTestSleeps >= WakeTestStopAfter) then
    WakeTestStop := 1;
end;
function TestEventDrivenWake5K(out Failure: string; out Checks: Integer): Boolean;
var P: TEventDrivenWake;
  procedure Check(C: Boolean; const Name: string);
  begin Inc(Checks); if not C then raise Exception.Create(Name); end;
  procedure ResetSimulation;
  begin
    P.Reset; WakeTestClock := 1000; WakeTestMode := WAIT_OBJECT_0;
    WakeTestWaits := 0; WakeTestSleeps := 0; WakeTestStop := 0;
    WakeTestStopAfter := 0; WakeTestBackwards := False;
  end;
begin
  Result := False; Failure := ''; Checks := 0; P := nil;
  Wake5KTick := MockWakeTick5K; Wake5KWait := MockWakeWait5K;
  Wake5KSleep := MockWakeSleep5K;
  try
    try
      P := TEventDrivenWake.Create; ResetSimulation;
      SleepUntilDueOrEvent(500, 123, 1000, P, @WakeTestStop);
      Check(WakeTestClock = 1250, 'signaled event obeys 250ms floor');
      Check((WakeTestWaits = 1) and (WakeTestSleeps = 5), 'one event consumed then timed coalescing');
      Check(P.FLastEarlyWake = 1250, 'early wake timestamp retained');
      SleepUntilDueOrEvent(500, 123, 1250, P, @WakeTestStop);
      Check(WakeTestClock = 1500, 'back-to-back early scans remain separated');
      Check(WakeTestWaits = 2, 'next scan receives its own single wake');
      ResetSimulation; SleepUntilDueOrEvent(100, 123, 1000, P, @WakeTestStop);
      Check(WakeTestClock = 1100, 'ordinary deadline shorter than early floor wins');
      Check(P.FLastEarlyWake = 0, 'ordinary expiry not logged as early wake');
      ResetSimulation; WakeTestMode := WAIT_TIMEOUT;
      SleepUntilDueOrEvent(175, 123, 1000, P, @WakeTestStop);
      Check((WakeTestClock = 1175) and (WakeTestWaits = 4), 'timeout waits cover requested period');
      Check(WakeTestSleeps = 0, 'wait timeouts do not double-sleep');
      ResetSimulation; WakeTestMode := WAIT_FAILED;
      SleepUntilDueOrEvent(175, 123, 1000, P, @WakeTestStop);
      Check((WakeTestClock = 1175) and (WakeTestWaits = 1), 'failed handle attempted once then fallback');
      ResetSimulation; SleepUntilDueOrEvent(175, 123, 1000, nil, @WakeTestStop);
      Check((WakeTestClock = 1175) and (WakeTestWaits = 0), 'nil wake policy cannot spin on signal');
      ResetSimulation; WakeTestStopAfter := 2;
      SleepUntilDueOrEvent(500, 123, 1000, P, @WakeTestStop);
      Check((WakeTestClock = 1100) and (WakeTestWaits = 1), 'stop polled while coalescing');
      ResetSimulation; WakeTestStop := 1;
      SleepUntilDueOrEvent(500, 123, 1000, P, @WakeTestStop);
      Check((WakeTestWaits = 0) and (WakeTestSleeps = 0), 'already stopped exits before any wait');
      ResetSimulation; SleepUntilDueOrEvent(0, 123, 1000, P, nil);
      Check((WakeTestWaits = 0) and (WakeTestClock = 1000), 'zero period is immediate');
      ResetSimulation; SleepUntilDueOrEvent(125, 0, 1000, P, nil);
      Check((WakeTestWaits = 0) and (WakeTestClock = 1125), 'no handle uses bounded sleep');
      ResetSimulation; SleepUntilDueOrEvent(125, INVALID_HANDLE_VALUE, 1000, P, nil);
      Check((WakeTestWaits = 0) and (WakeTestClock = 1125), 'invalid sentinel never passed to wait');
      ResetSimulation; WakeTestClock := 1234;
      SleepUntilDueOrEvent(500, 123, 1000, P, nil);
      Check((WakeTestClock = 1250) and (WakeTestSleeps = 1), 'last coalesced delay shortened to allowed boundary');
      ResetSimulation; WakeTestBackwards := True;
      SleepUntilDueOrEvent(500, 123, 1000, P, nil);
      Check(WakeTestClock = 900, 'clock discontinuity exits without underflow');
      ResetSimulation; WakeTestClock := High(UInt64) - 500;
      SleepUntilDueOrEvent(100, 0, WakeTestClock, P, nil);
      Check(WakeTestClock = High(UInt64) - 400, 'near-max ticks use subtraction safely');
      ResetSimulation;
      Check(P.DelayBeforeWake(1000, 1000) = 250, 'initial wake delay');
      Check(P.DelayBeforeWake(1000, 1249) = 1, 'boundary wake delay');
      Check(not P.MayWake(1000, 1249), 'before boundary rejected');
      Check(P.MayWake(1000, 1250), 'boundary accepted');
      Check(not P.MayWake(1000, 1250), 'same early wake not repeated');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    P.Free; Wake5KTick := nil; Wake5KWait := nil; Wake5KSleep := nil;
  end;
end;
