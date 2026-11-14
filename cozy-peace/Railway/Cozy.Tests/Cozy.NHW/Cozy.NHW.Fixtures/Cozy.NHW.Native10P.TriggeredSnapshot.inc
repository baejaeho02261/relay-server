function TestTriggeredSnapshot10P(out Failure: string; out Checks: Integer): Boolean;
var
  M: TTriggeredSnapshot;
  procedure Check(Value: Boolean; const Why: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Why);
  end;
begin
  Result := False;
  Failure := '';
  Checks := 0;
  M := nil;
  try
    try
      M := TTriggeredSnapshot.Create;
      Check(not M.CorroboratedTrigger(True, 1000), 'relevant observation required');
      M.SignalRelevant(1000);
      Check(not M.CorroboratedTrigger(False, 1100), 'independent corroboration required');
      Check(M.CorroboratedTrigger(True, 1100), 'first reservation');
      Check(not M.FHaveGrant, 'reservation is not PSS call');
      M.CompleteAttempt(1100, False);
      Check(not M.CorroboratedTrigger(True, 1200), 'retry throttle');
      Check(M.CorroboratedTrigger(True, 2100), 'skipped request retries before six seconds');
      M.CompleteAttempt(1100, True);
      Check(not M.FHaveGrant, 'stale completion ignored');
      M.CompleteAttempt(2100, True);
      Check(M.FHaveGrant and (M.FLastGrant = 2100), 'actual API attempt acknowledged');
      M.SignalRelevant(7000);
      Check(not M.CorroboratedTrigger(True, 7000), 'real API attempt six-second limit');
      M.SignalRelevant(8000);
      M.SignalRelevant(7500);
      Check(M.FRecentRelevant = 8000, 'late signal does not rewind');
      Check(M.CorroboratedTrigger(True, 8100), 'six-second boundary eligible');
      M.CompleteAttempt(8100, True);
      Check(not M.CorroboratedTrigger(True, 8200), 'real failure would still count as attempt');
      Check(not M.CorroboratedTrigger(True, 10), 'clock reversal clears correlation');
      Check(not M.FHaveRelevant, 'new epoch needs new event');
      M.SignalRelevant(11);
      Check(M.CorroboratedTrigger(True, 11), 'fresh event in new epoch');
      M.CompleteAttempt(11, False);
      Check(not M.CorroboratedTrigger(True, 4000), 'expired relevance cannot trigger');
      M.Reset; M.SignalRelevant(0);
      Check(M.CorroboratedTrigger(True, 0), 'zero tick supported');
      M.CompleteAttempt(0, True);
      Check(not M.CorroboratedTrigger(True, 1), 'zero tick grant throttled');
      M.Reset; M.SignalRelevant(High(UInt64));
      Check(M.CorroboratedTrigger(True, High(UInt64)), 'max tick works without addition');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    M.Free;
  end;
end;
