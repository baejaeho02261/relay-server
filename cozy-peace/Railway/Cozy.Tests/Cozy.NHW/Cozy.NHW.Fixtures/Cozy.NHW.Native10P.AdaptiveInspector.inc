function TestAdaptiveInspector10P(out Failure: string; out Checks: Integer): Boolean;
var
  M: TAdaptiveInspector;
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
      M := TAdaptiveInspector.Create;
      Check(M.ShouldInspect(False, False, 0, 0), 'initial reservation');
      Check(not M.FStates[0].HasSample, 'grant is not execution');
      Check(not M.ShouldInspect(False, False, 0, 0), 'duplicate reservation denied');
      Check(M.ShouldInspect(False, False, 0, 1), 'second sensor independent');
      M.CompleteInspection(0, 0, False);
      M.CompleteInspection(1, 0, True);
      Check(not M.ShouldInspect(False, False, 999, 0), 'bounded retry');
      Check(M.ShouldInspect(False, False, 1000, 0), 'skipped work retried early');
      Check(not M.ShouldInspect(False, False, 1000, 1), 'executed sensor cold cadence');
      M.CompleteInspection(0, 0, True);
      Check(not M.FStates[0].HasSample, 'stale completion rejected');
      M.CompleteInspection(0, 1000, True);
      Check(M.FStates[0].LastSample = 1000, 'actual work acknowledged');
      Check(not M.ShouldInspect(False, False, 2000, 0), 'quiet sensor not due');
      Check(M.ShouldInspect(False, True, 3000, 0), 'hot interval preserved');
      M.CompleteInspection(0, 3000, True);
      Check(not M.ShouldInspect(False, False, 3999, 0), 'hot cooldown');
      Check(M.ShouldInspect(False, False, 5000, 0), 'hot due');
      M.CompleteInspection(0, 5000, False);
      Check(M.ShouldInspect(False, False, 6000, 0), 'failed admission not full cadence');
      M.CompleteInspection(0, 6000, True);
      Check(not M.ShouldInspect(False, False, 25000, -1), 'negative slot rejected');
      Check(not M.ShouldInspect(False, False, 25000, 2), 'large slot rejected');
      Check(M.ShouldInspect(False, False, 10, 0), 'clock epoch reset');
      Check(not M.FStates[1].HasSample, 'other slot reset on clock reversal');
      M.Reset;
      Check(M.ShouldInspect(False, True, High(UInt64) - 1, 0), 'overflow boundary grant');
      Check(M.FHotUntil = High(UInt64), 'hot deadline saturates');
      M.CompleteInspection(0, High(UInt64) - 1, True);
      Check(not M.ShouldInspect(False, False, High(UInt64), 0), 'maximum tick no overflow');
      M.Reset;
      Check(M.ShouldInspect(False, False, 100, 0), 'abandoned reservation');
      Check(M.ShouldInspect(False, False, 1100, 0), 'abandoned work reclaimed after retry');
      M.CompleteInspection(0, 100, True);
      Check(not M.FStates[0].HasSample, 'abandoned token cannot complete');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    M.Free;
  end;
end;
