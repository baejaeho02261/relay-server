function TestSignalCorrelation10Q(out Failure: string; out Checks: Integer): Boolean;
var
  M: TSignalCorrelationMonitor; D: TDetectionKinds;
  procedure Check(Value: Boolean; const Why: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Why);
  end;
begin
  Result := False; Failure := ''; Checks := 0;
  M := nil;
  try
    try
      M := TSignalCorrelationMonitor.Create;
      D := []; M.Examine(False, True, 1000, D);
      Check(D = [], 'capability alone not correlation');
      D := [dkPECodeIntegrity]; M.Examine(False, False, 1100, D);
      Check(dkMultiSignal in D, 'independent memory family still correlates');
      M.ObservationGap; D := [dkPECodeIntegrity]; M.Examine(False, True, 1200, D);
      Check(not (dkMultiSignal in D), 'coverage gap does not reset report cooldown');
      M.Reset; D := []; M.Examine(False, True, 1000, D);
      D := [dkPECodeIntegrity]; M.Examine(False, False, 1100, D, False);
      Check(not (dkMultiSignal in D), 'invalid observation never emits derived signal');
      D := [dkPECodeIntegrity]; M.Examine(False, False, 1200, D);
      Check(not (dkMultiSignal in D), 'pre-gap capability is gone');
      M.Examine(False, True, 1300, D);
      Check(dkMultiSignal in D, 'new capability can corroborate recovered memory');
      M.Reset; D := []; M.Examine(False, True, 1000, D);
      D := [dkPrivateThread]; M.Examine(False, False, 1000, D);
      Check(not (dkMultiSignal in D), 'same tick not processed twice');
      M.Examine(False, False, 1100, D); Check(dkMultiSignal in D, 'new valid tick processed');
      M.Reset; D := []; M.Examine(False, True, 1000, D);
      D := [dkPrivateThread]; M.Examine(False, False, 900, D);
      Check(not (dkMultiSignal in D), 'backward clock no signal');
      M.Examine(False, False, 1100, D);
      Check(not (dkMultiSignal in D), 'clock boundary clears old capability');
      M.Reset; D := []; M.Examine(False, True, 1000, D);
      D := [dkPECodeIntegrity]; M.Examine(False, False, 10000, D);
      Check(not (dkMultiSignal in D), 'expired window clears old evidence');
      M.Reset; D := []; M.Examine(False, True, 1000, D);
      M.Examine(True, False, 1100, D); D := [dkPrivateThread];
      M.Examine(False, False, 1200, D); Check(not (dkMultiSignal in D), 'baseline breaks evidence');
      Check(not RecentSignal(2000, 1000, 10000), 'future signal rejected');
      Check(RecentSignal(1000, 9000, 8000), 'window boundary inclusive');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    M.Free;
  end;
end;
