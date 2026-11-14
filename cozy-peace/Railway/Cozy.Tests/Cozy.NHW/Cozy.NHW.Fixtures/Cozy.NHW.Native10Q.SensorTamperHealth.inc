function TestSensorTamperHealth10Q(out Failure: string; out Checks: Integer): Boolean;
var
  M: TSensorTamperHealth; D: TDetectionKinds;
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
      M := TSensorTamperHealth.Create; D := [];
      M.Observe(True, False, True, True, True, 0, 1000, 1000, 1000, D);
      M.Observe(False, False, True, True, False, 0, 1000, 1000, 2000, D);
      Check(M.FTraceMissingScans = 1, 'first distinct missing trace');
      M.Observe(False, False, True, True, False, 0, 1000, 1000, 2000, D);
      M.Observe(False, False, True, True, False, 0, 1000, 1000, 2000, D);
      Check((M.FTraceMissingScans = 1) and (D = []), 'duplicates not three missing observations');
      M.Observe(False, False, True, True, False, 0, 1000, 1000, 3000, D);
      Check(D = [], 'two observations not confirmed');
      M.Observe(False, False, True, True, False, 0, 1000, 1000, 4000, D);
      Check((dkObservationUncertain in D) and (M.LastReason = shTraceStopped), 'three new observations warn');
      D := []; M.Observe(False, False, True, True, True, 0, 1000, 1000, 5000, D);
      Check((M.FTraceMissingScans = 0) and (M.LastReason = shNone), 'baseline clears old candidates');
      M.Observe(True, False, True, True, False, 0, 1000, 1000, 6000, D);
      M.Observe(False, False, True, False, False, 0, 1000, 1000, 7000, D);
      M.Observe(False, False, True, False, False, 0, 1000, 1000, 6500, D);
      Check((M.FTraceMissingScans = 0) and (M.FThreadMissingScans = 0), 'backwards time breaks confirmations');
      Check(D = [], 'clock boundary not an attack');
      M.Reset; D := [];
      M.Observe(True, False, True, True, False, 0, 1000, 1000, 1000, D);
      M.Observe(True, False, True, False, False, 0, 1000, 1000, 2000, D);
      M.Observe(True, False, True, False, False, 0, 1000, 1000, 40000, D);
      Check((M.FThreadMissingScans = 1) and (D = []), 'large gap starts new missing run');
      M.Observe(True, False, True, False, False, 0, 1000, 1000, 41000, D);
      Check(D = [], 'two new missing observations');
      M.Observe(True, False, True, False, False, 0, 1000, 1000, 42000, D);
      Check((dkObservationUncertain in D) and (M.LastReason = shThreadSnapshotMissing), 'thread snapshots still supervised');
      D := []; M.Observe(True, True, False, True, False, 1, 1000, 1000, 43000, D);
      Check((D = []) and (M.LastReason = shEventLoss), 'different coverage concern keeps warning cooldown');
      M.Observe(True, False, True, False, False, 1, 1000, 1000, 0, D);
      Check(M.FThreadMissingScans = 0, 'zero tick cannot confirm');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    M.Free;
  end;
end;
