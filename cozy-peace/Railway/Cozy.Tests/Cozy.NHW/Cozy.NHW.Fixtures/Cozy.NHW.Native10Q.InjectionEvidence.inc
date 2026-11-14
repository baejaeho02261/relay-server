function TestInjectionEvidence10Q(out Failure: string; out Checks: Integer): Boolean;
var
  M: TInjectionEvidenceMonitor; D: TDetectionKinds;
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
      M := TInjectionEvidenceMonitor.Create;
      D := []; M.Examine(True, False, True, 1000, D);
      D := [dkPrivateThread]; M.Examine(True, False, False, 1100, D);
      Check(not (dkInjectionEvidence in D), 'two evidence families insufficient');
      D := [dkPECodeIntegrity]; M.Examine(True, False, False, 1200, D);
      Check(dkInjectionEvidence in D, 'all three observed families still correlate');
      M.ObservationGap; D := [dkPrivateThread, dkPECodeIntegrity];
      M.Examine(True, False, True, 1300, D);
      Check(not (dkInjectionEvidence in D), 'cooldown survives gap');
      M.Reset; D := []; M.Examine(True, False, True, 1000, D);
      D := [dkPrivateThread]; M.Examine(True, False, False, 1100, D);
      D := [dkPECodeIntegrity]; M.Examine(True, False, False, 1200, D, False);
      Check(not (dkInjectionEvidence in D), 'invalid impact observation not correlated');
      D := [dkPECodeIntegrity]; M.Examine(True, False, False, 1300, D);
      Check(not (dkInjectionEvidence in D), 'old thread/access evidence discarded');
      D := [dkPrivateThread]; M.Examine(True, False, True, 1400, D);
      Check(dkInjectionEvidence in D, 'fresh recovery families work');
      M.Reset; D := [dkPrivateThread, dkPECodeIntegrity];
      M.Examine(False, False, True, 1000, D);
      Check(not (dkInjectionEvidence in D), 'external target excluded');
      M.Examine(True, False, False, 1100, D);
      Check(not (dkInjectionEvidence in D), 'external target did not seed access');
      M.Reset; D := []; M.Examine(True, False, True, 1000, D);
      D := [dkPrivateThread, dkPECodeIntegrity]; M.Examine(True, False, False, 1000, D);
      Check(not (dkInjectionEvidence in D), 'duplicate input not processed');
      M.Examine(True, False, False, 900, D);
      Check(not (dkInjectionEvidence in D), 'backward observation rejected');
      M.Examine(True, False, False, 1100, D);
      Check(not (dkInjectionEvidence in D), 'reverse time clears access');
      M.Reset; D := []; M.Examine(True, False, True, 1000, D);
      D := [dkPrivateThread, dkPECodeIntegrity]; M.Examine(True, False, False, 12000, D);
      Check(not (dkInjectionEvidence in D), 'expired evidence not combined');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    M.Free;
  end;
end;
