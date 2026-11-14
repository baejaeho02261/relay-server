function TestObservationTrust10P(out Failure: string; out Checks: Integer): Boolean;
var
  M: TObservationTrust; K: TDetectionKinds; G: TObservationGrade;
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
      M := TObservationTrust.Create; K := [];
      G := M.Examine(True, True, True, True, False, 1000, 1000, 1000, K);
      Check(G = ogReliable, 'reliable first measured interval');
      M.Examine(True, True, False, True, False, 1000, 1000, 2000, K);
      Check(M.FConsecutiveDegraded = 1, 'first degraded');
      M.Examine(True, True, False, True, False, 1000, 1000, 2000, K);
      Check((M.FConsecutiveDegraded = 1) and (K = []), 'duplicate not a new sample');
      M.Examine(True, True, False, True, False, 1000, 1000, 3000, K);
      M.Examine(True, True, False, True, False, 1000, 1000, 4000, K);
      Check(dkObservationUncertain in K, 'three distinct degraded samples warn');
      K := [];
      M.Examine(True, True, False, True, False, 1000, 1000, 5000, K);
      Check(K = [], 'warning cooldown');
      M.Examine(True, True, True, True, False, 1000, 1000, 6000, K);
      Check(M.FConsecutiveDegraded = 0, 'reliable resets streak');
      G := M.Examine(True, True, True, True, False, 1000, 1000, 30000, K);
      Check((G = ogUnknown) and (M.FConsecutiveDegraded = 0), 'large observed time gap not reliable');
      M.Examine(True, True, False, True, False, 1000, 1000, 31000, K);
      Check(M.FConsecutiveDegraded = 1, 'new sequence after gap');
      G := M.Examine(True, True, True, True, False, 1000, 1000, 31000, K);
      Check((G = ogUnknown) and (M.FConsecutiveDegraded = 0), 'conflicting duplicate breaks streak');
      G := M.Examine(True, True, False, True, False, 1000, 1000, 100, K);
      Check((G = ogUnknown) and not M.FHadReliable, 'clock reversal new epoch');
      M.Examine(True, True, False, True, False, 1000, 1000, 1100, K);
      M.Examine(True, True, False, True, False, 1000, 1000, 2100, K);
      Check((K = []) and (M.FConsecutiveDegraded = 0), 'unknown startup is not an attack');
      Check(GradeObservation(True, True, True, True, False, 100, 0) = ogUnknown, 'invalid configured interval');
      M.Reset; K := [];
      G := M.Examine(True, True, True, True, False, 1000, 1000, 0, K);
      Check(G = ogReliable, 'zero first timestamp');
      M.Examine(True, True, False, True, False, 1000, 1000, 1000, K);
      M.FConsecutiveDegraded := 255;
      M.Examine(True, True, False, True, False, 1000, 1000, 2000, K);
      Check(M.FConsecutiveDegraded = 255, 'byte saturation');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    M.Free;
  end;
end;
