function TestRegistry10M(out Failure: string; out Checks: Integer): Boolean;
var W: TRegistryWatch; E: TRegistryEvidence; D: TDetectionKinds; I: Integer;
  procedure Check(Condition: Boolean; const Msg: string);
  begin
    Inc(Checks);
    if not Condition then raise Exception.Create(Msg);
  end;
begin
  Result := False; Failure := ''; Checks := 0;
  W := nil;
  try
    try
      W := TRegistryWatch.Create('test-only', False); D := [];
      E := Default(TRegistryEvidence);
      for I := 1 to 6 do W.ApplyEvidence(E, False, D);
      Check((W.FValuesPrime = 3) and (W.FKeysPrime = 3) and (W.FDaclPrime = 3), 'failed queries do not consume warmup');
      Check(D = [], 'unknown does not alert');
      E.ValuesKnown := True;
      for I := 1 to 3 do
      begin E.ValuesHash := UInt64(I); W.ApplyEvidence(E, False, D); end;
      Check((W.FValuesPrime = 0) and (W.FKeysPrime = 3) and (W.FDaclPrime = 3), 'channels prime independently');
      Check((D = []) and (W.FPrimeRemaining = 0), 'valid channel becomes ready silently');
      E.ValuesHash := 4; W.ApplyEvidence(E, False, D);
      Check(dkRegistryValue in D, 'ready values can alert despite inaccessible DACL');
      E := Default(TRegistryEvidence); D := []; W.ApplyEvidence(E, False, D);
      Check((W.FState.FValuesHash = 4) and W.FState.FValuesKnown, 'unknown preserves last successful channel');
      E.KeysKnown := True; E.KeysHash := 10;
      W.ApplyEvidence(E, False, D);
      Check(W.FKeysPrime = 2, 'first key observation consumes one success');
      E.KeysKnown := False; W.ApplyEvidence(E, False, D);
      Check(W.FKeysPrime = 2, 'key failure does not consume a success');
      E.KeysKnown := True; E.KeysHash := 11; W.ApplyEvidence(E, False, D);
      E.KeysHash := 12; W.ApplyEvidence(E, False, D);
      Check((W.FKeysPrime = 0) and (D = []), 'third valid key observation ends warmup');
      E.KeysHash := 13; W.ApplyEvidence(E, False, D);
      Check(dkRegistryKey in D, 'key detection unchanged after own warmup');
      W.Reset; E := Default(TRegistryEvidence); E.DaclKnown := True; D := [];
      for I := 1 to 3 do begin E.DaclHash := UInt64(I); W.ApplyEvidence(E, False, D); end;
      E.DaclHash := 9; W.ApplyEvidence(E, False, D);
      Check(dkRegistrySecurity in D, 'DACL has independent warmup and detection');
      Check((W.FValuesPrime = 3) and (W.FKeysPrime = 3), 'DACL success cannot prime other channels');
      W.Reset;
      Check((W.FPrimeAttempts = 0) and (W.FPrimeRemaining = 3), 'reopen/reset restores warmups');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    W.Free;
  end;
end;
