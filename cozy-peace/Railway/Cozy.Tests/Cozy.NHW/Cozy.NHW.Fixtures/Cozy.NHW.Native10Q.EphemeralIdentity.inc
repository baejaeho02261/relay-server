function TestEphemeralIdentity10Q(out Failure: string; out Checks: Integer): Boolean;
var
  M: TSessionActorIdentity; A, B, C: UInt64; I: Integer;
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
      M := TSessionActorIdentity.Create;
      Check(M.Observe(4, 1, 1000) = 0, 'system PID not aliased');
      Check(M.Observe(500, 0, 1000) = 0, 'unknown creation not identity');
      Check(M.Observe(500, 1, 0) = 0, 'zero observation rejected');
      A := M.Observe(500, 1, 1000); Check(A <> 0, 'session alias allocated');
      Check(M.Observe(500, 1, 2000) = A, 'identity stable');
      Check(M.Observe(500, 1, 1500) = A, 'old event can resolve an existing alias');
      Check(M.FSlots[0].LastTick = 2000, 'old event never rewinds recency');
      Check(M.Observe(501, 2, 1500) = 0, 'old event never inserts new identity');
      Check(M.Existing(501, 2) = 0, 'late event did not mutate cache');
      B := M.Observe(500, 2, 2000); Check((B <> 0) and (B <> A), 'PID reuse has separate alias');
      Check(M.Existing(500, 1) = A, 'old lifetime remains separately addressable');
      for I := 2 to NHW_ALIAS_CAPACITY - 1 do
      begin
        M.FSlots[I].PID := Cardinal(1000 + I);
        M.FSlots[I].Creation := UInt64(1000 + I);
        M.FSlots[I].AliasId := UInt64(100000 + I);
        M.FSlots[I].LastTick := UInt64(3000 + I);
      end;
      M.FLastTick := 4000;
      C := M.Observe(9999, 9999, 5000);
      Check(C <> 0, 'full cache accepts new identity');
      Check(M.Existing(9999, 9999) = C, 'new identity retained');
      Check(M.Existing(500, 1) = 0, 'oldest slot selected on tie');
      Check(M.Existing(500, 2) = B, 'other lifetime not accidentally replaced');
      M.Reset;
      for I := 0 to NHW_ALIAS_CAPACITY - 1 do
      begin
        M.FSlots[I].PID := Cardinal(1000 + I);
        M.FSlots[I].Creation := UInt64(1000 + I);
        M.FSlots[I].AliasId := UInt64(100000 + I);
        M.FSlots[I].LastTick := High(UInt64);
      end;
      M.FLastTick := High(UInt64);
      Check(M.Observe(9999, 9999, High(UInt64)) <> 0, 'all-maximum timestamp still selects bounded victim');
      M.Reset; Check(M.Existing(9999, 9999) = 0, 'session reset erases aliases');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    M.Free;
  end;
end;
