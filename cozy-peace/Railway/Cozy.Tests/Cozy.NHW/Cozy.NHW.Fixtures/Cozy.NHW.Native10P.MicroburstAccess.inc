function TestMicroburstAccess10P(out Failure: string; out Checks: Integer): Boolean;
var
  M: TMicroburstAccess; I, Used: Integer;
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
      M := TMicroburstAccess.Create;
      M.ObserveNewEdge(1, 1, 1000, 11);
      Check(not M.Correlated(1000), 'single actor');
      M.ObserveNewEdge(2, 2, 1001, 22);
      for I := 1 to 1000 do M.ObserveNewEdge(1, 4, UInt64(1001 + I), 11);
      Check(M.Correlated(2001), 'one actor cannot overwrite second actor by flooding');
      Used := 0;
      for I := Low(M.FItems) to High(M.FItems) do
        if M.FItems[I].Used then Inc(Used);
      Check(Used = 2, 'one bounded slot per actor');
      M.ObserveNewEdge(1, 8, 2002, 111);
      Used := 0;
      for I := Low(M.FItems) to High(M.FItems) do
        if M.FItems[I].Used and (M.FItems[I].OwnerPID = 1) then
        begin
          Inc(Used);
          Check(M.FItems[I].OwnerCreated = 111, 'PID reuse replaces old epoch');
          Check(M.FItems[I].Rights = 8, 'old epoch rights not inherited');
        end;
      Check(Used = 1, 'reused PID has one current identity');
      M.ObserveNewEdge(1, 16, 2000, 11);
      Check(M.Correlated(2002), 'late old event cannot rewrite current actor');
      Check(not M.Correlated(1999), 'reverse query excluded');
      Check(not M.Correlated(4003), 'both actors expired');
      M.Reset;
      M.ObserveNewEdge(1, 1, 0, 11);
      M.ObserveNewEdge(2, 2, 0, 22);
      Check(M.Correlated(0), 'zero tick valid');
      Check(M.Correlated(2000), 'window inclusive');
      Check(not M.Correlated(2001), 'window expired');
      M.Reset;
      M.ObserveNewEdge(1, 1, 100); // backward compatible unknown epoch
      M.ObserveNewEdge(2, 2, 100, 22);
      Check(not M.Correlated(100), 'unknown creation cannot support correlation');
      M.ObserveNewEdge(0, 2, 100, 1);
      M.ObserveNewEdge(3, 0, 100, 1);
      Check(not M.Correlated(100), 'invalid PID or rights excluded');
      for I := 1 to 100 do M.ObserveNewEdge(Cardinal(I), 1, UInt64(100 + I), UInt64(I + 1000));
      Used := 0;
      for I := Low(M.FItems) to High(M.FItems) do
        if M.FItems[I].Used then Inc(Used);
      Check(Used = 64, 'capacity bounded');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    M.Free;
  end;
end;
