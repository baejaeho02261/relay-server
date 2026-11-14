function TestWaitChain5K(out Failure: string; out Checks: Integer): Boolean;
var M: TWaitChainMonitor; I, Steps: Integer; Raised: Boolean;
  procedure Check(Condition: Boolean; const Name: string);
  begin Inc(Checks); if not Condition then raise Exception.Create(Name); end;
begin
  Result := False; Failure := ''; Checks := 0;
  try
    Wait5KStep := 0; Wait5KFailAt := 0;
    Wait5KAllocated := 0; Wait5KDisposed := 0;
    M := TWaitChainMonitor.Create;
    try
      Steps := Wait5KStep;
      Check(M.FPool.Count = MAX_OUTSTANDING, 'full pool constructed');
      Check(M.FSession = 0, 'constructor opens no WCT session');
      Check(Wait5KAllocated = MAX_OUTSTANDING, 'owned buffers allocated');
      M.StopSession; M.StopSession;
      Check(M.FRequests.Count = 0, 'idempotent stop clears requests');
    finally M.Free; end;
    Check(Wait5KAllocated = Wait5KDisposed, 'normal destruction returns every buffer');
    // Every construction boundary is fault injected. This includes failure
    // before FGuard, before each New and between New and FPool.Add.
    for I := 1 to Steps do
    begin
      Wait5KStep := 0; Wait5KFailAt := I;
      Wait5KAllocated := 0; Wait5KDisposed := 0;
      Raised := False; M := nil;
      try
        try M := TWaitChainMonitor.Create;
        except on E: EOutOfMemory do Raised := True; end;
      finally M.Free; end;
      Check(Raised, 'injected allocation failure reached at ' + IntToStr(I));
      Check(Wait5KAllocated = Wait5KDisposed,
        'partial constructor ownership at ' + IntToStr(I));
    end;
    Wait5KFailAt := 0; Wait5KStep := 0;
    M := TWaitChainMonitor.Create;
    try
      M.FEpoch := High(Cardinal);
      M.StopSession;
      Check(M.FEpoch = 0, 'epoch wraps explicitly with overflow checking');
    finally M.Free; end;
    Result := True;
  except on E: Exception do Failure := E.Message; end;
  Wait5KFailAt := 0;
end;
