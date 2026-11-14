function TestIPC10M(out Failure: string; out Checks: Integer): Boolean;
var M: TIPCMonitor; Obs: TList<TIPCObservation>; D: TDetectionKinds;
    I: Integer; Raised: Boolean; O: TIPCObservation;
  procedure Check(Condition: Boolean; const Msg: string);
  begin
    Inc(Checks);
    if not Condition then raise Exception.Create(Msg);
  end;
begin
  Result := False; Failure := ''; Checks := 0;
  M := nil; Obs := nil; IPC10MLive := 0; IPC10MFail := 0;
  try
    try
      M := TIPCMonitor.Create; Obs := TList<TIPCObservation>.Create;
      for I := 1 to 3 do
      begin
        IPC10MCall := 0; IPC10MFail := I; Raised := False; D := [];
        try M.Examine(Obs, True, 1000, D); except on E: EOutOfMemory do Raised := True; end;
        Check(Raised, 'injected allocation reached');
        Check(IPC10MLive = 0, 'every created temporary released');
        Check(M.FBaselineRemaining = 3, 'failed construction does not consume baseline');
      end;
      IPC10MFail := 0; IPC10MCall := 0; D := [dkHeapState];
      M.Examine(nil, True, 1000, D);
      Check((IPC10MCall = 0) and (D = [dkHeapState]), 'nil observations are unknown');
      for I := 1 to 3 do M.Examine(Obs, True, UInt64(I) * 1000, D);
      Check((M.FBaselineRemaining = 0) and (IPC10MLive = 0), 'normal path still primes and frees');
      O := Default(TIPCObservation); O.OwnerPID := 42; O.Kind := ikEvent;
      O.ObjectIdentity := $10000; O.GrantedAccess := 1; Obs.Add(O);
      M.Examine(Obs, True, 4000, D);
      Check(dkEvent in D, 'existing object detection retained');
      Check(IPC10MLive = 0, 'success path releases all temporaries');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    IPC10MFail := 0; Obs.Free; M.Free;
  end;
end;
