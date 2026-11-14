function TestPathGuard10M(out Failure: string; out Checks: Integer): Boolean;
var M: TPathGuard; D: TDetectionKinds; I: Integer; Raised: Boolean;
  procedure Check(Condition: Boolean; const Msg: string);
  begin
    Inc(Checks);
    if not Condition then raise Exception.Create(Msg);
  end;
begin
  Result := False; Failure := ''; Checks := 0;
  M := nil; Path10MLive := 0; Path10MFail := 0; Path10MQueryRaises := False;
  try
    try
      M := TPathGuard.Create;
      for I := 1 to 4 do
      begin
        M.Reset; Path10MCall := 0; Path10MFail := I; Raised := False; D := [dkHeapState];
        try M.Examine(1000, D); except on E: EOutOfMemory do Raised := True; end;
        Check(Raised, 'requested construction failure reached');
        Check(Path10MLive = 0, 'prior lists freed after intermediate failure');
        Check(D = [dkHeapState], 'allocation failure emits no new detection');
      end;
      M.Reset; Path10MFail := 0; Path10MCall := 0; Path10MQueryRaises := True;
      Raised := False; try M.Examine(1000, D); except on E: Exception do Raised := True; end;
      Check(Raised and (Path10MLive = 0), 'query exception releases all four lists');
      M.Reset; Path10MQueryRaises := False; Path10MCall := 0; D := [];
      M.Examine(1000, D);
      Check((Path10MCall = 4) and (Path10MLive = 0), 'normal path allocates and releases exactly four');
      Check(D = [], 'unknown snapshots do not fabricate changes');
      M.Examine(1001, D);
      Check(Path10MCall = 4, 'existing poll throttling retained');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    Path10MFail := 0; Path10MQueryRaises := False; M.Free;
  end;
end;
