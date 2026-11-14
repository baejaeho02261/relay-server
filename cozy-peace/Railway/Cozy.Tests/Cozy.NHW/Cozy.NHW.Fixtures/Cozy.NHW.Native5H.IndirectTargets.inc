var
  IndirectTestOriginalOK, IndirectTestCurrentOK, IndirectTestRaise: Boolean;
  IndirectTestOriginalKind, IndirectTestCurrentKind: TCodeLocation;
  IndirectTestOriginalRegion, IndirectTestCurrentRegion: NativeUInt;
function IndirectTestDescribe(Address: NativeUInt; out Kind: TCodeLocation;
  out Region: NativeUInt): Boolean;
begin
  if IndirectTestRaise then raise Exception.Create('synthetic describe exception');
  if Address = $10040 then
  begin Kind := IndirectTestOriginalKind; Region := IndirectTestOriginalRegion; Result := IndirectTestOriginalOK; end
  else
  begin Kind := IndirectTestCurrentKind; Region := IndirectTestCurrentRegion; Result := IndirectTestCurrentOK; end;
end;
function TestIndirectTargetsHardening(out Failure: string; out Checks: Integer): Boolean;
var M: TIndirectTargetMonitor; D: TDetectionKinds; Saved: TIndirectDescribeHook; Raised: Boolean;
  procedure Check(Value: Boolean; const Name: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Name); end;
  procedure Prime;
  begin
    M.Reset; D := []; IndirectTestRaise := False;
    IndirectTestOriginalOK := True; IndirectTestCurrentOK := True;
    IndirectTestOriginalKind := clImage; IndirectTestCurrentKind := clPrivate;
    IndirectTestOriginalRegion := $10000; IndirectTestCurrentRegion := $20000;
    M.Examine(True, True, True, 1, $10040, 0, 0, [], 1000, D);
  end;
  procedure Observe(Address: NativeUInt; Tick: UInt64; Independent: Boolean);
  var K: TDetectionKinds;
  begin
    D := []; K := []; if Independent then Include(K, dkIAT);
    M.Examine(True, False, True, 1, Address, 0, 0, K, Tick, D);
  end;
begin
  Result := False; Failure := ''; Checks := 0; M := nil; Saved := IndirectDescribeHook;
  try
    try
      IndirectDescribeHook := IndirectTestDescribe; M := TIndirectTargetMonitor.Create;
      Prime; Check(M.FItems[0].Expected = $10040, 'validated registration stored');
      Observe($20040, 2000, True); Check(M.FItems[0].Confirmations = 1, 'first validated redirect');
      IndirectTestCurrentOK := False; Observe($20040, 3000, True);
      Check((M.FItems[0].Confirmations = 0) and not (dkIndirectTarget in D), 'current query failure interrupts');
      IndirectTestCurrentOK := True; Observe($20040, 4000, True);
      Check(M.FItems[0].Confirmations = 1, 'first post-failure read');
      Observe($20040, 5000, True); Check(dkIndirectTarget in D, 'second post-failure read reports');
      Observe($20040, 6000, True); Check(not (dkIndirectTarget in D), 'cooldown retained');
      Prime; Observe($20040, 2000, True); IndirectTestOriginalOK := False;
      Observe($20040, 3000, True); Check(M.FItems[0].Confirmations = 0, 'original query failure interrupts');
      Prime; Observe($20040, 2000, True); Observe(0, 3000, True);
      Check((M.FItems[0].Confirmations = 0) and (M.FItems[0].Expected = $10040), 'zero callback clears candidate not approved registration');
      Observe($20040, 4000, True); Check(not (dkIndirectTarget in D), 'return from zero needs reconfirmation');
      Prime; Observe($20040, 2000, True); Observe($20040, 2000, True);
      Check(M.FItems[0].Confirmations = 1, 'duplicate time not confirmation');
      Prime; Observe($20040, 2000, True); IndirectTestCurrentRegion := $18000;
      Observe($20040, 3000, True); Check(M.FItems[0].Confirmations = 1, 'remapped destination restarts');
      Prime; Observe($20040, 2000, True); IndirectTestOriginalRegion := $8000;
      Observe($20040, 3000, True); Check(M.FItems[0].Confirmations = 1, 'changed original region restarts');
      Prime; Observe($20040, 2000, True); Observe($20080, 3000, True);
      Check((M.FItems[0].Observed = $20080) and (M.FItems[0].Confirmations = 1), 'new address restarts');
      Prime; Observe($20040, 2000, True); Observe($10040, 3000, True);
      Check(M.FItems[0].Confirmations = 0, 'restored expected target resets');
      Prime; Observe($20040, 2000, True); IndirectTestCurrentKind := clUnknown;
      Observe($20040, 3000, True); Check(M.FItems[0].Confirmations = 0, 'unknown code invalidates');
      Prime; Observe($20040, 2000, True); IndirectTestCurrentKind := clMapped;
      Observe($20040, 3000, True); Check(M.FItems[0].Confirmations = 0, 'mapped target not private');
      Prime; Observe($20040, 2000, True); IndirectTestOriginalKind := clPrivate;
      Observe($20040, 3000, True); Check(M.FItems[0].Confirmations = 0, 'original must still be image');
      Prime; Observe($20040, 2000, True); IndirectTestCurrentRegion := $30000;
      Observe($20040, 3000, True); Check(M.FItems[0].Confirmations = 0, 'non-containing destination rejected');
      Prime; Observe($20040, 2000, True); M.Examine(True, False, False, 1, $20040, 0, 0, [dkIAT], 3000, D);
      Check(M.FItems[0].Confirmations = 0, 'unstable epoch breaks sequence');
      Prime; Observe($20040, 2000, True); M.Examine(True, True, True, 1, $20040, 0, 0, [dkIAT], 3000, D);
      Check((M.FItems[0].Confirmations = 0) and (M.FItems[0].Expected = $10040), 'baseline does not silently approve replacement');
      Prime; Observe($20040, 3000, True); Observe($20040, 2000, True);
      Check((M.FItems[0].Confirmations = 1) and not (dkIndirectTarget in D), 'clock rollback not confirmation');
      Prime; Observe($20040, 2000, False); Observe($20040, 3000, False);
      Check(not (dkIndirectTarget in D), 'independent signal mandatory');
      Prime; Observe($20040, 2000, True); IndirectTestRaise := True; Raised := False;
      try Observe($20040, 3000, True); except on E: Exception do Raised := True; end;
      Check(Raised and (M.FItems[0].Confirmations = 0), 'exception invalidates all pending items');
      IndirectTestRaise := False; M.Reset; IndirectTestOriginalOK := False;
      Observe($10040, 4000, True); Check(M.FItems[0].Expected = 0, 'unavailable baseline not approved');
      M.Examine(False, False, True, 1, $10040, 0, 0, [], 5000, D);
      Check(M.FEpoch = 0, 'foreign target resets');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally IndirectDescribeHook := Saved; M.Free; end;
end;
