function TestAsyncGuard5L(out Failure: string; out Checks: Integer): Boolean;
var M: TAsyncGuardMonitor; Owners: TDictionary<Cardinal, Byte>;
    Entries: array[0..7] of TNativeHandleEntry;
    N, J: Integer; Raised: Boolean;
  procedure Check(C: Boolean; const Msg: string);
  begin Inc(Checks); if not C then raise Exception.Create(Msg); end;
  procedure Snapshot(Count: Integer);
  var I: Integer; P: PNativeHandleEntry;
  begin
    SetLength(Async5LData, 16 + Count * SizeOf(TNativeHandleEntry));
    FillChar(Async5LData[0], Length(Async5LData), 0);
    PNativeUInt(@Async5LData[0])^ := NativeUInt(Count);
    for I := 0 to Count - 1 do
    begin
      P := Pointer(NativeUInt(@Async5LData[0]) + 16 +
        NativeUInt(I) * SizeOf(TNativeHandleEntry));
      P^ := Entries[I];
    end;
  end;
begin
  Result := False; Failure := ''; Checks := 0; M := nil; Owners := nil;
  Async5LAlive := 0; Async5LAllocation := 0; Async5LFailAllocation := 0;
  Async5LFetchOK := True;
  try
    try
      M := TAsyncGuardMonitor.Create; Owners := TDictionary<Cardinal, Byte>.Create;
      M.FPort := $88; M.FOriginalPort := $88;
      Check(not M.QueryPortOwners(nil), 'nil output rejected');
      SetLength(Async5LData, 0); Owners.Add(7, 1);
      Check(not M.QueryPortOwners(Owners), 'empty buffer rejected');
      Check(Owners.Count = 0, 'failed result clears output');
      SetLength(Async5LData, 15);
      Check(not M.QueryPortOwners(Owners), 'truncated header rejected');
      Snapshot(0); Check(not M.QueryPortOwners(Owners), 'zero unsigned count rejected before minus one');
      PNativeUInt(@Async5LData[0])^ := High(NativeUInt);
      Check(not M.QueryPortOwners(Owners), 'oversize count rejected');
      FillChar(Entries, SizeOf(Entries), 0);
      Entries[0].OwnerPID := 4242; Entries[0].HandleValue := $88;
      Entries[0].ObjectPointer := Pointer(NativeUInt($100000));
      Entries[0].ObjectTypeIndex := 3;
      for J := 1 to High(Entries) do
      begin Entries[J] := Entries[0]; Entries[J].OwnerPID := 77; end;
      Entries[3].ObjectTypeIndex := 4;
      Entries[4].ObjectPointer := Pointer(NativeUInt($200000));
      Entries[5].OwnerPID := 0;
      Entries[6].OwnerPID := NativeUInt(High(Cardinal)) + NativeUInt(1);
      Entries[7].OwnerPID := 4242;
      Snapshot(8);
      Check(M.QueryPortOwners(Owners), 'valid owner snapshot accepted');
      Check((Owners.Count = 1) and Owners.ContainsKey(77), 'object/type/PID filters and dedup retained');
      M.FPort := $99;
      Check(not M.QueryPortOwners(Owners), 'changed owned-port handle rejected');
      Check(Owners.Count = 0, 'changed-port output cleared'); M.FPort := $88;
      Entries[0].HandleValue := $89; Snapshot(1);
      Check(not M.QueryPortOwners(Owners), 'missing owned reference is unknown');
      Entries[0].HandleValue := $88; Snapshot(1);
      Check(M.QueryPortOwners(Owners) and (Owners.Count = 0), 'only-self valid snapshot has zero foreign owners');
      Async5LFetchOK := False;
      Check(not M.QueryPortOwners(Owners), 'failed snapshot never committed');
      Async5LFetchOK := True;
      for N := 1 to 2 do
      begin
        Async5LAllocation := 0; Async5LFailAllocation := N; Raised := False;
        try M.ObserveForeignOwners(False);
        except on E: EOutOfMemory do Raised := True; end;
        Check(Raised, 'synthetic allocation failure propagated');
        Check(Async5LAlive = 0, 'temporary owner containers released after creation failure');
      end;
      Async5LFailAllocation := 0; Async5LAllocation := 0;
      Snapshot(1); Check(not M.ObserveForeignOwners(True), 'initial owner baseline quiet');
      Check(M.FPortBaselineReady, 'complete first snapshot primes owners');
      Snapshot(2); Check(M.ObserveForeignOwners(False), 'new foreign owner still detected');
      Check(not M.ObserveForeignOwners(False), 'existing owner not reported again');
      Async5LFetchOK := False; Check(not M.ObserveForeignOwners(False), 'failed snapshot is not a disappearance');
      Check(M.FOwnerMissing.ContainsKey(77), 'failed snapshot retains accepted owner');
      Async5LFetchOK := True; Snapshot(1); M.ObserveForeignOwners(False);
      Check(M.FOwnerMissing.ContainsKey(77), 'one valid missing snapshot retained');
      M.ObserveForeignOwners(False);
      Check(not M.FOwnerMissing.ContainsKey(77), 'two valid missing snapshots retire owner');
      Check(Async5LAlive = 0, 'all successful temporary containers released');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    Owners.Free;
    if M <> nil then begin M.FPort := 0; M.FOriginalPort := 0; end;
    M.Free; SetLength(Async5LData, 0);
  end;
end;
