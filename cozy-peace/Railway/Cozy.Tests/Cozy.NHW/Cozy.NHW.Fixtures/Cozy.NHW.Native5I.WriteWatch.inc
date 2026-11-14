var
  WatchTestExpected: TBytes;
  WatchTestQueryOK, WatchTestCopyOK, WatchTestDirtyOK: Boolean;
  WatchTestCorrupt, WatchTestPartial, WatchTestRaise: Boolean;
  WatchTestFailAfterCopy, WatchTestCopied: Boolean;
  WatchTestRegion: TVirtualRegion;
  WatchTestMask: Cardinal;
function WatchTestQuery(Process: THandle; Address: NativeUInt;
  out Region: TVirtualRegion): Boolean;
begin
  Region := WatchTestRegion;
  Result := WatchTestQueryOK and (Process <> 0) and (Address >= $10000) and
    not (WatchTestFailAfterCopy and WatchTestCopied);
end;
function WatchTestCopy(Address, Buffer: Pointer; Bytes: NativeUInt;
  out ReadBytes: NativeUInt): Boolean;
begin
  ReadBytes := 0;
  if WatchTestRaise then raise Exception.Create('synthetic read failure');
  Result := WatchTestCopyOK and (Address <> nil) and (Buffer <> nil) and
    (Bytes = NativeUInt(Length(WatchTestExpected)));
  if not Result then Exit;
  Move(WatchTestExpected[0], PByte(Buffer)^, Bytes);
  if WatchTestCorrupt then PByte(Buffer)^ := PByte(Buffer)^ xor $FF;
  ReadBytes := Bytes;
  if WatchTestPartial then Dec(ReadBytes);
  WatchTestCopied := True;
end;
function WatchTestDirty(Base: Pointer; RegionSize: NativeUInt;
  PageSize: Cardinal; out DirtyMask: Cardinal): Boolean;
begin
  DirtyMask := WatchTestMask;
  Result := WatchTestDirtyOK and (Base <> nil) and (RegionSize = 16384) and (PageSize = 4096);
end;
function TestWriteWatch5I(out Failure: string; out Checks: Integer): Boolean;
var
  M: TWriteWatchMonitor;
  D: TDetectionKinds;
  H: TTargetHolder;
  Changed, Raised: Boolean;
  SavedCopy: TWatchCopyHook; SavedQuery: TWatchQueryHook; SavedDirty: TWatchDirtyHook;
  procedure Check(Value: Boolean; const Name: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Name); end;
  procedure Prime;
  var I: Integer;
  begin
    M.FBase := nil; M.Reset(0); // never release the synthetic pointer
    M.FBase := Pointer(NativeUInt($10000)); M.FRegionSize := 16384; M.FPageSize := 4096;
    M.FEnabled := True; SetLength(M.FExpected, 16384);
    for I := 0 to Length(M.FExpected) - 1 do M.FExpected[I] := Byte(I and $FF);
    WatchTestExpected := Copy(M.FExpected, 0, Length(M.FExpected));
    WatchTestQueryOK := True; WatchTestCopyOK := True; WatchTestDirtyOK := True;
    WatchTestCorrupt := False; WatchTestPartial := False; WatchTestRaise := False;
    WatchTestFailAfterCopy := False; WatchTestCopied := False; WatchTestMask := 0;
    WatchTestRegion := Default(TVirtualRegion);
    WatchTestRegion.BaseAddress := $10000; WatchTestRegion.AllocationBase := $10000;
    WatchTestRegion.Size := 16384; WatchTestRegion.State := ALLOC_MEM_COMMIT;
    WatchTestRegion.Protect := $04; WatchTestRegion.RegionType := ALLOC_MEM_PRIVATE;
    D := [];
  end;
  procedure Observe(Tick: UInt64);
  begin D := []; WatchTestCopied := False; M.Examine(WinCurrentProcessId, Tick, D); end;
begin
  Result := False; Failure := ''; Checks := 0; M := nil;
  SavedCopy := WatchCopyHook; SavedQuery := WatchQueryHook; SavedDirty := WatchDirtyHook;
  try
    try
      WatchCopyHook := WatchTestCopy; WatchQueryHook := WatchTestQuery; WatchDirtyHook := WatchTestDirty;
      M := TWriteWatchMonitor.Create;
      Prime; Check(M.TryCanaryChanged(Changed) and not Changed, 'bounded complete clean copy accepted');
      Check(M.FLastContentValid, 'valid content observation marked');
      WatchTestCorrupt := True;
      Check(M.TryCanaryChanged(Changed) and Changed, 'local-buffer content difference accepted');
      WatchTestPartial := True;
      Check(not M.TryCanaryChanged(Changed) and not Changed, 'partial copy is not corruption evidence');
      Check(not M.FLastContentValid, 'partial copy marked unavailable');
      WatchTestPartial := False; WatchTestCopyOK := False;
      Check(not M.TryCanaryChanged(Changed), 'failed read rejected');
      Prime; WatchTestFailAfterCopy := True;
      Check(not M.TryCanaryChanged(Changed), 'post-copy metadata failure rejects result');
      Prime; WatchTestRegion.Protect := $104;
      Check(not M.TryCanaryChanged(Changed) and not WatchTestCopied, 'guarded pages not copied');
      Prime; WatchTestRegion.AllocationBase := $20000;
      Check(not M.RegionReadable, 'different allocation rejected');
      Prime; WatchTestRegion.Size := 100;
      Check(not M.RegionReadable, 'non-containing metadata rejected');
      Prime; M.FRegionSize := High(NativeUInt);
      Check(not M.TryCanaryChanged(Changed), 'oversized read rejected before dereference');
      Prime; M.FPageSize := 8192;
      Check(not M.RegionReadable, 'unexpected geometry rejected');
      Prime; WatchTestCorrupt := True; Observe(1000);
      Check(dkWriteIntegrity in D, 'fresh corrupt observation reports');
      Observe(2000); Check(not (dkWriteIntegrity in D), 'same corruption not reported again');
      WatchTestCopyOK := False; Observe(3000);
      Check(M.FWasCorrupt and not M.FLastContentValid, 'failed read preserves last committed corrupt value');
      Check(not (dkWriteIntegrity in D), 'failed read does not report integrity');
      WatchTestCopyOK := True; Observe(4000);
      Check(not (dkWriteIntegrity in D), 'same corruption after gap not duplicated');
      WatchTestCorrupt := False; Observe(5000);
      Check(not M.FWasCorrupt and M.FLastContentValid, 'successful clean copy clears committed corruption');
      WatchTestCorrupt := True; Observe(6000);
      Check(dkWriteIntegrity in D, 'new corruption after clean observation reports');
      Prime; WatchTestMask := 1; Observe(1000);
      Check(not (dkWriteWatch in D) and (M.FEpisodes.Count = 0),
        'uncorroborated dirty page is telemetry only');
      H := Default(TTargetHolder); H.RightsUnion := ACCESS_VM_WRITE;
      M.ObserveHolder(H, True, False, False, 0, 1200);
      Observe(1500);
      Check((dkWriteWatch in D) and (M.FEpisodes.Count = 1),
        'dirty page plus fresh VM_WRITE capability reports');
      WatchTestDirtyOK := False; Observe(2000);
      Check((M.FEpisodes.Count = 0) and M.FWatchNeedsBaseline, 'dirty query failure breaks repeat sequence');
      WatchTestDirtyOK := True; Observe(3000);
      Check(not (dkWriteWatch in D) and not M.FWatchNeedsBaseline, 'first recovered dirty reset establishes baseline');
      M.ObserveHolder(H, True, False, False, 0, 3500); Observe(4000);
      M.ObserveHolder(H, True, False, False, 0, 4500); Observe(5000);
      Check(not (dkRepeatedWrite in D), 'gap does not provide old repeat credit');
      M.ObserveHolder(H, True, False, False, 0, 5500); Observe(6000);
      Check(dkRepeatedWrite in D, 'three corroborated fresh cycles still report repeated writes');
      Prime; H := Default(TTargetHolder); H.RightsUnion := ACCESS_VM_WRITE;
      M.ObserveHolder(H, True, False, False, 0, 1000);
      Check(M.FLastFreshWrite = 1000, 'holder evidence tracked');
      WatchTestQueryOK := False; Observe(1500);
      Check((M.FLastFreshWrite = 0) and M.FWatchNeedsBaseline, 'metadata gap clears cross-gap correlation');
      Prime; WatchTestRaise := True; Raised := False;
      try Observe(1000); except on X: Exception do Raised := True; end;
      Check(Raised and M.FWatchNeedsBaseline and not M.FLastContentValid, 'exception propagates with invalidated coverage');
      Prime; WatchTestMask := 1; Observe(2000); Observe(1000);
      Check((M.FEpisodes.Count = 0) and not (dkWriteWatch in D), 'clock rollback rebaselines dirty collection');
      Prime; WatchTestCorrupt := True; D := [];
      M.Examine(0, 1000, D); Check(D = [], 'foreign or absent target not inspected');
      Prime; Observe(1000); WatchTestCorrupt := True; Observe(1200);
      Check(not (dkWriteIntegrity in D), 'original sampling interval retained');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    if M <> nil then begin M.FBase := nil; M.FEnabled := False; end;
    M.Free; SetLength(WatchTestExpected, 0);
    WatchCopyHook := SavedCopy; WatchQueryHook := SavedQuery; WatchDirtyHook := SavedDirty;
  end;
end;
