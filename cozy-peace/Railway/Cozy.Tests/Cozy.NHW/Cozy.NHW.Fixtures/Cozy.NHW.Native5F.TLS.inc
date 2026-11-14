const TLS_TEST_BASE = NativeUInt($3000000);
var
  TLSTestData: TBytes;
  TLSTestView: TPEView;
  TLSTestFailAddress: NativeUInt;
  TLSTestRaise, TLSTestChangeArray, TLSTestChangeDirectory: Boolean;
  TLSTestArrayReads, TLSTestDirReads: Integer;
  TLSTestSnapshot: TTLSCallbackSnapshot;
  TLSTestCaptureOK, TLSTestCaptureRaise: Boolean;
procedure TLSTestPut64(Offset: Integer; Value: UInt64);
begin Move(Value, TLSTestData[Offset], SizeOf(Value)); end;
procedure TLSTestSetup;
begin
  SetLength(TLSTestData, $4000); FillChar(TLSTestData[0], Length(TLSTestData), 0);
  TLSTestView := Default(TPEView); TLSTestView.Base := TLS_TEST_BASE;
  TLSTestView.ImageSize := Length(TLSTestData);
  TLSTestView.Directory[9].RVA := $200; TLSTestView.Directory[9].Size := 40;
  TLSTestPut64($200 + 24, UInt64(TLS_TEST_BASE + $1000));
  TLSTestPut64($1000, $90000000); TLSTestPut64($1008, $80000000);
  TLSTestFailAddress := 0; TLSTestRaise := False;
  TLSTestChangeArray := False; TLSTestChangeDirectory := False;
  TLSTestArrayReads := 0; TLSTestDirReads := 0;
end;
function TLSTestGetView(out V: TPEView): Boolean;
begin V := TLSTestView; Result := True; end;
function TLSTestRead(Address: NativeUInt; var Dest; Bytes: NativeUInt): Boolean;
var Offset: NativeUInt; V: UInt64; D: TTLSDirectory64;
begin
  Result := False;
  if TLSTestRaise then raise Exception.Create('synthetic TLS read exception');
  if (Address = TLSTestFailAddress) or (Address < TLS_TEST_BASE) then Exit;
  Offset := Address - TLS_TEST_BASE;
  if not NHWBufferSpan(NativeUInt(Length(TLSTestData)), Offset, Bytes) then Exit;
  Move(TLSTestData[Offset], Dest, Bytes);
  if (Offset = $1000) and (Bytes = 8) then
  begin
    Inc(TLSTestArrayReads);
    if TLSTestChangeArray and (TLSTestArrayReads > 1) then
    begin V := $90001000; Move(V, Dest, SizeOf(V)); end;
  end;
  if (Offset = $200) and (Bytes = SizeOf(D)) then
  begin
    Inc(TLSTestDirReads);
    if TLSTestChangeDirectory and (TLSTestDirReads > 1) then
    begin Move(Dest, D, SizeOf(D)); Inc(D.AddressOfCallbacks, 8); Move(D, Dest, SizeOf(D)); end;
  end;
  Result := True;
end;
function TLSTestDescribe(Address: NativeUInt; out K: TCodeLocation;
  out RegionBase: NativeUInt): Boolean;
begin
  RegionBase := Address and not NativeUInt($FFF);
  if Address >= $90000000 then K := clPrivate else K := clImage;
  Result := True;
end;
function TLSTestCapture(out S: TTLSCallbackSnapshot): Boolean;
begin
  if TLSTestCaptureRaise then raise Exception.Create('synthetic TLS capture exception');
  S := TLSTestSnapshot; Result := TLSTestCaptureOK;
end;
function TestTLSHardening(out Failure: string; out Checks: Integer): Boolean;
var
  SavedView: TTLSViewHook; SavedRead: TTLSReadHook;
  SavedDescribe: TTLSDescribeHook; SavedCapture: TTLSCaptureHook;
  S: TTLSCallbackSnapshot; M: TTLSCallbackMonitor; D: TDetectionKinds;
  I: Integer; Raised: Boolean;
  procedure Check(Value: Boolean; const Name: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Name); end;
  procedure SetupMonitor;
  begin
    M.Reset; D := []; TLSTestCaptureOK := True; TLSTestCaptureRaise := False;
    TLSTestSnapshot := Default(TTLSCallbackSnapshot);
    TLSTestSnapshot.Valid := True; TLSTestSnapshot.Status := tcsComplete;
    TLSTestSnapshot.Count := 2; TLSTestSnapshot.Digest := 10;
    M.Examine(True, False, 1000, D);
    TLSTestSnapshot.PrivateExecutable := 1; TLSTestSnapshot.Digest := 20;
  end;
begin
  Result := False; Failure := ''; Checks := 0; M := nil;
  SavedView := TLSViewHook; SavedRead := TLSReadHook;
  SavedDescribe := TLSDescribeHook; SavedCapture := TLSCaptureHook;
  try
    try
      TLSViewHook := TLSTestGetView; TLSReadHook := TLSTestRead;
      TLSDescribeHook := TLSTestDescribe; TLSTestSetup;
      Check(CaptureTLSCallbacks(S) and S.Valid and (S.Count = 2) and
        (S.PrivateExecutable = 1) and (S.Status = tcsComplete), 'complete TLS snapshot');
      Check(TLSTestArrayReads = 2, 'callback array read twice');
      TLSTestSetup; TLSTestFailAddress := TLS_TEST_BASE + $1008;
      Check(not CaptureTLSCallbacks(S) and (S.Status = tcsReadFailed) and
        (S.Count = 0) and (S.Digest = 0), 'partial callbacks never published');
      TLSTestSetup; TLSTestChangeArray := True;
      Check(not CaptureTLSCallbacks(S) and (S.Status = tcsChangedDuringRead), 'callback changed between passes');
      TLSTestSetup; TLSTestChangeDirectory := True;
      Check(not CaptureTLSCallbacks(S) and (S.Status = tcsChangedDuringRead), 'callback array address changed');
      TLSTestSetup; TLSTestView.Directory[9].RVA := 0; TLSTestView.Directory[9].Size := 0;
      Check(CaptureTLSCallbacks(S) and S.Valid and (S.Count = 0), 'absent TLS is valid');
      TLSTestView.Directory[9].Size := 40;
      Check(not CaptureTLSCallbacks(S) and (S.Status = tcsInvalidRange), 'inconsistent absent directory');
      TLSTestSetup; TLSTestPut64($218, 0);
      Check(CaptureTLSCallbacks(S) and S.Valid and (S.Count = 0), 'null callbacks pointer allowed');
      TLSTestSetup; TLSTestPut64($1000, 0);
      Check(CaptureTLSCallbacks(S) and (S.Count = 0), 'empty terminated array allowed');
      TLSTestSetup;
      for I := 0 to MAX_TLS_CALLBACKS - 1 do TLSTestPut64($1000 + I * 8, $80000000);
      TLSTestPut64($1000 + MAX_TLS_CALLBACKS * 8, 0);
      Check(CaptureTLSCallbacks(S) and (S.Count = MAX_TLS_CALLBACKS), 'exact callback limit plus terminator');
      TLSTestPut64($1000 + MAX_TLS_CALLBACKS * 8, $80000000);
      Check(not CaptureTLSCallbacks(S) and (S.Status = tcsUnterminatedWithinLimit) and
        (S.Count = 0), 'missing terminator within bound distinguished');
      TLSTestSetup; TLSTestPut64($218, High(UInt64) - 3);
      Check(not CaptureTLSCallbacks(S) and (S.Status = tcsInvalidRange), 'overflowing slot range rejected');
      TLSTestSetup; TLSTestView.Directory[9].Size := 39;
      Check(not CaptureTLSCallbacks(S) and (S.Status = tcsInvalidRange), 'short directory rejected');
      TLSTestSetup; TLSTestRaise := True; Raised := False;
      try CaptureTLSCallbacks(S); except on E: Exception do Raised := True; end;
      Check(Raised and not S.Valid and (S.Count = 0), 'exception snapshot remains empty');
      TLSTestRaise := False; TLSCaptureHook := TLSTestCapture;
      M := TTLSCallbackMonitor.Create; SetupMonitor;
      M.Examine(False, True, 9000, D);
      Check((M.FConfirmations = 1) and (D = []), 'first change not detection');
      TLSTestCaptureOK := False; M.Examine(False, True, 17000, D);
      Check((M.FConfirmations = 0) and (M.FBaselineDigest = 10), 'read failure clears candidate only');
      TLSTestCaptureOK := True; M.Examine(False, True, 25000, D);
      Check((M.FConfirmations = 1) and (D = []), 'recovered first confirmation');
      M.Examine(False, True, 33000, D);
      Check(dkTLSCallbackIntegrity in D, 'fresh stable pair detects');
      D := []; M.Examine(False, True, 41000, D);
      Check((D = []) and (M.FConfirmations = 2), 'cooldown and bounded confirmation');
      SetupMonitor; M.Examine(False, False, 9000, D); M.Examine(False, False, 17000, D);
      Check((D = []) and (M.FConfirmations = 2), 'independent evidence required');
      SetupMonitor; M.Examine(False, True, 9000, D); M.Examine(False, True, 40001, D);
      Check((D = []) and (M.FConfirmations = 1), 'candidate expiration');
      SetupMonitor; M.Examine(False, True, 9000, D);
      TLSTestSnapshot.PrivateExecutable := 2; M.Examine(False, True, 17000, D);
      Check((D = []) and (M.FConfirmations = 1), 'private count part of identity');
      TLSTestSnapshot.Status := tcsReadFailed; M.Examine(False, True, 25000, D);
      Check(M.FConfirmations = 0, 'success with failed status rejected');
      SetupMonitor; M.Examine(False, True, 9000, D);
      TLSTestSnapshot.Count := 65; M.Examine(False, True, 17000, D);
      Check(M.FConfirmations = 0, 'invalid callback count rejected');
      SetupMonitor; M.Examine(False, True, 9000, D);
      TLSTestSnapshot.Digest := 10; M.Examine(False, True, 17000, D);
      Check((M.FConfirmations = 0) and (D = []), 'return to baseline');
      SetupMonitor; M.Examine(False, True, 9000, D); M.Examine(False, True, 100, D);
      Check((M.FConfirmations = 1) and (D = []), 'clock rollback resets confirmation');
      SetupMonitor; M.Examine(False, True, 9000, D); M.Examine(False, True, 9000, D);
      Check(M.FConfirmations = 1, 'same tick not a new sample');
      TLSTestCaptureRaise := True; Raised := False;
      try M.Examine(False, True, 17000, D); except on E: Exception do Raised := True; end;
      Check(Raised and (M.FConfirmations = 0) and (D = []), 'capture exception clears candidate');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    M.Free; TLSViewHook := SavedView; TLSReadHook := SavedRead;
    TLSDescribeHook := SavedDescribe; TLSCaptureHook := SavedCapture;
    TLSTestData := nil;
  end;
end;
