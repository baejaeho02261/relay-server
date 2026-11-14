const IMPORT_TEST_BASE = NativeUInt($2000000);
var
  ImportTestData: TBytes;
  ImportTestView: TPEView;
  ImportTestFailAddress: NativeUInt;
  ImportTestRaise: Boolean;
  ImportTestViewCalls: Integer;
  ImportTestChangeView: Boolean;
  ImportTestSnapshot: TImportRiskSnapshot;
  ImportTestCaptureOK, ImportTestCaptureRaise: Boolean;
procedure ImportTestPut32(Offset: Integer; Value: Cardinal);
begin Move(Value, ImportTestData[Offset], SizeOf(Value)); end;
procedure ImportTestPut64(Offset: Integer; Value: UInt64);
begin Move(Value, ImportTestData[Offset], SizeOf(Value)); end;
procedure ImportTestSetup;
begin
  SetLength(ImportTestData, $20000); FillChar(ImportTestData[0], Length(ImportTestData), 0);
  ImportTestView := Default(TPEView); ImportTestView.Base := IMPORT_TEST_BASE;
  ImportTestView.ImageSize := Length(ImportTestData);
  ImportTestView.Directory[1].RVA := $200; ImportTestView.Directory[1].Size := 40;
  ImportTestPut32($200 + 12, $1000); ImportTestPut32($200 + 16, $2000);
  ImportTestPut64($2000, $90000000); ImportTestPut64($2008, $80000000);
  ImportTestFailAddress := 0; ImportTestRaise := False;
  ImportTestViewCalls := 0; ImportTestChangeView := False;
end;
function ImportTestGetView(out V: TPEView): Boolean;
begin
  Inc(ImportTestViewCalls); V := ImportTestView;
  if ImportTestChangeView and (ImportTestViewCalls > 1) then Inc(V.Directory[1].RVA);
  Result := True;
end;
function ImportTestRead(Address: NativeUInt; var Dest; Bytes: NativeUInt): Boolean;
var Offset: NativeUInt;
begin
  Result := False;
  if ImportTestRaise then raise Exception.Create('synthetic import read exception');
  if (Address = ImportTestFailAddress) or (Address < IMPORT_TEST_BASE) then Exit;
  Offset := Address - IMPORT_TEST_BASE;
  if not NHWBufferSpan(NativeUInt(Length(ImportTestData)), Offset, Bytes) then Exit;
  Move(ImportTestData[Offset], Dest, Bytes); Result := True;
end;
function ImportTestDescribe(Address: NativeUInt; out K: TCodeLocation;
  out RegionBase: NativeUInt): Boolean;
begin
  RegionBase := Address and not NativeUInt($FFF);
  if Address >= $90000000 then K := clPrivate else K := clImage;
  Result := True;
end;
function ImportTestCapture(out S: TImportRiskSnapshot): Boolean;
begin
  if ImportTestCaptureRaise then raise Exception.Create('synthetic import capture exception');
  S := ImportTestSnapshot; Result := ImportTestCaptureOK;
end;
function TestImportHardening(out Failure: string; out Checks: Integer): Boolean;
var
  SavedView: TImportViewHook; SavedRead: TImportReadHook;
  SavedDescribe: TImportDescribeHook; SavedCapture: TImportCaptureHook;
  S: TImportRiskSnapshot; M: TImportRedirectionMonitor; D: TDetectionKinds;
  I: Integer; Raised: Boolean;
  procedure Check(Value: Boolean; const Name: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Name); end;
  procedure SetupMonitor;
  begin
    M.Reset; D := []; ImportTestCaptureOK := True; ImportTestCaptureRaise := False;
    ImportTestSnapshot := Default(TImportRiskSnapshot);
    ImportTestSnapshot.Valid := True; ImportTestSnapshot.Total := 4;
    ImportTestSnapshot.RiskDigest := 10; M.Examine(True, False, 1000, D);
    ImportTestSnapshot.PrivateExecutable := 1; ImportTestSnapshot.RiskDigest := 20;
  end;
begin
  Result := False; Failure := ''; Checks := 0; M := nil;
  SavedView := ImportViewHook; SavedRead := ImportReadHook;
  SavedDescribe := ImportDescribeHook; SavedCapture := ImportCaptureHook;
  try
    try
      ImportViewHook := ImportTestGetView; ImportReadHook := ImportTestRead;
      ImportDescribeHook := ImportTestDescribe; ImportTestSetup;
      Check(CaptureImportRisk(S) and S.Valid and (S.Total = 2) and
        (S.PrivateExecutable = 1), 'complete terminated table');
      for I := 0 to 4 do
      begin
        ImportTestSetup; ImportTestPut32($214 + I * 4, 1);
        Check(not CaptureImportRisk(S) and not S.Valid and (S.Total = 0) and
          (S.RiskDigest = 0), 'each nonzero terminator field rejected');
      end;
      ImportTestSetup; ImportTestView.Directory[1].Size := 20;
      Check(not CaptureImportRisk(S) and not S.Valid, 'missing directory terminator');
      ImportTestSetup; ImportTestPut32($210, 0);
      Check(not CaptureImportRisk(S), 'FirstThunk zero in live descriptor rejected');
      ImportTestSetup; ImportTestPut32($20C, $20000);
      Check(not CaptureImportRisk(S), 'DLL-name RVA outside image rejected');
      ImportTestSetup; ImportTestFailAddress := IMPORT_TEST_BASE + $2008;
      Check(not CaptureImportRisk(S) and (S.PrivateExecutable = 0) and
        (S.RiskDigest = 0), 'read failure clears partial risk');
      ImportTestSetup; ImportTestChangeView := True;
      Check(not CaptureImportRisk(S) and not S.Valid, 'directory changed during collection');
      ImportTestSetup; ImportTestView.Directory[1].RVA := 0;
      ImportTestView.Directory[1].Size := 0;
      Check(CaptureImportRisk(S) and S.Valid and (S.Total = 0), 'no-import image remains valid');
      ImportTestView.Directory[1].Size := 40;
      Check(not CaptureImportRisk(S), 'inconsistent zero RVA rejected');
      ImportTestSetup;
      for I := 0 to MAX_IMPORT_SLOTS - 1 do ImportTestPut64($2000 + I * 8, $80000000);
      ImportTestPut64($2000 + MAX_IMPORT_SLOTS * 8, 0);
      Check(CaptureImportRisk(S) and (S.Total = MAX_IMPORT_SLOTS), 'exact slot cap plus terminator');
      ImportTestPut64($2000 + MAX_IMPORT_SLOTS * 8, $80000000);
      Check(not CaptureImportRisk(S) and (S.Total = 0), 'over-limit nonzero slot rejected');
      ImportTestSetup; ImportTestRaise := True; Raised := False;
      try CaptureImportRisk(S); except on E: Exception do Raised := True; end;
      Check(Raised and not S.Valid and (S.RiskDigest = 0), 'exception leaves no published snapshot');
      ImportTestRaise := False; ImportCaptureHook := ImportTestCapture;
      M := TImportRedirectionMonitor.Create; SetupMonitor;
      M.Examine(False, True, 8000, D);
      Check((M.FConfirmations = 1) and (D = []), 'one changed snapshot is candidate');
      ImportTestCaptureOK := False; M.Examine(False, True, 15000, D);
      Check((M.FConfirmations = 0) and M.FPrimed and (M.FInitialRisk = 0), 'failure preserves baseline only');
      ImportTestCaptureOK := True; M.Examine(False, True, 22000, D);
      Check((M.FConfirmations = 1) and (D = []), 'fresh first confirmation after failure');
      M.Examine(False, True, 29000, D);
      Check(dkImportRedirect in D, 'fresh pair detects');
      D := []; M.Examine(False, True, 36000, D);
      Check((D = []) and (M.FConfirmations = 2), 'cooldown and saturation');
      SetupMonitor; M.Examine(False, True, 8000, D); M.Examine(False, True, 39001, D);
      Check((M.FConfirmations = 1) and (D = []), 'old candidate expires');
      SetupMonitor; M.Examine(False, False, 8000, D); M.Examine(False, False, 15000, D);
      Check((M.FConfirmations = 2) and (D = []), 'independent evidence still required');
      SetupMonitor; M.Examine(False, True, 8000, D);
      ImportTestSnapshot.PrivateExecutable := 2; M.Examine(False, True, 15000, D);
      Check((M.FConfirmations = 1) and (D = []), 'risk count participates in candidate identity');
      ImportTestSnapshot.PrivateExecutable := 5; M.Examine(False, True, 22000, D);
      Check(M.FConfirmations = 0, 'impossible private count rejected');
      SetupMonitor; M.Examine(False, True, 8000, D);
      ImportTestSnapshot.Valid := False; M.Examine(False, True, 15000, D);
      Check(M.FConfirmations = 0, 'invalid success clears candidate');
      SetupMonitor; M.Examine(False, True, 8000, D); M.Examine(False, True, 100, D);
      Check((M.FConfirmations = 1) and (D = []), 'rollback starts new candidate');
      SetupMonitor; M.Examine(False, True, 8000, D); M.Examine(False, True, 8000, D);
      Check(M.FConfirmations = 1, 'same tick cannot count twice');
      ImportTestCaptureRaise := True; Raised := False;
      try M.Examine(False, True, 15000, D); except on E: Exception do Raised := True; end;
      Check(Raised and (M.FConfirmations = 0) and (D = []), 'exception clears candidate');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    M.Free; ImportViewHook := SavedView; ImportReadHook := SavedRead;
    ImportDescribeHook := SavedDescribe; ImportCaptureHook := SavedCapture;
    ImportTestData := nil;
  end;
end;
