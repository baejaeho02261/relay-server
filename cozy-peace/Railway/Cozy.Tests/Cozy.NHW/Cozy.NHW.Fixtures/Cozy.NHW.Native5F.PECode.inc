// Compile only through NHW.Native5F.Tests.dproj. Synthetic readable image;
// no real module contents, permissions, debugger state or foreign memory changed.
const CODE_TEST_BASE = NativeUInt($1000000);
var
  CodeTestHeader: array[0..4095] of Byte;
  CodeTestBytes: Cardinal;
  CodeTestValue: Byte;
  CodeTestFail, CodeTestRaise, CodeTestPresent: Boolean;

procedure CodeTestPut16(Offset: Integer; Value: Word);
begin Move(Value, CodeTestHeader[Offset], SizeOf(Value)); end;
procedure CodeTestPut32(Offset: Integer; Value: Cardinal);
begin Move(Value, CodeTestHeader[Offset], SizeOf(Value)); end;
procedure CodeTestSetup(Bytes: Cardinal);
begin
  FillChar(CodeTestHeader, SizeOf(CodeTestHeader), 0);
  CodeTestBytes := Bytes;
  CodeTestValue := $90;
  CodeTestFail := False; CodeTestRaise := False; CodeTestPresent := True;
  CodeTestPut16(0, $5A4D); CodeTestPut32($3C, $80);
  CodeTestPut32($80, $4550); CodeTestPut16($84, $8664);
  CodeTestPut16($86, 1); CodeTestPut32($88, 123);
  CodeTestPut16($94, $F0); CodeTestPut16($98, $20B);
  CodeTestPut32($D0, $1000 + Bytes);
  CodeTestPut32($188 + 8, Bytes); CodeTestPut32($188 + 12, $1000);
  CodeTestPut32($188 + 16, Bytes); CodeTestPut32($188 + 36, $60000020);
end;
function CodeTestRead(Address: NativeUInt; var Dest; Bytes: NativeUInt): Boolean;
var Offset: NativeUInt;
begin
  Result := False;
  if Address < CODE_TEST_BASE then Exit;
  Offset := Address - CODE_TEST_BASE;
  if NHWBufferSpan(SizeOf(CodeTestHeader), Offset, Bytes) then
  begin Move(CodeTestHeader[Offset], Dest, Bytes); Exit(True); end;
  if CodeTestRaise then raise Exception.Create('synthetic code read exception');
  if CodeTestFail or (Offset < $1000) then Exit;
  if not NHWBufferSpan(CodeTestBytes, Offset - $1000, Bytes) then Exit;
  FillChar(Dest, Bytes, CodeTestValue);
  Result := True;
end;
function CodeTestModule(Index: Integer): HMODULE;
begin
  if (Index = 0) and CodeTestPresent then Result := HMODULE(CODE_TEST_BASE)
  else Result := 0;
end;
function TestPECodeHardening(out Failure: string; out Checks: Integer): Boolean;
var
  SavedRead: TCodeReadHook; SavedModule: TCodeModuleHook;
  P: TCodeScanProgress; A, B: TCodeImageDigest;
  R: TCodeScanResult; Restarted, Raised: Boolean;
  M: TPECodeIntegrityMonitor; D: TDetectionKinds;
  I: Integer; BaseHash: UInt64;
  procedure Check(Value: Boolean; const Name: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Name); end;
  procedure SetupMonitor;
  begin
    CodeTestSetup($1000); M.Reset; D := [];
    M.Examine(True, 1000, D); M.Examine(True, 7000, D);
  end;
begin
  Failure := ''; Checks := 0; Result := False; M := nil;
  SavedRead := CodeReadHook; SavedModule := CodeModuleHook;
  try
    try
      CodeReadHook := CodeTestRead; CodeModuleHook := CodeTestModule;
      CodeTestSetup($1000);
      Check(not CaptureExecutableCodeDigest(0, A) and not A.Valid, 'nil module rejected');
      Check(CaptureExecutableCodeDigest(HMODULE(CODE_TEST_BASE), A) and A.Valid,
        'complete synthetic digest');
      Check((A.BytesHashed = $1000) and (A.SectionCount = 1), 'exact byte scope');
      P := Default(TCodeScanProgress);
      R := AdvanceCodeDigest(HMODULE(CODE_TEST_BASE), 600, P, B, Restarted);
      Check((R = csrPending) and not B.Valid and (P.BytesHashed = 600), 'partial not published');
      for I := 1 to 6 do R := AdvanceCodeDigest(HMODULE(CODE_TEST_BASE), 600, P, B, Restarted);
      Check((R = csrComplete) and B.Valid and (A.Value = B.Value), 'segmented equals complete');
      Check(not P.Active, 'completed progress released');
      P := Default(TCodeScanProgress);
      R := AdvanceCodeDigest(HMODULE(CODE_TEST_BASE), 0, P, B, Restarted);
      Check((R = csrFailed) and not B.Valid and not P.Active, 'zero budget rejected');
      R := AdvanceCodeDigest(HMODULE(CODE_TEST_BASE), 600, P, B, Restarted);
      CodeTestFail := True;
      R := AdvanceCodeDigest(HMODULE(CODE_TEST_BASE), 600, P, B, Restarted);
      Check((R = csrFailed) and not B.Valid and (B.BytesHashed = 0), 'partial read discarded');
      Check(not P.Active and (P.Hash = 0), 'failed progress cleared');
      CodeTestFail := False;
      R := AdvanceCodeDigest(HMODULE(CODE_TEST_BASE), 600, P, B, Restarted);
      CodeTestPut32($88, 124);
      R := AdvanceCodeDigest(HMODULE(CODE_TEST_BASE), 600, P, B, Restarted);
      Check(Restarted and (R = csrPending) and (P.BytesHashed = 600), 'layout change restarts pass');
      CodeTestSetup($1000); CodeTestPut16($84, $14C);
      Check(not CaptureExecutableCodeDigest(HMODULE(CODE_TEST_BASE), A), 'wrong machine rejected');
      CodeTestSetup($1000); CodeTestPut16($86, 65);
      Check(not CaptureExecutableCodeDigest(HMODULE(CODE_TEST_BASE), A), 'section cap enforced');
      CodeTestSetup($1000); CodeTestPut32($188 + 12, $1FFF);
      Check(not CaptureExecutableCodeDigest(HMODULE(CODE_TEST_BASE), A), 'out of image bytes rejected');
      CodeTestSetup($1000); CodeTestPut32($188 + 36, $E0000020);
      Check(not CaptureExecutableCodeDigest(HMODULE(CODE_TEST_BASE), A), 'writable code scope unchanged');
      CodeTestSetup(25 * 1024 * 1024); P := Default(TCodeScanProgress);
      R := AdvanceCodeDigest(HMODULE(CODE_TEST_BASE), CODE_SCAN_BUDGET, P, B, Restarted);
      Check((R = csrPending) and (P.BytesHashed = CODE_SCAN_BUDGET), '>24MiB first bounded pass');
      R := AdvanceCodeDigest(HMODULE(CODE_TEST_BASE), CODE_SCAN_BUDGET, P, B, Restarted);
      Check((R = csrComplete) and B.Valid and (B.BytesHashed = 25 * 1024 * 1024), 'tail beyond 24MiB covered');
      Check(CaptureExecutableCodeDigest(HMODULE(CODE_TEST_BASE), A) and
        (A.Value = B.Value), 'large complete/segmented digests match');
      M := TPECodeIntegrityMonitor.Create; SetupMonitor;
      Check(M.FCells[0].Stable and M.FCells[0].Primed, 'two complete startup observations');
      BaseHash := M.FCells[0].BaselineDigest;
      CodeTestValue := $91; M.Examine(False, 13000, D);
      Check((M.FCells[0].PendingCount = 1) and (D = []), 'one changed complete pass');
      CodeTestFail := True; M.Examine(False, 19000, D);
      Check((M.FCells[0].PendingCount = 0) and
        (M.FCells[0].BaselineDigest = BaseHash), 'failure clears candidate preserves baseline');
      CodeTestFail := False; M.Examine(False, 25000, D);
      Check((M.FCells[0].PendingCount = 1) and (D = []), 'recovery starts first confirmation');
      M.Examine(False, 31000, D);
      Check(dkPECodeIntegrity in D, 'fresh matching pair detects');
      D := []; M.Examine(False, 37000, D);
      Check((D = []) and (M.FCells[0].PendingCount = 2), 'bounded counter and cooldown');
      SetupMonitor; CodeTestValue := $91; M.Examine(False, 13000, D);
      CodeTestValue := $90; M.Examine(False, 19000, D);
      Check((M.FCells[0].PendingCount = 0) and (D = []), 'return to baseline clears');
      CodeTestValue := $91; M.Examine(False, 25000, D); M.Examine(True, 31000, D);
      Check((M.FCells[0].PendingCount = 0) and (D = []), 'explicit baseline does not report');
      SetupMonitor; CodeTestValue := $91; M.Examine(False, 13000, D);
      CodeTestRaise := True; Raised := False;
      try M.Examine(False, 19000, D); except on E: Exception do Raised := True; end;
      Check(Raised and (M.FCells[0].PendingCount = 0) and (D = []), 'exception clears before engine handling');
      CodeTestRaise := False; M.Examine(False, 25000, D);
      M.Examine(False, 10, D);
      Check((M.FCells[0].PendingCount = 1) and (D = []), 'clock rollback does not reuse confirmation');
      CodeTestPresent := False; M.Examine(False, 6010, D);
      Check(not M.FCells[0].Primed and not M.FProgress[0].Active, 'missing module invalidates state');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally M.Free; CodeReadHook := SavedRead; CodeModuleHook := SavedModule; end;
end;
