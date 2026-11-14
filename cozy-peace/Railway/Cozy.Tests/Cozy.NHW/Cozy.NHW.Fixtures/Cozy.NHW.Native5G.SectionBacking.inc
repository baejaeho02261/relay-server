var
  BackingTestFull: TBackingFileIDInfo;
  BackingTestLegacy: BY_HANDLE_FILE_INFORMATION;
  BackingTestFullOK, BackingTestLegacyOK, BackingTestRaise: Boolean;
  BackingTestError: Cardinal;
  BackingTestLegacyCalls: Integer;
function BackingTestID128(Handle: THandle; out Info: TBackingFileIDInfo;
  out Error: Cardinal): Boolean;
begin
  Info := BackingTestFull; Error := BackingTestError;
  Result := BackingTestFullOK and (Handle <> 0);
end;
function BackingTestID64(Handle: THandle;
  out Info: BY_HANDLE_FILE_INFORMATION): Boolean;
begin
  Inc(BackingTestLegacyCalls); Info := BackingTestLegacy;
  Result := BackingTestLegacyOK and (Handle <> 0);
end;
function BackingTestCapture(Module: HMODULE; out Identity: TSectionIdentity): Boolean;
begin
  Identity := Default(TSectionIdentity);
  if BackingTestRaise then raise Exception.Create('synthetic backing capture exception');
  Result := False; // no real filesystem access in this fixture
  if Module = 0 then Exit;
end;
function TestSectionBackingHardening(out Failure: string; out Checks: Integer): Boolean;
var
  A, B, C: TSectionIdentity;
  M: TSectionBackingMonitor;
  D: TDetectionKinds;
  SavedFull: TBackingID128Hook;
  SavedLegacy: TBackingID64Hook;
  SavedCapture: TBackingCaptureHook;
  Raised: Boolean;
  procedure Check(Value: Boolean; const Name: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Name); end;
  procedure Setup;
  begin
    A := Default(TSectionIdentity); A.Valid := True; A.Base := $10000;
    A.MappedNameHash := 123; A.PathFileID := 42; A.FileIDKind := sfkFileID128;
    A.VolumeSerial := $1234567887654321; A.FileID128[0] := 1; A.FileID128[15] := 5;
    B := A; B.FileID128[15] := 6; // intentionally keep the same legacy digest
    D := [];
  end;
  procedure Prime;
  begin
    Setup; M.Reset; M.ObserveIdentity(0, True, True, A, 1000, D);
    M.FLastEvidence := 2000;
  end;
begin
  Result := False; Failure := ''; Checks := 0; M := nil;
  SavedFull := BackingID128Hook; SavedLegacy := BackingID64Hook;
  SavedCapture := BackingCaptureHook;
  try
    try
      Check(SizeOf(TBackingFileIDInfo) = 24, 'Win64 FILE_ID_INFO layout');
      Setup;
      Check(SectionBackingCandidate(A, B, 2, True), 'upper file-ID bytes compared despite identical digest');
      Check(not SectionBackingCandidate(A, B, 1, True), 'two confirmations required');
      Check(not SectionBackingCandidate(A, B, 2, False), 'independent evidence required');
      B := A; B.VolumeSerial := A.VolumeSerial xor (UInt64(1) shl 48);
      Check(SectionBackingCandidate(A, B, 2, True), 'upper volume-serial bits preserved');
      B := A; B.PathFileID := 999;
      Check(not SectionBackingCandidate(A, B, 2, True), 'full identity not replaced by compact digest');
      B := A; Inc(B.MappedNameHash);
      Check(SectionBackingCandidate(A, B, 2, True), 'mapped-name change still included');
      B := A; B.Base := $20000;
      Check(not SectionBackingCandidate(A, B, 2, True), 'different module generation not compared');
      B := A; B.FileIDKind := sfkLegacy64;
      Check(not SectionBackingCandidate(A, B, 2, True), 'precision change is not file replacement');
      B := A; B.Valid := False;
      Check(not SectionBackingCandidate(A, B, 2, True), 'invalid capture cannot report');
      A := Default(TSectionIdentity); A.Valid := True; A.Base := $10000;
      A.PathFileID := 88; B := A; B.PathFileID := 89;
      Check(SectionBackingCandidate(A, B, 2, True), 'old v60 rule fixture compatibility');
      BackingID128Hook := BackingTestID128; BackingID64Hook := BackingTestID64;
      BackingTestFull := Default(TBackingFileIDInfo);
      BackingTestFull.VolumeSerialNumber := $1234567887654321;
      BackingTestFull.Identifier[0] := 3; BackingTestFull.Identifier[15] := 9;
      BackingTestLegacy := Default(BY_HANDLE_FILE_INFORMATION);
      BackingTestLegacy.dwVolumeSerialNumber := 7; BackingTestLegacy.nFileIndexLow := 99;
      BackingTestFullOK := True; BackingTestLegacyOK := True;
      BackingTestLegacyCalls := 0; BackingTestError := 0;
      Check(CaptureBackingFileID(1, C) and (C.FileIDKind = sfkFileID128), 'full-ID path preferred');
      Check((C.VolumeSerial = BackingTestFull.VolumeSerialNumber) and
        (C.FileID128[15] = 9), 'full identity copied without truncation');
      Check(BackingTestLegacyCalls = 0, 'no legacy fallback on success');
      Check(not CaptureBackingFileID(0, C) and (C.PathFileID = 0), 'zero handle rejected with cleared output');
      Check(not CaptureBackingFileID(INVALID_HANDLE_VALUE, C), 'invalid handle rejected');
      BackingTestFullOK := False; BackingTestError := ERROR_ACCESS_DENIED;
      Check(not CaptureBackingFileID(1, C), 'access denied not downgraded');
      Check(BackingTestLegacyCalls = 0, 'access denied never invokes fallback');
      BackingTestError := ERROR_NOT_SUPPORTED;
      Check(CaptureBackingFileID(1, C) and (C.FileIDKind = sfkLegacy64), 'explicitly unsupported format permits tagged fallback');
      Check((C.FileIDFallbackError = ERROR_NOT_SUPPORTED) and (C.LegacyFileIndex = 99) and
        (C.VolumeSerial = 7), 'fallback precision and reason retained');
      BackingTestLegacy.nFileIndexLow := 0;
      Check(not CaptureBackingFileID(1, C), 'legacy zero sentinel rejected');
      BackingTestLegacy.nFileIndexLow := High(Cardinal);
      BackingTestLegacy.nFileIndexHigh := High(Cardinal);
      Check(not CaptureBackingFileID(1, C), 'legacy all-ones sentinel rejected');
      BackingTestLegacy.nFileIndexLow := 99; BackingTestLegacy.nFileIndexHigh := 0;
      BackingTestLegacyOK := False;
      Check(not CaptureBackingFileID(1, C) and (C.FileIDKind = sfkUnspecified), 'failed fallback does not publish partial identity');
      Check(BackingIDUnsupported(ERROR_INVALID_FUNCTION), 'unsupported invalid function');
      Check(BackingIDUnsupported(ERROR_INVALID_PARAMETER), 'older-provider invalid parameter fallback');
      Check(BackingIDUnsupported(ERROR_CALL_NOT_IMPLEMENTED), 'absent API fallback');
      Check(not BackingIDUnsupported(ERROR_INVALID_HANDLE), 'bad handle not compatibility fallback');
      M := TSectionBackingMonitor.Create;
      Prime; M.ObserveIdentity(0, True, False, B, 2000, D);
      Check(M.FConfirmations[0] = 1, 'first change stored');
      M.ObserveIdentity(0, True, False, B, 2000, D);
      Check(M.FConfirmations[0] = 1, 'same tick does not confirm');
      M.ObserveIdentity(0, True, False, B, 3000, D);
      Check(dkSectionBacking in D, 'second full identity confirms');
      Prime; M.ObserveIdentity(0, True, False, B, 2000, D);
      M.ObserveIdentity(0, False, False, B, 3000, D);
      Check((M.FConfirmations[0] = 0) and not M.FPending[0].Valid, 'capture failure clears candidate');
      Check(SameBackingIdentity(M.FBaseline[0], A), 'capture failure preserves approved baseline');
      M.ObserveIdentity(0, True, False, B, 4000, D);
      Check((M.FConfirmations[0] = 1) and not (dkSectionBacking in D), 'recovery requires fresh confirmation');
      Prime; M.ObserveIdentity(0, True, False, B, 2000, D);
      C := B; C.FileID128[14] := 7; M.ObserveIdentity(0, True, False, C, 3000, D);
      Check(M.FConfirmations[0] = 1, 'different full candidate with identical hash cannot accumulate');
      Prime; M.ObserveIdentity(0, True, False, B, 2000, D);
      M.FLastEvidence := 47000; M.ObserveIdentity(0, True, False, B, 47000, D);
      Check(dkSectionBacking in D, 'exact 45-second lifetime allowed');
      Prime; M.ObserveIdentity(0, True, False, B, 2000, D);
      M.FLastEvidence := 47001; M.ObserveIdentity(0, True, False, B, 47001, D);
      Check((M.FConfirmations[0] = 1) and not (dkSectionBacking in D), 'expired candidate starts at one');
      Prime; M.ObserveIdentity(0, True, False, B, 2000, D);
      M.ObserveIdentity(0, True, False, B, 100, D);
      Check((M.FConfirmations[0] = 1) and not (dkSectionBacking in D), 'rollback cannot reuse confirmations');
      Prime; M.ObserveIdentity(0, True, False, B, 2000, D);
      C := B; C.FileIDKind := sfkLegacy64; M.ObserveIdentity(0, True, False, C, 3000, D);
      Check((M.FConfirmations[0] = 0) and (M.FBaseline[0].FileIDKind = sfkFileID128), 'fallback cannot overwrite strong baseline');
      Prime; M.ObserveIdentity(0, True, False, B, 2000, D);
      M.ObserveIdentity(0, True, False, A, 3000, D);
      Check(M.FConfirmations[0] = 0, 'return to baseline clears');
      Prime; M.ObserveIdentity(0, True, False, B, 2000, D);
      M.ObserveIdentity(0, True, True, B, 3000, D);
      Check((M.FConfirmations[0] = 0) and SameBackingIdentity(M.FBaseline[0], B), 'explicit baseline update preserved');
      Prime; M.ObserveIdentity(0, True, False, B, 2000, D);
      BackingCaptureHook := BackingTestCapture; BackingTestRaise := True; Raised := False;
      try M.Examine(False, True, 13000, D); except on E: Exception do Raised := True; end;
      Check(Raised, 'capture exception propagates');
      Check(M.FConfirmations[0] = 0, 'capture exception invalidates pending evidence');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    M.Free; BackingID128Hook := SavedFull; BackingID64Hook := SavedLegacy;
    BackingCaptureHook := SavedCapture;
  end;
end;
