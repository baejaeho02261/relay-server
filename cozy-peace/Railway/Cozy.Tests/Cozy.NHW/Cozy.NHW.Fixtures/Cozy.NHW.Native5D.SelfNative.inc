// Real local heap ranges, synthetic PE/PEB data; no live code is patched.
var
  SelfTestBasicMode: Integer;
  SelfTestPeb: array[0..63] of Byte;
  SelfTestParameters: TParametersPrefix;
function SelfTestBasicQuery(ProcessHandle: THandle; InformationClass: Cardinal;
  Info: Pointer; InfoLength: Cardinal; ReturnLength: PCardinal): LongInt; stdcall;
var B: TProcessBasicX64;
begin
  B := Default(TProcessBasicX64);
  B.PebBaseAddress := @SelfTestPeb[0];
  B.UniqueProcessId := NativeUInt(WinCurrentProcessId);
  if SelfTestBasicMode = 4 then Inc(B.UniqueProcessId);
  if SelfTestBasicMode = 5 then B.PebBaseAddress := Pointer(High(NativeUInt) - 8);
  Move(B, Info^, SizeOf(B));
  ReturnLength^ := SizeOf(B);
  case SelfTestBasicMode of
    1: ReturnLength^ := 0;
    2: ReturnLength^ := SizeOf(B) - 1;
    3: ReturnLength^ := SizeOf(B) + 1;
  end;
  if SelfTestBasicMode = 6 then Result := -1 else Result := 0;
end;
function TestSelfNativeHardening(out Failure: string; out Checks: Integer): Boolean;
var
  SavedQuery: TNtQueryInformationProcess; SavedResolved: Boolean;
  Image: TBytes; W, N: TArray<NativeUInt>;
  Base, Opt, ImportBase: NativeUInt;
  Digest: UInt64; Entries: Cardinal; Valid: Boolean; I: Integer;
  U: TUnicodeString64;
  procedure Check(Value: Boolean; const Name: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Name); end;
  procedure BuildImage;
  begin
    SetLength(Image, $5000); FillChar(Image[0], Length(Image), 0);
    Base := NativeUInt(@Image[0]); Opt := Base + $80 + 24; ImportBase := Base + $200;
    PWord(Pointer(Base))^ := DOS_SIGNATURE;
    PCardinal(Pointer(Base + $3C))^ := $80;
    PCardinal(Pointer(Base + $80))^ := PE_SIGNATURE;
    PWord(Pointer(Base + $80 + 20))^ := 240;
    PWord(Pointer(Opt))^ := PE64_MAGIC;
    PCardinal(Pointer(Opt + 56))^ := $5000;
    PCardinal(Pointer(Opt + 108))^ := 16;
    PCardinal(Pointer(Opt + 120))^ := $200;
    PCardinal(Pointer(Opt + 124))^ := 40;
    PCardinal(Pointer(ImportBase + 16))^ := $1000;
    PUInt64(Pointer(Base + $1000))^ := $12345678;
  end;
  procedure ExpectBadIAT(const Name: string);
  begin
    Digest := 99; Entries := 99;
    Check(not CaptureIATAtBase(Base, Digest, Entries), Name);
    Check((Digest = 0) and (Entries = 0), Name + ' zero outputs');
  end;
begin
  Result := False; Failure := ''; Checks := 0;
  SavedQuery := QueryProcessPtr; SavedResolved := ProcessResolved;
  try
    try
      Check(not RangePresent(11, 1, 10), 'RVA beyond image');
      Check(RangePresent(10, 0, 10), 'empty end span');
      Check(not ReadableRange(High(NativeUInt) - 1, 8), 'address wrap rejected');
      BuildImage;
      Check(CaptureIATAtBase(Base, Digest, Entries), 'valid synthetic IAT');
      Check((Entries = 1) and (Digest <> 0), 'complete IAT committed');
      PCardinal(Pointer(ImportBase + 20 + 12))^ := $333;
      ExpectBadIAT('nonzero terminating descriptor');
      BuildImage; PCardinal(Pointer(Opt + 124))^ := 20;
      ExpectBadIAT('missing terminator after partial count');
      BuildImage; PCardinal(Pointer(Opt + 108))^ := 17;
      ExpectBadIAT('directory count exceeds optional header');
      BuildImage; PWord(Pointer(Opt))^ := $10B;
      ExpectBadIAT('PE32 rejected');
      BuildImage; PCardinal(Pointer(ImportBase + 16))^ := $5000;
      ExpectBadIAT('out of image thunk');
      BuildImage;
      for I := 0 to 1023 do PUInt64(Pointer(Base + $1000 + NativeUInt(I) * 8))^ := 1;
      ExpectBadIAT('unterminated thunk list');
      BuildImage; PUInt64(Pointer(Base + $1000))^ := 0;
      ExpectBadIAT('no IAT entries');
      SetLength(W, 11); SetLength(N, 3);
      for I := 0 to High(W) do W[I] := NativeUInt(@StartFingerprint);
      for I := 0 to High(N) do N[I] := 0;
      Check(FingerprintFunctionArrays(W, N, Digest, Valid), 'complete function array');
      Check(Valid, 'own image targets executable');
      W[High(W)] := 0; Digest := 99; Valid := True;
      Check(not FingerprintFunctionArrays(W, N, Digest, Valid), 'late null required pointer');
      Check((Digest = 0) and not Valid, 'failed pointer array has no partial success');
      W[High(W)] := 1;
      Check(FingerprintFunctionArrays(W, N, Digest, Valid), 'observed invalid address is evidence');
      Check(not Valid, 'invalid target differs from unavailable collection');
      SetLength(W, 8);
      Digest := 99; Valid := True;
      Check(not FingerprintFunctionArrays(W, N, Digest, Valid), 'short total pointer count');
      Check((Digest = 0) and not Valid, 'short function array clears outputs');
      U := Default(TUnicodeString64); U.Length := 1; U.MaximumLength := 2;
      Check(not ReadUnicodeFingerprint(U, Digest), 'odd unicode length');
      U.Length := 0; U.MaximumLength := 1;
      Check(not ReadUnicodeFingerprint(U, Digest), 'odd maximum unicode length');
      U := Default(TUnicodeString64);
      Check(ReadUnicodeFingerprint(U, Digest), 'empty unicode supported');
      FillChar(SelfTestPeb, SizeOf(SelfTestPeb), 0);
      SelfTestParameters := Default(TParametersPrefix);
      PPointer(@SelfTestPeb[$20])^ := @SelfTestParameters;
      ProcessResolved := True; QueryProcessPtr := SelfTestBasicQuery;
      for I := 1 to 6 do
      begin
        SelfTestBasicMode := I; Digest := 99;
        Check(not CaptureProcessParameters(Digest), 'incomplete/mismatched basic info');
        Check(Digest = 0, 'basic info failure clears digest');
      end;
      SelfTestBasicMode := 0;
      Check(CaptureProcessParameters(Digest), 'complete synthetic process parameters');
      Check(Digest <> 0, 'parameter digest committed');
      SelfTestParameters.CommandLine.Length := 2;
      SelfTestParameters.CommandLine.MaximumLength := 2;
      SelfTestParameters.CommandLine.Buffer := nil;
      Digest := 99;
      Check(not CaptureProcessParameters(Digest), 'invalid command line after valid image name');
      Check(Digest = 0, 'parameter partial digest never escapes');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    QueryProcessPtr := SavedQuery; ProcessResolved := SavedResolved;
  end;
end;
