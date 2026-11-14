var
  TestETWPayload: TBytes;
  TestETWMode, TestETWSizeCalls, TestETWReadCalls: Integer;

function TestPropertySize(Rec: PEtwEventRecord; ContextCount: Cardinal;
  Context: Pointer; PropertyCount: Cardinal; PropertyDescriptor: Pointer;
  var Required: Cardinal): Cardinal; stdcall;
begin
  Inc(TestETWSizeCalls);
  Required := Cardinal(Length(TestETWPayload));
  case TestETWMode of
    1: Exit(ERROR_NOT_FOUND);
    2: Required := 4097;
    4: if TestETWSizeCalls = 1 then Required := 2;
  end;
  Result := 0;
end;
function TestReadProperty(Rec: PEtwEventRecord; ContextCount: Cardinal;
  Context: Pointer; PropertyCount: Cardinal; PropertyDescriptor: Pointer;
  BufferSize: Cardinal; Buffer: PByte): Cardinal; stdcall;
begin
  Inc(TestETWReadCalls);
  if TestETWMode = 3 then
  begin
    Buffer^ := 123;
    Exit(ERROR_ACCESS_DENIED);
  end;
  if (TestETWMode = 5) or (BufferSize < Cardinal(Length(TestETWPayload))) then
    Exit(ERROR_INSUFFICIENT_BUFFER);
  if Length(TestETWPayload) <> 0 then
    Move(TestETWPayload[0], Buffer^, Length(TestETWPayload));
  Result := 0;
end;

function TestETWNativeHardening(out Failure: string; out Checks: Integer): Boolean;
var
  SavedSize: TTdhGetPropertySize;
  SavedRead: TTdhGetProperty;
  Rec: TEtwEventRecord;
  PayloadByte: Byte;
  B: TBytes;
  S: string;
  V: Cardinal;
  Wide: UInt64;
  procedure Check(Value: Boolean; const Name: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Name);
  end;
  procedure Mode(Value: Integer);
  begin
    TestETWMode := Value; TestETWSizeCalls := 0; TestETWReadCalls := 0;
  end;
  procedure TextBytes(const Text: string);
  begin
    SetLength(B, Length(Text) * 2);
    if Length(B) <> 0 then Move(PWideChar(Text)^, B[0], Length(B));
  end;
begin
  Checks := 0; Failure := ''; Result := False;
  SavedSize := EtwPropertySize; SavedRead := EtwGetProperty;
  try
    try
      EtwPropertySize := TestPropertySize;
      EtwGetProperty := TestReadProperty;
      Rec := Default(TEtwEventRecord);
      Rec.Header.Size := SizeOf(TEtwHeader);
      PayloadByte := 0; Rec.UserData := @PayloadByte; Rec.UserDataLength := 1;
      Check(EtwAbiValid, 'ETW Win64 layouts');
      Check(EtwRecordValid(@Rec), 'valid record envelope');
      Check(not EtwRecordValid(nil), 'nil record');
      Rec.Header.Size := 1; Check(not EtwRecordValid(@Rec), 'short header');
      Rec.Header.Size := SizeOf(TEtwHeader);
      Rec.UserData := nil; Check(not EtwRecordValid(@Rec), 'missing payload');
      Rec.UserData := @PayloadByte;
      Rec.ExtendedDataCount := 1; Check(not EtwRecordValid(@Rec), 'missing extended data');
      Rec.ExtendedDataCount := 0;
      Mode(0); SetLength(TestETWPayload, 4); V := 123;
      Move(V, TestETWPayload[0], 4);
      Check(ReadEtwUInt(@Rec, 'ProcessId', V) and (V = 123), 'DWORD property');
      SetLength(TestETWPayload, 8); Wide := UInt64(High(Cardinal));
      Move(Wide, TestETWPayload[0], 8);
      Check(ReadEtwUInt(@Rec, 'ProcessId', V) and (V = High(Cardinal)), 'bounded QWORD');
      Inc(Wide); Move(Wide, TestETWPayload[0], 8);
      Check(not ReadEtwUInt(@Rec, 'ProcessId', V) and (V = 0), 'QWORD truncation rejected');
      SetLength(TestETWPayload, 2);
      Check(not ReadEtwUInt(@Rec, 'ProcessId', V), 'wrong integer width');
      TestETWPayload := nil;
      Check(not ReadEtwBytes(@Rec, 'P', B) and (Length(B) = 0), 'zero required length');
      SetLength(TestETWPayload, 4);
      Mode(1); Check(not ReadEtwBytes(@Rec, 'P', B), 'missing property');
      Mode(2); Check(not ReadEtwBytes(@Rec, 'P', B) and (TestETWReadCalls = 0), 'property cap');
      Mode(3); Check(not ReadEtwBytes(@Rec, 'P', B) and (Length(B) = 0), 'partial property discarded');
      Mode(4); Check(ReadEtwBytes(@Rec, 'P', B) and (Length(B) = 4), 'requery size after insufficient buffer');
      Check((TestETWSizeCalls = 2) and (TestETWReadCalls = 2), 'one property retry');
      Mode(5); Check(not ReadEtwBytes(@Rec, 'P', B) and (Length(B) = 0), 'repeated size failure');
      Check(TestETWReadCalls = 2, 'property retry cap');
      Mode(0); Check(not ReadEtwBytes(@Rec, '', B), 'empty property name');
      Check(not ReadEtwBytes(@Rec, 'P' + #0 + 'X', B), 'NUL property name');
      Check(not ReadEtwBytes(@Rec, StringOfChar('P', 1025), B), 'property name length cap');
      Check(TestETWSizeCalls = 0, 'invalid names never passed to TDH');
      TextBytes('AB'); Check(DecodeEtwText(B, S) and (S = 'AB'), 'bounded unterminated text');
      TextBytes('AB' + #0); Check(DecodeEtwText(B, S) and (S = 'AB'), 'terminated text');
      TextBytes('AB' + #0 + #0); Check(DecodeEtwText(B, S) and (S = 'AB'), 'zero padding');
      TextBytes('A' + #0 + 'B'); Check(not DecodeEtwText(B, S) and (S = ''), 'nonzero tail rejected');
      TextBytes(WideChar($D800)); Check(not DecodeEtwText(B, S), 'unpaired high surrogate');
      TextBytes(WideChar($DC00)); Check(not DecodeEtwText(B, S), 'unpaired low surrogate');
      TextBytes(string(WideChar($D800)) + string(WideChar($DC00))); Check(DecodeEtwText(B, S), 'valid surrogate pair');
      SetLength(B, 3); Check(not DecodeEtwText(B, S), 'odd text bytes');
      TextBytes(StringOfChar('A', 2048)); Check(DecodeEtwText(B, S), 'maximum text length');
      TextBytes(StringOfChar('A', 2049)); Check(not DecodeEtwText(B, S), 'text cap');
      TextBytes(#0); Check(not DecodeEtwText(B, S), 'empty text remains unavailable');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    EtwPropertySize := SavedSize;
    EtwGetProperty := SavedRead;
    TestETWPayload := nil;
  end;
end;
