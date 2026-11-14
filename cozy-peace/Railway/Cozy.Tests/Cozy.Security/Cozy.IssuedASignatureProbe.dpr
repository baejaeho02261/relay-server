program Cozy_IssuedASignatureProbe;
{$APPTYPE CONSOLE}
{$R+}{$Q+}
{$IFNDEF GAME_ISSUED_A_TESTS}
  {$MESSAGE FATAL 'Build this isolated probe with GAME_ISSUED_A_TESTS.'}
{$ENDIF}
uses
{ Cozy central text imports. }
  Cozy.Strings.Application in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Application.pas',
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.Security in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Security.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}
  Cozy.Strings.TestsSecurity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsSecurity.pas',

  System.SysUtils, System.Classes, System.JSON, System.NetEncoding,
  Cozy.IssuedA, Cozy.Security, Cozy.Api.Pointer;
var Passed: Integer;

procedure Require(Value: Boolean; const Code: string);
begin
  if not Value then raise EInvalidOpException.Create(Code);
end;

function Decode(Obj: TJSONObject; const Name: string; Maximum: Integer): TBytes;
var Value: TJSONValue; Encoding: TBase64Encoding; Text: string;
begin
  Result := nil;
  Value := Obj.GetValue(Name);
  Require(Value is TJSONString, CozyText_IssuedASignatureProbe_FIXTURE_FIELD_TYPE_90203a23);
  Text := Value.Value;
  Require((Length(Text) > 0) and (Length(Text) <= ((Maximum + 2) div 3) * 4), CozyText_IssuedASignatureProbe_FIXTURE_FIELD_LIMIT_da34b2e4);
  Encoding := TBase64Encoding.Create(0);
  try
    Result := Encoding.DecodeStringToBytes(Text);
    Require((Length(Result) > 0) and (Length(Result) <= Maximum) and
      (Encoding.EncodeBytesToString(Result) = Text), CozyText_IssuedASignatureProbe_FIXTURE_BASE64_a0216ad1);
  finally
    Encoding.Free;
    WipeText(Text);
  end;
end;

procedure Check(const Bytes, Anchor, Expected: TBytes; Accepted: Boolean;
  SizeAdjustment: Integer = 0);
var Stream: TMemoryStream; Config: TBytes; Rejected: Boolean; Original: Int64;
begin
  Stream := TMemoryStream.Create;
  try
    if Length(Bytes) <> 0 then Stream.WriteBuffer(Bytes[0], Length(Bytes));
    Original := 7;
    if Original > Stream.Size then Original := Stream.Size;
    Stream.Position := Original;
    Rejected := False;
    try
      Config := VerifyIssuedATestStream(Stream, UInt64(Length(Bytes) + SizeAdjustment), Anchor);
    except
      on E: EIssuedA do Rejected := True;
      on E: EReadError do Rejected := True;
    end;
    Require(Stream.Position = Original, CozyText_IssuedASignatureProbe_PINNED_STREAM_POSITION_NOT_RESTORED_d8057d13);
    Require(Rejected <> Accepted, CozyText_IssuedASignatureProbe_ISSUED_A_ACCEPTANCE_MISMATCH_974b42af);
    if Accepted then
      Require((Length(Config) = Length(Expected)) and
        CompareMem(@Config[0], @Expected[0], Length(Expected)), CozyText_IssuedASignatureProbe_ISSUED_A_CONFIG_MISMATCH_6ed86787);
    Inc(Passed);
  finally
    WipeBytes(Config);
    Stream.Free;
  end;
end;

procedure Run;
var FileStream: TFileStream; Raw, FinalBytes, Anchor, Config, Mutated, WrongAnchor: TBytes;
  Text: string; Parsed: TJSONValue; Obj: TJSONObject; TemplateBytes, HeaderAt, I: Integer;
  procedure Change(Offset: Integer);
  begin
    Mutated := Copy(FinalBytes, 0, Length(FinalBytes));
    try
      Mutated[Offset] := Mutated[Offset] xor 1;
      Check(Mutated, Anchor, Config, False);
    finally WipeBytes(Mutated); end;
  end;
begin
  Require(ParamCount = 1, CozyText_IssuedASignatureProbe_USAGE_PROBE_PUBLIC_VECTOR_JSON_4a4c04e2);
  Parsed := nil;
  FileStream := TFileStream.Create(ParamStr(1), fmOpenRead or fmShareDenyWrite);
  try
    Require((FileStream.Size > 0) and (FileStream.Size <= 65536), CozyText_IssuedASignatureProbe_FIXTURE_FILE_LIMIT_fd934ad9);
    SetLength(Raw, Integer(FileStream.Size));
    FileStream.ReadBuffer(Raw[0], Length(Raw));
  finally FileStream.Free; end;
  try
    Text := TEncoding.UTF8.GetString(Raw);
    Parsed := TJSONObject.ParseJSONValue(Text);
    Require(Parsed is TJSONObject, CozyText_IssuedASignatureProbe_FIXTURE_OBJECT_5ccc249d);
    Obj := TJSONObject(Parsed);
    Require(Obj.GetValue(CozyText_IssuedASignatureProbe_scope_63ff8b96).Value = CozyText_IssuedASignatureProbe_SYNTHETIC_PUBLIC_ONLY_NATIVE_CNG_VECTOR_08a722cb, CozyText_IssuedASignatureProbe_FIXTURE_SCOPE_c20c676c);
    Anchor := Decode(Obj, CozyText_IssuedASignatureProbe_anchorBase64_2ac006fc, 331);
    Config := Decode(Obj, CozyText_IssuedASignatureProbe_configBase64_eec8c0ff, 8192);
    FinalBytes := Decode(Obj, CozyText_IssuedASignatureProbe_finalBase64_33d3410d, 32768);
    Require(Length(Anchor) = 331, CozyText_IssuedASignatureProbe_FIXTURE_ANCHOR_LENGTH_e8406212);
    TemplateBytes := StrToInt(Obj.GetValue(CozyText_IssuedASignatureProbe_templateBytes_42bf8f32).Value);
    HeaderAt := Length(FinalBytes) - 453;
    Require((TemplateBytes >= 512) and (TemplateBytes + Length(Config) = HeaderAt), CozyText_IssuedASignatureProbe_FIXTURE_LENGTHS_17119bed);
    Check(FinalBytes, Anchor, Config, True);
    Check(FinalBytes, Anchor, Config, True); { independent CNG provider/key cleanup }
    Check(FinalBytes, Anchor, Config, False, 1);
    Change(0); Change(TemplateBytes - 1); Change(TemplateBytes);
    Change(HeaderAt - 1); Change(HeaderAt); Change(HeaderAt + 15);
    Change(HeaderAt + 16); Change(HeaderAt + 20); Change(HeaderAt + 24);
    Change(HeaderAt + 56); Change(HeaderAt + 120); Change(HeaderAt + 184);
    Change(HeaderAt + 439); Change(HeaderAt + 440); Change(Length(FinalBytes) - 1);
    { Every truncated tail length, plus no tail, must fail without reading
      beyond the file or leaving the stream at a changed position. }
    for I := 1 to 453 do
    begin
      Mutated := Copy(FinalBytes, 0, Length(FinalBytes) - I);
      try Check(Mutated, Anchor, Config, False); finally WipeBytes(Mutated); end;
    end;
    Mutated := Copy(FinalBytes, 0, Length(FinalBytes));
    try
      SetLength(Mutated, Length(Mutated) + 1);
      Mutated[High(Mutated)] := 0;
      Check(Mutated, Anchor, Config, False); { unsigned trailing byte }
    finally WipeBytes(Mutated); end;
    WrongAnchor := Copy(Anchor, 0, Length(Anchor));
    try
      WrongAnchor[16] := WrongAnchor[16] xor 1;
      Check(FinalBytes, WrongAnchor, Config, False);
      WrongAnchor[16] := WrongAnchor[16] xor 1;
      WrongAnchor[48 + 27] := WrongAnchor[48 + 27] xor 1;
      Check(FinalBytes, WrongAnchor, Config, False);
      FillChar(WrongAnchor[16], Length(WrongAnchor) - 16, 0);
      Check(FinalBytes, WrongAnchor, Config, False); { unconfigured anchor }
    finally WipeBytes(WrongAnchor); end;
    Mutated := Copy(FinalBytes, 0, Length(FinalBytes));
    try
      for I := HeaderAt + 16 to HeaderAt + 23 do Mutated[I] := $FF;
      Check(Mutated, Anchor, Config, False); { unsigned 32-bit length overflow }
    finally WipeBytes(Mutated); end;
    Writeln(CozyText_IssuedASignatureProbe_JsonFixture_7365886b,
      CozyText_IssuedASignatureProbe_actualNativeExecuted_true_cases_5689bbfa, Passed,
      CozyText_IssuedASignatureProbe_wholeAboExecution_NOT_RUN_authenticode_false_3f80993f);
  finally
    Parsed.Free;
    WipeText(Text); WipeBytes(Raw); WipeBytes(FinalBytes);
    WipeBytes(Anchor); WipeBytes(Config); WipeBytes(Mutated); WipeBytes(WrongAnchor);
  end;
end;
begin
  try
    SealApiPointerStorage;
    Run;
  except
    on E: Exception do
    begin
      Writeln(CozyText_IssuedASignatureProbe_JsonFixture_576ee6b1);
      Writeln(ErrOutput, E.ClassName, CozyText_IssuedASignatureProbe_Text_8a9b1928, E.Message);
      ExitCode := 1;
    end;
  end;
end.
