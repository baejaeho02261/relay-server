program Cozy_FloatJsonProbe;
{ Manual Win64 test only. Input: one UTF-8 JSON object per line. Output: one
  ordered JSON result per input. This measures the real protocol parser and
  request encoder; it does not invent a Delphi receipt canonicalizer. }
{$APPTYPE CONSOLE}
{$I ..\..\Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Handoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Handoff.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.TestsProtocol in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsProtocol.pas',
 System.SysUtils, System.Classes, System.JSON,
  Cozy.ProtocolJson, Cozy.JsonEnvelope, Cozy.Hashes;

function Hex(const Bytes: TBytes): string;
const Digits: string = CozyText_FloatJsonProbe_0123456789abcdef_3d00742b;
var I: Integer;
begin
  SetLength(Result, Length(Bytes) * 2);
  for I := 0 to High(Bytes) do
  begin
    Result[I * 2 + 1] := Digits[(Bytes[I] shr 4) + 1];
    Result[I * 2 + 2] := Digits[(Bytes[I] and 15) + 1];
  end;
end;

procedure Measure(const Text: string; Index: Integer);
var Body, ResultObject: TJSONObject; NumberValue: TJSONValue;
  BodyBytes, EnvelopeBytes: TBytes; D: Double; Bits: UInt64;
begin
  Body := nil; ResultObject := TJSONObject.Create;
  try
    ResultObject.AddPair(CozyText_FloatJsonProbe_index_80e01ebf, TJSONNumber.Create(Index));
    try
      Body := ParseProtocolObject(Text, 16384);
    except
      on E: EConvertError do
      begin
        ResultObject.AddPair(CozyText_FloatJsonProbe_accepted_5e80b6c8, TJSONBool.Create(False));
        ResultObject.AddPair(CozyText_FloatJsonProbe_errorClass_59574224, E.ClassName);
        Writeln(ResultObject.ToJSON);
        Exit;
      end;
    end;
    { Fail the whole process on encoder/hash/runtime failures. Only the parser's
      deliberate EConvertError is a negative protocol decision. }
    ResultObject.AddPair(CozyText_FloatJsonProbe_accepted_5e80b6c8, TJSONBool.Create(True));
    NumberValue := Body.GetValue('n');
    if NumberValue is TJSONNumber then
    begin
      D := TJSONNumber(NumberValue).AsDouble;
      Move(D, Bits, SizeOf(Bits));
      ResultObject.AddPair(CozyText_FloatJsonProbe_numberBits_f0a2a5cd, LowerCase(IntToHex(Bits, 16)));
    end;
    BodyBytes := TEncoding.UTF8.GetBytes(Body.ToJSON);
    EnvelopeBytes := EncodeRequestEnvelope(CozyText_FloatJsonProbe_bootstrap_59db76cf, Body, 32768);
    ResultObject.AddPair(CozyText_FloatJsonProbe_bodyHex_98e57e8f, Hex(BodyBytes));
    ResultObject.AddPair(CozyText_FloatJsonProbe_envelopeHex_8a7535a9, Hex(EnvelopeBytes));
    ResultObject.AddPair(CozyText_FloatJsonProbe_bodySha512_66d4ea96, SHA512Bytes(BodyBytes));
    ResultObject.AddPair(CozyText_FloatJsonProbe_envelopeSha512_c3f3c89f, SHA512Bytes(EnvelopeBytes));
    Writeln(ResultObject.ToJSON);
  finally
    Body.Free; ResultObject.Free;
  end;
end;

var Bytes: TBytes; Text: string; Lines: TStringList; I: Integer; Encoded: UTF8String;
  Input: TFileStream;
begin
  try
    if ParamCount <> 1 then raise EArgumentException.Create(CozyText_FloatJsonProbe_FLOAT_JSON_CORPUS_ARGUMENT_e3f545aa);
    Input := TFileStream.Create(ParamStr(1), fmOpenRead or fmShareDenyWrite);
    try
      if (Input.Size < 1) or (Input.Size > 4 * 1024 * 1024) then
        raise EArgumentException.Create(CozyText_FloatJsonProbe_FLOAT_JSON_CORPUS_LIMIT_4f08c1f2);
      SetLength(Bytes, Integer(Input.Size));
      Input.ReadBuffer(Bytes[0], Length(Bytes));
    finally Input.Free; end;
    SetLength(Encoded, Length(Bytes)); Move(Bytes[0], Encoded[1], Length(Bytes));
    Text := DecodeProtocolUTF8(Encoded);
    Lines := TStringList.Create;
    try
      Lines.Text := Text;
      if (Lines.Count < 1) or (Lines.Count > 4096) then
        raise EArgumentException.Create(CozyText_FloatJsonProbe_FLOAT_JSON_CORPUS_COUNT_fc10f6d7);
      for I := 0 to Lines.Count - 1 do Measure(Lines[I], I);
    finally Lines.Free; end;
  except
    on E: Exception do
    begin
      Writeln(ErrOutput, E.ClassName, CozyText_FloatJsonProbe_Text_0b9c64e2, E.Message);
      ExitCode := 1;
    end;
  end;
end.
