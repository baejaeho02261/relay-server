program Cozy_ProtocolJsonDifferentialProbe;
{$APPTYPE CONSOLE}
{$I ..\..\Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc}
uses
{ Cozy central text imports. }
  Cozy.Strings.Handoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Handoff.pas',
  Cozy.Strings.TestsProtocol in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsProtocol.pas',
 System.SysUtils, System.Classes, System.JSON, Winapi.Windows,
  Cozy.ProtocolJson;
const MaximumFrame = 131072;
var InputStream: THandleStream; Header: array[0..2] of Cardinal;
  Raw: UTF8String; Text: string; Value: TJSONObject; Count: Integer;
function ReadExact(Buffer: Pointer; Size: Integer; AllowEnd: Boolean): Boolean;
var Done, N: Integer;
begin
  Done := 0;
  while Done < Size do
  begin
    N := InputStream.Read(PByte(Buffer)[Done], Size - Done);
    if N < 0 then raise EReadError.Create(CozyText_ProtocolJsonDifferentialProbe_PROBE_READ_FAILED_81570d6a);
    if N = 0 then
    begin
      if AllowEnd and (Done = 0) then Exit(False);
      raise EReadError.Create(CozyText_ProtocolJsonDifferentialProbe_PROBE_TRUNCATED_FRAME_3a209f87);
    end;
    Inc(Done, N);
  end;
  Result := True;
end;
begin
  InputStream := nil;
  try
    if ParamCount <> 0 then raise EArgumentException.Create(CozyText_ProtocolJsonDifferentialProbe_PROBE_NO_ARGUMENTS_8e9ad70d);
    SetTextCodePage(Output, CP_UTF8);
    InputStream := THandleStream.Create(GetStdHandle(STD_INPUT_HANDLE));
    Writeln(CozyText_ProtocolJsonDifferentialProbe_JsonFixture_41ee0373); Flush(Output);
    Count := 0;
    while ReadExact(@Header[0], SizeOf(Header), True) do
    begin
      Inc(Count);
      if (Count > 10000) or (Header[0] > MaximumFrame) or
        (Header[1] = 0) or (Header[1] > MaximumFrame) or (Header[2] > 2) then
        raise EReadError.Create(CozyText_ProtocolJsonDifferentialProbe_PROBE_FRAME_LIMIT_5e772fac);
      SetLength(Raw, Header[0]);
      if Header[0] <> 0 then ReadExact(@Raw[1], Header[0], False);
      Value := nil;
      try
        try
          Text := DecodeProtocolUTF8(Raw);
          if Header[2] = 1 then Value := ParseProtocolRequest(Text, Header[1])
          else Value := ParseProtocolObject(Text, Header[1]);
          if Header[2] = 2 then
          begin
            if (Value.Count <> 2) or
              not (Value.GetValue(CozyText_ProtocolJsonDifferentialProbe_name_abc4b2f7) is TJSONString) or
              not (Value.GetValue(CozyText_ProtocolJsonDifferentialProbe_value_00267832) is TJSONObject) then
              raise EConvertError.Create(CozyText_ProtocolJsonDifferentialProbe_PROTOCOL_SCHEMA_INVALID_a62adc41);
            ValidateProtocolDocument(Value.GetValue(CozyText_ProtocolJsonDifferentialProbe_name_abc4b2f7).Value,
              TJSONObject(Value.GetValue(CozyText_ProtocolJsonDifferentialProbe_value_00267832)));
          end;
          Writeln(CozyText_ProtocolJsonDifferentialProbe_JsonFixture_a69af3e4, Value.ToJSON, '}');
        except
          on E: EConvertError do Writeln(CozyText_ProtocolJsonDifferentialProbe_JsonFixture_23665675);
        end;
      finally
        Value.Free;
        if Length(Raw) <> 0 then FillChar(Raw[1], Length(Raw), 0);
        Raw := ''; Text := '';
      end;
      Flush(Output);
    end;
  except
    on E: Exception do begin InputStream.Free; Halt(1); end;
  end;
  InputStream.Free;
end.
