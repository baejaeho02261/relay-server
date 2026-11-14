program Cozy_JsonEnvelopeProbe;
{$APPTYPE CONSOLE}
{$I ..\..\Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc}
uses
{ Cozy central text imports. }
  Cozy.Strings.Handoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Handoff.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.TestsProtocol in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsProtocol.pas',
 System.SysUtils, System.JSON, Cozy.JsonEnvelope, Cozy.ProtocolJson;
{$I Cozy.ProtocolSchemaCases.inc}
{$I Cozy.ProtocolDocumentCases.inc}
var Packet, Legacy, Parsed, Body: TJSONObject; A, B: TBytes; I, J: Integer;
  Original, Operation: string; Rejected: Boolean;
  Mutation: TJSONObject; Pair: TJSONPair;
procedure RequireDocumentRejected(const Name: string; Value: TJSONObject);
var WasRejected: Boolean;
begin
  WasRejected := False;
  try ValidateProtocolDocument(Name, Value);
  except on E: EConvertError do WasRejected := True; end;
  if not WasRejected then raise Exception.Create(CozyText_JsonEnvelopeProbe_INVALID_DOCUMENT_ACCEPTED_d122fbd3);
end;
begin
  A := nil; B := nil;
  try
    for I := Low(ProtocolSchemaCases) to High(ProtocolSchemaCases) do
    begin
      Packet := ParseProtocolRequest(ProtocolSchemaCases[I], 32768);
      try
        Body := Packet.GetValue(CozyText_JsonEnvelopeProbe_body_67083f07) as TJSONObject;
        Operation := Packet.GetValue(CozyText_JsonEnvelopeProbe_operation_3bedefb6).Value;
        Original := Body.ToJSON;
        Legacy := TJSONObject.Create;
        try
          Legacy.AddPair(CozyText_JsonEnvelopeProbe_operation_3bedefb6, Operation);
          Legacy.AddPair(CozyText_JsonEnvelopeProbe_tlsPinVersion_6fde483b, TJSONNumber.Create(1));
          Legacy.AddPair(CozyText_JsonEnvelopeProbe_body_67083f07, TJSONObject(Body.Clone));
          A := TEncoding.UTF8.GetBytes(Legacy.ToJSON);
          B := EncodeRequestEnvelope(Operation, Body, 32768);
          if (Length(A) <> Length(B)) or not CompareMem(@A[0], @B[0], Length(A)) then
            raise Exception.Create(CozyText_JsonEnvelopeProbe_WIRE_CHANGED_b53a80a0);
          if Body.ToJSON <> Original then raise Exception.Create(CozyText_JsonEnvelopeProbe_BORROWED_BODY_CHANGED_3c0e20ed);
          Parsed := ParseProtocolRequest(TEncoding.UTF8.GetString(B), Length(B));
          Parsed.Free;
          B := EncodeRequestEnvelope(Operation, Body, Length(A));
          Rejected := False;
          try B := EncodeRequestEnvelope(Operation, Body, Length(A) - 1);
          except on E: EArgumentException do Rejected := True; end;
          if not Rejected then raise Exception.Create(CozyText_JsonEnvelopeProbe_ENVELOPE_LIMIT_ACCEPTED_73eb1d54);
          Body.AddPair(CozyText_JsonEnvelopeProbe_unexpected_28c3335b, CozyText_JsonEnvelopeProbe_must_reject_b2bb4fe8);
          Rejected := False;
          try B := EncodeRequestEnvelope(Operation, Body, 32768);
          except on E: EConvertError do Rejected := True; end;
          if not Rejected then raise Exception.Create(CozyText_JsonEnvelopeProbe_UNDECLARED_FIELD_ACCEPTED_4c04a0f9);
        finally Legacy.Free; end;
      finally Packet.Free; end;
    end;
    { Signed payload strings may contain escaped Unicode/NUL/quotes; the packet
      layer does not reinterpret or normalize their signed bytes. }
    Packet := ParseProtocolRequest(ProtocolSchemaCases[High(ProtocolSchemaCases)],32768);
    try
      Body := Packet.GetValue(CozyText_JsonEnvelopeProbe_body_67083f07) as TJSONObject;
      Body.RemovePair(CozyText_JsonEnvelopeProbe_payloadJSON_58ec79d3).Free;
      Body.AddPair(CozyText_JsonEnvelopeProbe_payloadJSON_58ec79d3,CozyText_JsonEnvelopeProbe_JsonFixture_c676471f+#$D55C+#$AD6D+CozyText_JsonEnvelopeProbe_zero_u0000_6f362ec8);
      Original := Body.ToJSON;
      B := EncodeRequestEnvelope(CozyText_JsonEnvelopeProbe_execute_090658e3,Body,32768);
      Parsed := ParseProtocolRequest(TEncoding.UTF8.GetString(B),Length(B));
      try
        if (Parsed.GetValue(CozyText_JsonEnvelopeProbe_body_67083f07) as TJSONObject).ToJSON <> Original then
          raise Exception.Create(CozyText_JsonEnvelopeProbe_SIGNED_PAYLOAD_BYTES_CHANGED_15036dbc);
      finally Parsed.Free; end;
    finally Packet.Free; end;
    for I := Low(ProtocolDocumentSchemaCases) to High(ProtocolDocumentSchemaCases) do
    begin
      Packet := ParseProtocolObject(ProtocolDocumentSchemaCases[I], 65536);
      try
        Operation := Packet.GetValue(CozyText_JsonEnvelopeProbe_name_2c9aa2be).Value;
        Body := Packet.GetValue(CozyText_JsonEnvelopeProbe_value_204ba8d9) as TJSONObject;
        ValidateProtocolDocument(Operation, Body);
        for Pair in Body do
        begin
          Mutation := TJSONObject(Body.Clone);
          try
            Mutation.RemovePair(Pair.JsonString.Value).Free;
            Mutation.AddPair(Pair.JsonString.Value, TJSONNull.Create);
            RequireDocumentRejected(Operation, Mutation);
          finally Mutation.Free; end;
        end;
        Mutation := TJSONObject(Body.Clone);
        try
          Mutation.AddPair(CozyText_JsonEnvelopeProbe_role_244e5106, 'A');
          RequireDocumentRejected(Operation, Mutation);
        finally Mutation.Free; end;
        { In-memory duplicate keys must fail before field lookup. }
        Mutation := TJSONObject(Body.Clone);
        try
          Pair := Body.Pairs[0];
          Mutation.AddPair(Pair.JsonString.Value, TJSONValue(Pair.JsonValue.Clone));
          RequireDocumentRejected(Operation, Mutation);
        finally Mutation.Free; end;
      finally Packet.Free; end;
    end;
    Writeln(CozyText_JsonEnvelopeProbe_PASS_generated_response_evidence_documents_exact_adb043b2);
    Writeln(CozyText_JsonEnvelopeProbe_PASS_real_Delphi_schema_encoder_40_command_shape_67ad084e);
  except on E: Exception do begin Writeln(E.ClassName, CozyText_JsonEnvelopeProbe_Text_637c11a1, E.Message); Halt(1); end; end;
  for J := 0 to High(A) do A[J] := 0;
  for J := 0 to High(B) do B[J] := 0;
end.
