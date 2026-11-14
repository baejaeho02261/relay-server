unit Cozy.ProtocolJson;
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
interface
uses
{ Cozy central text imports. }
  Cozy.Strings.Handoff,
 System.JSON;
{ The caller owns Result. This parser never converts an ambiguous wire object
  to application data: depth, duplicates, Unicode, integer ranges and trailing
  input are checked independently of the RTL parser's permissive behavior. }
function DecodeProtocolUTF8(const Bytes: UTF8String): string;
function ParseProtocolObject(const Text: string; MaximumBytes: Integer): TJSONObject;
{ Shared, generated command contract. All returned JSON objects remain owned
  by the caller. Domain authorization/signature checks still run on the server. }
{ Generated response/evidence rules share the request schema and parser. }
procedure ValidateProtocolDocument(const Name: string; Value: TJSONObject);
procedure ValidateProtocolRequest(const Operation: string; Body: TJSONObject);
procedure ValidateProtocolEnvelope(Value: TJSONObject);
function ParseProtocolRequest(const Text: string; MaximumBytes: Integer): TJSONObject;
function ProtocolRequestMaximumBytes: Integer;
function ProtocolSchemaDigest: string;
implementation
uses System.SysUtils, System.Generics.Collections, System.Math, System.RegularExpressions;
function DecodeProtocolUTF8(const Bytes: UTF8String): string;
var I, J, Need: Integer; B, CodePoint: Cardinal;
begin
  I := 1;
  while I <= Length(Bytes) do
  begin
    B := Byte(Bytes[I]);
    if B < $80 then begin Inc(I); Continue; end;
    if (B >= $C2) and (B <= $DF) then begin Need := 1; CodePoint := B and $1F; end
    else if (B >= $E0) and (B <= $EF) then begin Need := 2; CodePoint := B and $0F; end
    else if (B >= $F0) and (B <= $F4) then begin Need := 3; CodePoint := B and $07; end
    else raise EConvertError.Create(CozyText_ProtocolJson_PROTOCOL_UTF8_INVALID_fd8d9d7f);
    if I + Need > Length(Bytes) then raise EConvertError.Create(CozyText_ProtocolJson_PROTOCOL_UTF8_INVALID_fd8d9d7f);
    for J := 1 to Need do
    begin
      B := Byte(Bytes[I + J]);
      if (B and $C0) <> $80 then raise EConvertError.Create(CozyText_ProtocolJson_PROTOCOL_UTF8_INVALID_fd8d9d7f);
      CodePoint := (CodePoint shl 6) or (B and $3F);
    end;
    if ((Need = 1) and (CodePoint < $80)) or
      ((Need = 2) and (CodePoint < $800)) or
      ((Need = 3) and (CodePoint < $10000)) or
      ((CodePoint >= $D800) and (CodePoint <= $DFFF)) or (CodePoint > $10FFFF) then
      raise EConvertError.Create(CozyText_ProtocolJson_PROTOCOL_UTF8_INVALID_fd8d9d7f);
    Inc(I, Need + 1);
  end;
  Result := UTF8ToString(Bytes);
end;

procedure Invalid;
begin raise EConvertError.Create(CozyText_ProtocolJson_PROTOCOL_JSON_INVALID_c3741c2d); end;
procedure Scalar(const Text: string);
var I, C: Integer;
begin
  I := 1;
  while I <= Length(Text) do
  begin
    C := Ord(Text[I]);
    if (C >= $D800) and (C <= $DBFF) then
    begin
      Inc(I); if I > Length(Text) then Invalid;
      C := Ord(Text[I]); if (C < $DC00) or (C > $DFFF) then Invalid;
    end
    else if (C >= $DC00) and (C <= $DFFF) then Invalid;
    Inc(I);
  end;
end;
procedure BoundSyntax(const Text: string);
var I, Nodes: Integer;
  procedure White;
  begin
    while (I <= Length(Text)) and CharInSet(Text[I], [' ', #9, #10, #13]) do Inc(I);
  end;
  function Peek: Char;
  begin
    if I > Length(Text) then Result := #0 else Result := Text[I];
  end;
  procedure Expect(C: Char);
  begin
    if Peek <> C then Invalid;
    Inc(I);
  end;
  procedure StringToken;
  var C: Char; J: Integer;
  begin
    Expect('"');
    while I <= Length(Text) do
    begin
      C := Text[I]; Inc(I);
      if C = '"' then Exit;
      if C < #32 then Invalid;
      if C = '\' then
      begin
        C := Peek; Inc(I);
        if C = 'u' then
          for J := 1 to 4 do
          begin
            if not CharInSet(Peek, ['0'..'9', 'a'..'f', 'A'..'F']) then Invalid;
            Inc(I);
          end
        else if not CharInSet(C, ['"', '\', '/', 'b', 'f', 'n', 'r', 't']) then Invalid;
      end;
    end;
    Invalid;
  end;
  procedure NumberToken;
  begin
    if Peek = '-' then Inc(I);
    if Peek = '0' then Inc(I)
    else
    begin
      if not CharInSet(Peek, ['1'..'9']) then Invalid;
      repeat Inc(I); until not CharInSet(Peek, ['0'..'9']);
    end;
    if Peek = '.' then
    begin
      Inc(I); if not CharInSet(Peek, ['0'..'9']) then Invalid;
      repeat Inc(I); until not CharInSet(Peek, ['0'..'9']);
    end;
    if CharInSet(Peek, ['e', 'E']) then
    begin
      Inc(I); if CharInSet(Peek, ['+', '-']) then Inc(I);
      if not CharInSet(Peek, ['0'..'9']) then Invalid;
      repeat Inc(I); until not CharInSet(Peek, ['0'..'9']);
    end;
  end;
  procedure Literal(const Token: string);
  begin
    if Copy(Text, I, Length(Token)) <> Token then Invalid;
    Inc(I, Length(Token));
  end;
  procedure Value(Depth: Integer);
  begin
    Inc(Nodes); if (Depth > 32) or (Nodes > 32768) then Invalid;
    White;
    case Peek of
      '{': begin
        Inc(I); White;
        if Peek = '}' then begin Inc(I); Exit; end;
        repeat
          White; StringToken; White; Expect(':'); Value(Depth + 1); White;
          if Peek = '}' then begin Inc(I); Exit; end;
          Expect(',');
        until False;
      end;
      '[': begin
        Inc(I); White;
        if Peek = ']' then begin Inc(I); Exit; end;
        repeat
          Value(Depth + 1); White;
          if Peek = ']' then begin Inc(I); Exit; end;
          Expect(',');
        until False;
      end;
      '"': StringToken;
      't': Literal(CozyText_ProtocolJson_true_cee8b631);
      'f': Literal(CozyText_ProtocolJson_false_f39810a9);
      'n': Literal(CozyText_ProtocolJson_null_63843753);
    else NumberToken;
    end;
  end;
begin
  I := 1; Nodes := 0; White;
  if Peek <> '{' then Invalid;
  Value(0); White;
  if I <= Length(Text) then Invalid;
end;

procedure Validate(Value: TJSONValue; Depth: Integer; var Nodes: Integer);
var Pair: TJSONPair; Item: TJSONValue; Seen: TDictionary<string, Boolean>;
  N: Int64; D: Double; Fmt: TFormatSettings;
begin
  Inc(Nodes); if (Nodes > 32768) or (Depth > 32) or (Value = nil) then Invalid;
  if Value is TJSONObject then
  begin
    Seen := TDictionary<string, Boolean>.Create;
    try
      for Pair in TJSONObject(Value) do
      begin
        Scalar(Pair.JsonString.Value);
        if Seen.ContainsKey(Pair.JsonString.Value) or
          (Pair.JsonString.Value = CozyText_ProtocolJson_proto_7538e122) or (Pair.JsonString.Value = CozyText_ProtocolJson_constructor_214dce11) or
          (Pair.JsonString.Value = CozyText_ProtocolJson_prototype_721ca8c8) then Invalid;
        Seen.Add(Pair.JsonString.Value, True); Validate(Pair.JsonValue, Depth + 1, Nodes);
      end;
    finally Seen.Free; end;
  end
  else if Value is TJSONArray then
    for Item in TJSONArray(Value) do Validate(Item, Depth + 1, Nodes)
  else if Value is TJSONString then Scalar(Value.Value)
  else if Value is TJSONNumber then
  begin
    if TryStrToInt64(Value.Value, N) then
    begin if (N > 9007199254740991) or (N < -9007199254740991) then Invalid; end
    else
    begin
      Fmt := TFormatSettings.Invariant;
      if not TryStrToFloat(Value.Value, D, Fmt) then Invalid;
      if IsNan(D) or IsInfinite(D) or (Abs(D) > 9007199254740991.0) then Invalid;
    end;
  end;
end;
function ParseProtocolObject(const Text: string; MaximumBytes: Integer): TJSONObject;
var Value: TJSONValue; Nodes: Integer;
begin
  if (MaximumBytes <= 0) or (TEncoding.UTF8.GetByteCount(Text) > MaximumBytes) then Invalid;
  Scalar(Text); BoundSyntax(Text); Value := TJSONObject.ParseJSONValue(Text);
  try
    if not (Value is TJSONObject) then Invalid;
    Nodes := 0; Validate(Value, 0, Nodes);
    Result := TJSONObject(Value); Value := nil;
  finally Value.Free; end;
end;
{$I Cozy.ProtocolSchema.inc}
var PacketSchema: TJSONObject;
procedure SchemaInvalid;
begin
  raise EConvertError.Create(CozyText_ProtocolJson_PROTOCOL_SCHEMA_INVALID_ad38e3a7);
end;
function SchemaNumber(Value: TJSONValue): Double;
begin
  if not (Value is TJSONNumber) or
    not TryStrToFloat(Value.Value, Result, TFormatSettings.Invariant) or
    IsNan(Result) or IsInfinite(Result) then SchemaInvalid;
end;
function SchemaEqual(Left, Right: TJSONValue): Boolean;
begin
  if (Left is TJSONNumber) and (Right is TJSONNumber) then
    Exit(SchemaNumber(Left) = SchemaNumber(Right));
  if (Left is TJSONString) and (Right is TJSONString) then
    Exit(Left.Value = Right.Value);
  if (Left is TJSONBool) and (Right is TJSONBool) then
    Exit(TJSONBool(Left).AsBoolean = TJSONBool(Right).AsBoolean);
  Result := (Left is TJSONNull) and (Right is TJSONNull);
end;
procedure ValidateSchema(Node: TJSONObject; Value: TJSONValue; Depth: Integer);
var RefValue, Rule, Bound: TJSONValue; Kind, Text, Pattern: string;
  Required, Group: TJSONArray; Props: TJSONObject; Pair: TJSONPair;
  Item: TJSONValue; N: Double; Count: Integer; Matched: Boolean;
begin
  if (Depth > 32) or (Node = nil) or (Value = nil) then SchemaInvalid;
  RefValue := Node.GetValue(CozyText_ProtocolJson_ref_dbc6f224);
  if RefValue <> nil then
  begin
    Rule := TJSONObject(PacketSchema.GetValue(CozyText_ProtocolJson_definitions_73e05fa3)).GetValue(RefValue.Value);
    if not (Rule is TJSONObject) then SchemaInvalid;
    ValidateSchema(TJSONObject(Rule), Value, Depth + 1); Exit;
  end;
  Rule := Node.GetValue(CozyText_ProtocolJson_anyOf_78bd2974);
  if Rule <> nil then
  begin
    for Item in TJSONArray(Rule) do
    begin
      try
        ValidateSchema(TJSONObject(Item), Value, Depth + 1);
        Exit;
      except
        on E: EConvertError do
          if E.Message <> CozyText_ProtocolJson_PROTOCOL_SCHEMA_INVALID_ad38e3a7 then raise;
      end;
    end;
    SchemaInvalid;
  end;
  Rule := Node.GetValue(CozyText_ProtocolJson_enum_445c81f9);
  if Rule <> nil then
  begin
    Matched := False;
    for Item in TJSONArray(Rule) do
      if SchemaEqual(Item, Value) then begin Matched := True; Break; end;
    if not Matched then SchemaInvalid;
  end;
  Rule := Node.GetValue(CozyText_ProtocolJson_type_5eaaf2e7); if Rule = nil then Exit;
  Kind := Rule.Value;
  if Kind = CozyText_ProtocolJson_string_24371e40 then
  begin
    if not (Value is TJSONString) then SchemaInvalid;
    Text := Value.Value;
    Bound := Node.GetValue(CozyText_ProtocolJson_minLength_67c89d4a);
    if (Bound <> nil) and (Length(Text) < SchemaNumber(Bound)) then SchemaInvalid;
    Bound := Node.GetValue(CozyText_ProtocolJson_maxLength_1bc84f8d);
    if (Bound <> nil) and (Length(Text) > SchemaNumber(Bound)) then SchemaInvalid;
    Bound := Node.GetValue(CozyText_ProtocolJson_maxBytes_382f1471);
    if (Bound <> nil) and (TEncoding.UTF8.GetByteCount(Text) > SchemaNumber(Bound)) then SchemaInvalid;
    Bound := Node.GetValue(CozyText_ProtocolJson_pattern_358b2f19);
    if Bound <> nil then
    begin
      Pattern := Bound.Value;
      { The extra absolute-end assertion rejects a final newline that '$'
        alone can allow. No untrusted pattern is compiled. }
      if not TRegEx.IsMatch(Text, Pattern + CozyText_ProtocolJson_s_S_00d4b003) then SchemaInvalid;
    end;
  end
  else if Kind = CozyText_ProtocolJson_integer_86575e9c then
  begin
    N := SchemaNumber(Value);
    if (Abs(N) > 9007199254740991.0) or (Frac(N) <> 0) or
      (N < SchemaNumber(Node.GetValue(CozyText_ProtocolJson_minimum_17f90ec0))) or
      (N > SchemaNumber(Node.GetValue(CozyText_ProtocolJson_maximum_a222126b))) then SchemaInvalid;
  end
  else if Kind = CozyText_ProtocolJson_array_1bfa66e4 then
  begin
    if not (Value is TJSONArray) then SchemaInvalid;
    if TJSONArray(Value).Count > SchemaNumber(Node.GetValue(CozyText_ProtocolJson_maxItems_396efcf6)) then SchemaInvalid;
    for Item in TJSONArray(Value) do
      ValidateSchema(TJSONObject(Node.GetValue(CozyText_ProtocolJson_items_b1becea9)), Item, Depth + 1);
  end
  else if Kind = CozyText_ProtocolJson_object_ef053355 then
  begin
    if not (Value is TJSONObject) then SchemaInvalid;
    Props := TJSONObject(Node.GetValue(CozyText_ProtocolJson_properties_e0f18dec));
    if Props <> nil then
    begin
      for Pair in TJSONObject(Value) do
      begin
        Rule := Props.GetValue(Pair.JsonString.Value);
        if not (Rule is TJSONObject) then SchemaInvalid;
        ValidateSchema(TJSONObject(Rule), Pair.JsonValue, Depth + 1);
      end;
      Required := TJSONArray(Node.GetValue(CozyText_ProtocolJson_required_c238e75f));
      for Item in Required do
        if TJSONObject(Value).GetValue(Item.Value) = nil then SchemaInvalid;
    end;
    Group := TJSONArray(Node.GetValue(CozyText_ProtocolJson_allOrNone_e2d92130));
    if Group <> nil then
    begin
      Count := 0;
      for Item in Group do if TJSONObject(Value).GetValue(Item.Value) <> nil then Inc(Count);
      if (Count <> 0) and (Count <> Group.Count) then SchemaInvalid;
    end;
    Group := TJSONArray(Node.GetValue(CozyText_ProtocolJson_exactlyOne_edc3fa73));
    if Group <> nil then
    begin
      Count := 0;
      for Item in Group do if TJSONObject(Value).GetValue(Item.Value) <> nil then Inc(Count);
      if Count <> 1 then SchemaInvalid;
    end;
  end
  else SchemaInvalid;
end;
procedure ValidateProtocolDocument(const Name: string; Value: TJSONObject);
var Documents, Rule: TJSONObject; RuleValue: TJSONValue; Nodes: Integer;
begin
  if Value = nil then SchemaInvalid;
  Nodes := 0; Validate(Value, 0, Nodes);
  Documents := TJSONObject(PacketSchema.GetValue(CozyText_ProtocolJson_documents_42e76750));
  if Documents = nil then SchemaInvalid;
  RuleValue := Documents.GetValue(Name);
  if not (RuleValue is TJSONObject) then SchemaInvalid;
  Rule := TJSONObject(RuleValue);
  ValidateSchema(Rule, Value, 0);
end;
procedure ValidateProtocolRequest(const Operation: string; Body: TJSONObject);
var Commands: TJSONArray; Command: TJSONValue; Rule: TJSONObject;
  ActionValue: TJSONValue; Nodes: Integer;
begin
  if Body = nil then SchemaInvalid;
  { In-memory callers also receive duplicate/Unicode/number/depth validation.
    We do not serialize or copy tokens into a second JSON tree. }
  Nodes := 0; Validate(Body, 0, Nodes);
  ActionValue := Body.GetValue(CozyText_ProtocolJson_action_e06f26e2);
  if not (ActionValue is TJSONString) then SchemaInvalid;
  Commands := TJSONArray(PacketSchema.GetValue(CozyText_ProtocolJson_commands_3268d067));
  for Command in Commands do
  begin
    Rule := TJSONObject(Command);
    if (Rule.GetValue(CozyText_ProtocolJson_operation_48c2bf10).Value = Operation) and
      (Rule.GetValue(CozyText_ProtocolJson_action_e06f26e2).Value = ActionValue.Value) then
    begin ValidateSchema(TJSONObject(Rule.GetValue(CozyText_ProtocolJson_body_f06ac25c)), Body, 0); Exit; end;
  end;
  SchemaInvalid;
end;
procedure ValidateProtocolEnvelope(Value: TJSONObject);
var Nodes: Integer;
begin
  if Value = nil then SchemaInvalid;
  Nodes := 0; Validate(Value, 0, Nodes);
  ValidateSchema(TJSONObject(PacketSchema.GetValue(CozyText_ProtocolJson_envelope_f6c56618)), Value, 0);
  ValidateProtocolRequest(Value.GetValue(CozyText_ProtocolJson_operation_48c2bf10).Value,
    TJSONObject(Value.GetValue(CozyText_ProtocolJson_body_f06ac25c)));
end;
function ParseProtocolRequest(const Text: string; MaximumBytes: Integer): TJSONObject;
begin
  if (MaximumBytes < 1) or (MaximumBytes > ProtocolRequestMaximumBytes) then SchemaInvalid;
  Result := ParseProtocolObject(Text, MaximumBytes);
  try ValidateProtocolEnvelope(Result);
  except
    Result.Free;
    raise;
  end;
end;
function ProtocolRequestMaximumBytes: Integer;
begin Result := ProtocolSchemaMaximumRequestBytes; end;
function ProtocolSchemaDigest: string;
begin Result := ProtocolSchemaSHA512; end;
initialization
  { Trusted generated constants only; no local policy file or sensitive key. }
  PacketSchema := TJSONObject.ParseJSONValue(ProtocolSchemaJSON) as TJSONObject;
finalization
  PacketSchema.Free;
end.
