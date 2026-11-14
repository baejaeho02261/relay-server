unit Cozy.JsonEnvelope;
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
interface
uses
{ Cozy central text imports. }
  Cozy.Strings.Handoff,
 System.SysUtils, System.JSON, Cozy.Api.Contracts;
function EncodeRequestEnvelope(const Operation: string; Body: TJSONObject;
  MaximumBytes: Integer): TBytes;
{ Borrow Body; return one owner for the exact legacy UTF8 wire envelope. }
function EncodeRequestEnvelopeOwned(const Operation: string; Body: TJSONObject;
  MaximumBytes: Integer): TApiSensitiveBuffer;
implementation
uses Cozy.ProtocolJson;
function EncodeRequestEnvelope(const Operation: string; Body: TJSONObject;
  MaximumBytes: Integer): TBytes;
var Text: string; BodyUtf8, Prefix: UTF8String; PrefixSize, BodySize: Integer;
begin
  if (Body = nil) or (MaximumBytes < 1) or
    (MaximumBytes > ProtocolRequestMaximumBytes) then
    raise EArgumentException.Create(CozyText_JsonEnvelope_REQUEST_ENVELOPE_ARGUMENT_03c057bd);
  ValidateProtocolRequest(Operation, Body);
  Result := nil;
  try
    { No cloned JSON tree and no whole UTF16 envelope. Body serialization and
      field ordering remain byte-for-byte equal to the original JSON writer. }
    Text := Body.ToJSON; BodyUtf8 := UTF8Encode(Text);
    UniqueString(Text);
    if Length(Text) > 0 then FillChar(PChar(Text)^, Length(Text) * SizeOf(Char), 0);
    Text := '';
    Prefix := UTF8String(CozyText_JsonEnvelope_JsonFixture_fbede879 + Operation + CozyText_JsonEnvelope_tlsPinVersion_1_body_54e32be7);
    PrefixSize := Length(Prefix); BodySize := Length(BodyUtf8);
    if (MaximumBytes <= PrefixSize) or (BodySize > MaximumBytes - PrefixSize - 1) then
      raise EArgumentException.Create(CozyText_JsonEnvelope_REQUEST_ENVELOPE_LIMIT_7d84dcd8);
    SetLength(Result, PrefixSize + BodySize + 1);
    Move(Prefix[1], Result[0], PrefixSize);
    if BodySize <> 0 then Move(BodyUtf8[1], Result[PrefixSize], BodySize);
    Result[High(Result)] := Ord('}');
  finally
    UniqueString(Text);
    if Length(Text) > 0 then FillChar(PChar(Text)^, Length(Text) * SizeOf(Char), 0);
    Text := '';
    if Length(BodyUtf8) > 0 then FillChar(BodyUtf8[1], Length(BodyUtf8), 0);
    BodyUtf8 := '';
  end;
end;
function EncodeRequestEnvelopeOwned(const Operation: string; Body: TJSONObject;
  MaximumBytes: Integer): TApiSensitiveBuffer;
var
  Text: string;
  Prefix: UTF8String;
  PrefixSize, BodySize: Integer;
begin
  if (Body = nil) or (MaximumBytes < 1) or
    (MaximumBytes > ProtocolRequestMaximumBytes) then
    raise EArgumentException.Create(CozyText_JsonEnvelope_REQUEST_ENVELOPE_ARGUMENT_03c057bd);
  ValidateProtocolRequest(Operation, Body);
  try
    Prefix := UTF8String(CozyText_JsonEnvelope_JsonFixture_fbede879 + Operation + CozyText_JsonEnvelope_tlsPinVersion_1_body_54e32be7);
    PrefixSize := Length(Prefix);
    Text := Body.ToJSON;
    BodySize := TEncoding.UTF8.GetByteCount(Text);
    if (MaximumBytes <= PrefixSize) or (BodySize > MaximumBytes - PrefixSize - 1) then
      raise EArgumentException.Create(CozyText_JsonEnvelope_REQUEST_ENVELOPE_LIMIT_7d84dcd8);
    { Public RTL encoding writes directly into the final exact-sized allocation.
      No second body owner, body copy or temporary UTF8 string on Delphi. }
    Result := TApiSensitiveBuffer.CreateUtf8Framed(Prefix, Text, '}', MaximumBytes);
  finally
    UniqueString(Text);
    if Text <> '' then FillChar(PChar(Text)^, Length(Text) * SizeOf(Char), 0);
    Text := '';
  end;
end;
end.
