unit Cozy.Server.Profile;
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
interface
uses
{ Cozy central text imports. }
  Cozy.Strings.Network,
 System.SysUtils, Cozy.Tls.PinWindow;
type
  EConnectProfile = class(Exception);
  { Values are public trust material, not credentials. Pin state is a snapshot;
    the live monotonic trust window remains separately shared by clones. }
  TConnectProfileFields = record
    Host, ServerKeyId, ServerPublicKey, TlsServerName, TlsCertificateSha256,
      PinState: string;
    Port: Word;
  end;
  TConnectServerProfile = class
  private
    FPinWindow: ITlsPinWindow;
    FFields: TConnectProfileFields;
    function GetHost: string;
    function GetPort: Word;
    function GetServerKeyId: string;
    function GetServerPublicKey: string;
    function GetTlsServerName: string;
    function GetTlsCertificateSha256: string;
    function GetBindingID: string;
    function GetDisplayEndpoint: string;
    class function Parse(const Text: string): TConnectServerProfile; static;
    class function Build(const Fields: TConnectProfileFields;
      const SharedWindow: ITlsPinWindow): TConnectServerProfile; static;
  public
    class function FromJSON(const Text: string): TConnectServerProfile; static;
    { Canonical bytes for one fixed trusted snapshot, including its exact floor.
      A live ToJSON export may advance that floor and must not be cached. }
    class function CanonicalizeJSON(const Text: string): string; static;
    function Clone: TConnectServerProfile;
    function ToJSON: string;
    procedure SelectTlsPins(out Primary, Secondary: string);
    procedure CheckTlsPeer(const Pin: string);
    procedure LearnTlsPlan(const Text, PresentedPin: string;
      const BeforeCommit: TProc = nil);
    property Host: string read GetHost;
    property Port: Word read GetPort;
    property ServerKeyId: string read GetServerKeyId;
    property ServerPublicKey: string read GetServerPublicKey;
    property TlsServerName: string read GetTlsServerName;
    property TlsCertificateSha256: string read GetTlsCertificateSha256;
    property BindingID: string read GetBindingID;
    property DisplayEndpoint: string read GetDisplayEndpoint;
  end;
implementation
uses Winapi.Windows, System.JSON, System.NetEncoding, Cozy.Integrity, Cozy.ProtocolJson;
type
  TRsaPublicHeader = packed record
    Magic, BitLength, ExponentBytes, ModulusBytes, Prime1Bytes, Prime2Bytes: DWORD;
  end;
  TProfileField = (pfVersion, pfProtocol, pfHost, pfPort, pfServerKeyId,
    pfServerPublicKey, pfTlsServerName, pfTlsCertificateSha256, pfTlsPinState);
  TProfileKind = (pkInteger, pkString);
  TProfileRule = record
    Name: string;
    Kind: TProfileKind;
    Required: Boolean;
  end;
const
  ProtocolName = CozyText_Server_Profile_GAME_CONNECT_4_245dd76b;
  MaxProfileBytes = 8192;
  MaxPinStateBytes = 6144;
  { One ordered schema drives input shape/type checks and output field order.
    Identity/key/pin semantics are validated once by ValidateFields below. }
  ProfileRules: array[TProfileField] of TProfileRule = (
    (Name:CozyText_Server_Profile_version_fb3048c8; Kind:pkInteger; Required:True),
    (Name:CozyText_Server_Profile_protocol_339a97c5; Kind:pkString; Required:True),
    (Name:CozyText_Server_Profile_host_0641da68; Kind:pkString; Required:True),
    (Name:CozyText_Server_Profile_port_25ea07ca; Kind:pkInteger; Required:True),
    (Name:CozyText_Server_Profile_serverKeyId_d1ff78c8; Kind:pkString; Required:True),
    (Name:CozyText_Server_Profile_serverPublicKey_e4bd8c76; Kind:pkString; Required:True),
    (Name:CozyText_Server_Profile_tlsServerName_c15a064b; Kind:pkString; Required:True),
    (Name:CozyText_Server_Profile_tlsCertificateSha256_0b04d80c; Kind:pkString; Required:True),
    (Name:CozyText_Server_Profile_tlsPinState_6ab6346f; Kind:pkString; Required:False));
procedure InvalidProfile;
begin
  raise EConnectProfile.Create(CozyText_Server_Profile_A_exe_a500a22a);
end;
function FieldText(Obj: TJSONObject; Field: TProfileField): string;
begin Result := Obj.GetValue(ProfileRules[Field].Name).Value; end;
procedure ValidateShape(Obj: TJSONObject);
var Seen: array[TProfileField] of Boolean; Pair: TJSONPair;
  Field: TProfileField; Found: Boolean;
begin
  FillChar(Seen, SizeOf(Seen), 0);
  for Pair in Obj do
  begin
    Found := False;
    for Field := Low(TProfileField) to High(TProfileField) do
      if Pair.JsonString.Value = ProfileRules[Field].Name then
      begin
        if Seen[Field] then InvalidProfile;
        Seen[Field] := True; Found := True;
        case ProfileRules[Field].Kind of
          pkInteger: if not (Pair.JsonValue is TJSONNumber) then InvalidProfile;
          pkString: if not (Pair.JsonValue is TJSONString) then InvalidProfile;
        end;
        Break;
      end;
    if not Found then InvalidProfile;
  end;
  for Field := Low(TProfileField) to High(TProfileField) do
    if ProfileRules[Field].Required and not Seen[Field] then InvalidProfile;
end;
function IsHostValid(const Host: string): Boolean;
var
  I, LabelStart, LabelLength: Integer;
  C: Char;
begin
  Result := False;
  if (Length(Host) < 1) or (Length(Host) > 253) then Exit;
  LabelStart := 1;
  for I := 1 to Length(Host) + 1 do
  begin
    if I > Length(Host) then C := '.' else C := Host[I];
    if C = '.' then
    begin
      LabelLength := I - LabelStart;
      if (LabelLength < 1) or (LabelLength > 63) then Exit;
      if (Host[LabelStart] = '-') or (Host[I - 1] = '-') then Exit;
      LabelStart := I + 1;
    end
    else if not CharInSet(C, ['a'..'z', '0'..'9', '-']) then Exit;
  end;
  Result := True;
end;


procedure ValidateFields(const Fields: TConnectProfileFields);
var I: Integer; PublicKey: string; Header: TRsaPublicHeader; Bytes: TBytes;
  Exponent: UInt64; Encoding: TBase64Encoding;
  procedure Hex64(const Value: string);
  var Ch: Char;
  begin
    if Length(Value) <> 64 then InvalidProfile;
    for Ch in Value do if not CharInSet(Ch, ['0'..'9','a'..'f']) then InvalidProfile;
  end;
begin
  if not IsHostValid(Fields.Host) or not IsHostValid(Fields.TlsServerName) or
    (Fields.Port = 0) then InvalidProfile;
  Hex64(Fields.ServerKeyId); Hex64(Fields.TlsCertificateSha256);
  if (Fields.PinState <> '') and
    (TEncoding.UTF8.GetByteCount(Fields.PinState) > MaxPinStateBytes) then InvalidProfile;
  PublicKey := Fields.ServerPublicKey;
  if (Length(PublicKey) < 376) or (Length(PublicKey) > 384) then InvalidProfile;
  Encoding := TBase64Encoding.Create(0);
  try
    try
      Bytes := Encoding.DecodeStringToBytes(PublicKey);
    except
      InvalidProfile;
    end;
    if Encoding.EncodeBytesToString(Bytes) <> PublicKey then InvalidProfile;
  finally
    Encoding.Free;
  end;
  if Length(Bytes) < SizeOf(Header) then InvalidProfile;
  Move(Bytes[0], Header, SizeOf(Header));
  if (Header.Magic <> $31415352) or (Header.BitLength <> 2048) or
     (Header.ModulusBytes <> 256) or (Header.Prime1Bytes <> 0) or
     (Header.Prime2Bytes <> 0) or (Header.ExponentBytes < 1) or
     (Header.ExponentBytes > 8) then InvalidProfile;
  if Length(Bytes) <> Integer(SizeOf(Header) + Header.ExponentBytes + 256) then
    InvalidProfile;
  Exponent := 0;
  if Bytes[SizeOf(Header)] = 0 then InvalidProfile;
  for I := 0 to Integer(Header.ExponentBytes) - 1 do
    Exponent := (Exponent shl 8) or Bytes[SizeOf(Header) + I];
  if (Exponent < 3) or ((Exponent and 1) = 0) then InvalidProfile;
  if (Bytes[SizeOf(Header) + Header.ExponentBytes] and $80) = 0 then InvalidProfile;
  if (Bytes[Length(Bytes) - 1] and 1) = 0 then InvalidProfile;
  if IntegritySHA256Bytes(Bytes) <> Fields.ServerKeyId then InvalidProfile;

end;
function ReadFields(const Text: string): TConnectProfileFields;
var Obj: TJSONObject; PortNumber: Integer; PortText: string;
begin
  Obj := nil;
  if (Text = '') or (TEncoding.UTF8.GetByteCount(Text) > MaxProfileBytes) then InvalidProfile;
  try
    try Obj := ParseProtocolObject(Text, MaxProfileBytes);
    except on E: Exception do InvalidProfile; end;
    ValidateShape(Obj);
    if (FieldText(Obj,pfVersion) <> '4') or
      (FieldText(Obj,pfProtocol) <> ProtocolName) then InvalidProfile;
    PortText := FieldText(Obj,pfPort);
    if not TryStrToInt(PortText,PortNumber) then InvalidProfile;
    if (PortNumber < 1) or (PortNumber > 65535) or
      (PortText <> IntToStr(PortNumber)) then InvalidProfile;
    { Historical native profiles accept uppercase ASCII host labels and
      normalize their binding. TLS server names remain strictly lowercase. }
    Result.Host := LowerCase(FieldText(Obj,pfHost)); Result.Port := Word(PortNumber);
    Result.ServerKeyId := FieldText(Obj,pfServerKeyId);
    Result.ServerPublicKey := FieldText(Obj,pfServerPublicKey);
    Result.TlsServerName := FieldText(Obj,pfTlsServerName);
    Result.TlsCertificateSha256 := FieldText(Obj,pfTlsCertificateSha256);
    Result.PinState := '';
    if Obj.GetValue(ProfileRules[pfTlsPinState].Name) <> nil then
    begin
      Result.PinState := FieldText(Obj,pfTlsPinState);
      if Result.PinState = '' then InvalidProfile;
    end;
    ValidateFields(Result);
  finally Obj.Free; end;
end;
function WriteFields(const Fields: TConnectProfileFields): string;
var Obj: TJSONObject; Field: TProfileField; Value: TJSONValue;
begin
  ValidateFields(Fields);
  Obj := TJSONObject.Create;
  try
    for Field := Low(TProfileField) to High(TProfileField) do
    begin
      if (Field = pfTlsPinState) and (Fields.PinState = '') then Continue;
      case Field of
        pfVersion: Value := TJSONNumber.Create(4);
        pfProtocol: Value := TJSONString.Create(ProtocolName);
        pfHost: Value := TJSONString.Create(Fields.Host);
        pfPort: Value := TJSONNumber.Create(Fields.Port);
        pfServerKeyId: Value := TJSONString.Create(Fields.ServerKeyId);
        pfServerPublicKey: Value := TJSONString.Create(Fields.ServerPublicKey);
        pfTlsServerName: Value := TJSONString.Create(Fields.TlsServerName);
        pfTlsCertificateSha256: Value := TJSONString.Create(Fields.TlsCertificateSha256);
        pfTlsPinState: Value := TJSONString.Create(Fields.PinState);
      else InvalidProfile; Value := nil; end;
      Obj.AddPair(ProfileRules[Field].Name,Value);
    end;
    Result := Obj.ToJSON;
    if TEncoding.UTF8.GetByteCount(Result) > MaxProfileBytes then InvalidProfile;
  finally Obj.Free; end;
end;
class function TConnectServerProfile.Build(const Fields: TConnectProfileFields;
  const SharedWindow: ITlsPinWindow): TConnectServerProfile;
begin
  ValidateFields(Fields);
  Result := TConnectServerProfile.Create;
  try
    Result.FFields := Fields;
    if SharedWindow <> nil then Result.FPinWindow := SharedWindow
    else
    begin
      try
        Result.FPinWindow := NewTlsPinWindow(Fields.Host,Fields.Port,Fields.ServerKeyId,
          Fields.TlsServerName,Fields.TlsCertificateSha256,Fields.PinState);
      except on E: Exception do InvalidProfile; end;
    end;
    { Do not keep a stale exported floor beside the live shared state. }
    Result.FFields.PinState := '';
  except Result.Free; raise; end;
end;
class function TConnectServerProfile.Parse(const Text: string): TConnectServerProfile;
begin Result := Build(ReadFields(Text),nil); end;
class function TConnectServerProfile.FromJSON(const Text: string): TConnectServerProfile;
begin Result := Parse(Text); end;
class function TConnectServerProfile.CanonicalizeJSON(const Text: string): string;
var Fields: TConnectProfileFields; Checked: TConnectServerProfile;
begin
  Fields := ReadFields(Text); Checked := Build(Fields,nil);
  try Result := WriteFields(Fields); finally Checked.Free; end;
end;
function TConnectServerProfile.Clone: TConnectServerProfile;
begin
  if FPinWindow = nil then InvalidProfile;
  { Copies public immutable fields and the SAME interface owner. A temporary
    deserialize would reset its local clock; clones must never own that reset. }
  Result := Build(FFields,FPinWindow);
end;
function TConnectServerProfile.ToJSON: string;
var Snapshot: TConnectProfileFields;
begin
  if FPinWindow = nil then InvalidProfile;
  Snapshot := FFields; Snapshot.PinState := FPinWindow.ExportTrusted;
  Result := WriteFields(Snapshot);
end;
procedure TConnectServerProfile.SelectTlsPins(out Primary, Secondary: string);
begin FPinWindow.SelectPins(Primary,Secondary); end;
procedure TConnectServerProfile.CheckTlsPeer(const Pin: string);
begin FPinWindow.CheckPresented(Pin); end;
procedure TConnectServerProfile.LearnTlsPlan(const Text, PresentedPin: string;
  const BeforeCommit: TProc);
begin FPinWindow.LearnAuthenticated(Text,PresentedPin,BeforeCommit); end;
function TConnectServerProfile.GetHost: string;
begin Result := FFields.Host; end;
function TConnectServerProfile.GetPort: Word;
begin Result := FFields.Port; end;
function TConnectServerProfile.GetServerKeyId: string;
begin Result := FFields.ServerKeyId; end;
function TConnectServerProfile.GetServerPublicKey: string;
begin Result := FFields.ServerPublicKey; end;
function TConnectServerProfile.GetTlsServerName: string;
begin Result := FFields.TlsServerName; end;
function TConnectServerProfile.GetTlsCertificateSha256: string;
begin Result := FFields.TlsCertificateSha256; end;
function TConnectServerProfile.GetBindingID: string;
begin
  Result := ProtocolName + ':' + FFields.ServerKeyId + ':' + FFields.Host + ':' +
    IntToStr(FFields.Port) + ':' + FFields.TlsServerName + ':' + FFields.TlsCertificateSha256;
end;
function TConnectServerProfile.GetDisplayEndpoint: string;
begin Result := FFields.Host + ':' + IntToStr(FFields.Port); end;
end.
