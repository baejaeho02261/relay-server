unit Cozy.DeviceKey;
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
{$IFDEF GAME_DEVICE_IDENTITY_PROBE}{$DEFINE GAME_DEVICE_KEY_PROBE}{$ENDIF}
{$IFDEF GAME_RECOVERY_DEVICE_PROBE}{$DEFINE GAME_DEVICE_KEY_PROBE}{$ENDIF}
interface
uses
{ Cozy central text imports. }
  Cozy.Strings.Identity,
{$IF (Defined(GAME_DEVICE_IDENTITY_PROBE))}
  Cozy.Strings.TestsIdentity,
{$ENDIF}
 System.SysUtils, System.JSON, Cozy.Lifetime;
type
  { The persistent application key is separate from every A/B/O session key.
    Its private bytes never leave the Windows KSP. Server policy chooses the
    provider explicitly; platform-key failure never falls back to software. }
  TPersistentDeviceKey = class
  private
    FGate: TGameCallGate;
    FLock: TObject;
    FProvider, FKey, FAik: NativeUInt;
    FPlatform: Boolean;
    FPublicKey: string;
{$IFDEF GAME_RECOVERY_DEVICE_PROBE}
    FRecoveryOwned: Boolean;
    FRecoveryKeyName: string;
{$ENDIF}
    function PropertyBytes(Handle: NativeUInt; const Name: string;
      Maximum: Cardinal = 16384): TBytes;
    function PropertyDword(Handle: NativeUInt; const Name: string): Cardinal;
    function PasswordRequired(Handle: NativeUInt): Boolean;
    procedure OpenNamedKey(const Namespace: string);
    procedure LoadPublicKey;
    function SignCore(const Text: string): string;
    function GetPublicKey:string;
    function GetIsPlatform:Boolean;
    function TpmCommand(const Command: TBytes): TBytes;
    function ReadTpmPublic(Handle: Cardinal): TBytes;
    procedure Certify(const Nonce: TBytes; out Attest, Signature: TBytes);
    function ReadQuotePcrs: TBytes;
    procedure QuotePcrs(const QualifyingDigest: TBytes;
      out Attest, Signature: TBytes);
  public
    constructor Create(const Namespace: string; RequirePlatform: Boolean);
    destructor Destroy; override;
    function Sign(const Text: string): string;
    function CreateEvidence(const NonceBase64: string): TJSONObject;
    function Activate(const ActivationBase64: string): string;
    function TryCreatePcrQuote(const QualifyingDigest: TBytes;
      out Quote: TJSONObject): Boolean;
{$IFDEF GAME_DEVICE_KEY_PROBE}
    function ProbePrivateExportBlocked: Boolean;
{$ENDIF}
{$IFDEF GAME_DEVICE_IDENTITY_PROBE}
    procedure DeleteProbeKey;
{$ENDIF}
{$IFDEF GAME_RECOVERY_DEVICE_PROBE}
    { Existing mode never creates or changes a key. CreateNew is exclusive and
      intended only for the next namespace of an isolated restored server. }
    constructor OpenRecoveryProbe(const Namespace: string;
      RequirePlatform, CreateNew: Boolean);
    function RecoveryProviderImplementation: Cardinal;
    procedure DeleteRecoveryProbeKey;
{$ENDIF}
    property PublicKey: string read GetPublicKey;
    property IsPlatform: Boolean read GetIsPlatform;
  end;
{$IFDEF GAME_DEVICE_IDENTITY_PROBE}
procedure RunDeviceKeyConstructionContracts;
{$ENDIF}
implementation
uses Winapi.Windows, System.NetEncoding, Cozy.Security, Cozy.Api.ROR13,
  Cozy.Api.Pointer, Cozy.Api.Contracts, Cozy.Platform.ExportResolver;
type
  TOpenProvider = function(out Provider: NativeUInt; Name: PWideChar; Flags: Cardinal): LongInt; stdcall;
  TOpenKey = function(Provider: NativeUInt; out Key: NativeUInt; Name: PWideChar; Legacy, Flags: Cardinal): LongInt; stdcall;
  TCreateKey = function(Provider: NativeUInt; out Key: NativeUInt; Algorithm, Name: PWideChar; Legacy, Flags: Cardinal): LongInt; stdcall;
  TSetProperty = function(Handle: NativeUInt; Name: PWideChar; Data: PByte; Size, Flags: Cardinal): LongInt; stdcall;
  TGetProperty = function(Handle: NativeUInt; Name: PWideChar; Data: PByte; Size: Cardinal; out Actual: Cardinal; Flags: Cardinal): LongInt; stdcall;
  TFinalize = function(Key: NativeUInt; Flags: Cardinal): LongInt; stdcall;
  TExport = function(Key, Other: NativeUInt; Kind: PWideChar; Parameters: Pointer; Data: PByte; Size: Cardinal; out Actual: Cardinal; Flags: Cardinal): LongInt; stdcall;
  TSign = function(Key: NativeUInt; Padding: Pointer; Hash: PByte; HashSize: Cardinal; Signature: PByte; Size: Cardinal; out Actual: Cardinal; Flags: Cardinal): LongInt; stdcall;
  TDelete = function(Handle: NativeUInt; Flags: Cardinal): LongInt; stdcall;
  TFree = function(Handle: NativeUInt): LongInt; stdcall;
  TTbsSubmit = function(Context: NativeUInt; Locality, Priority: Cardinal; Command: PByte; CommandSize: Cardinal; Response: PByte; var ResponseSize: Cardinal): Cardinal; stdcall;
  TPadding = record Algorithm: PWideChar; end;
var
  OpenProviderSlot, OpenKeySlot, CreateKeySlot, SetSlot, GetSlot, FinalizeSlot,
    ExportSlot, SignSlot, FreeSlot, TbsSlot: TEncodedApiPointer;
{$IFDEF GAME_DEVICE_KEY_PROBE}
  DeleteSlot:TEncodedApiPointer;
{$ENDIF}
const
  Silent = $40;
  NteBadKeyset = Cardinal($80090016);
  NteNotFound = Cardinal($80090011);
  NteExists = Cardinal($8009000F);
procedure Check(Status: LongInt);
begin if Status <> 0 then raise EDeviceSecurity.CreateFmt(CozyText_DeviceKey_DEVICE_KEY_NATIVE_FAILURE_8_8x_f7d91fbb, [Cardinal(Status)]); end;
procedure Invalid;
begin raise EDeviceSecurity.Create(CozyText_DeviceKey_DEVICE_TPM_NATIVE_FORMAT_INVALID_4b3f4e26); end;
function Ptr(const B: TBytes): PByte;
begin if Length(B)=0 then Result:=nil else Result:=@B[0]; end;
function Encode(const B:TBytes):string;
var E:TBase64Encoding;
begin E:=TBase64Encoding.Create(0);try Result:=E.EncodeBytesToString(B);finally E.Free;end;end;
function Decode(const S:string; MinSize,MaxSize:Integer):TBytes;
var E:TBase64Encoding;
begin
 if (Length(S)<1) or (Length(S)>((MaxSize+2) div 3)*4) then Invalid;
 E:=TBase64Encoding.Create(0);try Result:=E.DecodeStringToBytes(S);
 if (Length(Result)<MinSize) or (Length(Result)>MaxSize) or (E.EncodeBytesToString(Result)<>S) then Invalid;
 finally E.Free;end;
end;
procedure Put(var B:TBytes; V:UInt64; N:Integer);
var P,I:Integer;
begin P:=Length(B);SetLength(B,P+N);for I:=N-1 downto 0 do begin B[P+I]:=Byte(V and 255);V:=V shr 8;end;end;
procedure Append(var B:TBytes;const V:TBytes);
var P:Integer;
begin P:=Length(B);SetLength(B,P+Length(V));if Length(V)>0 then Move(V[0],B[P],Length(V));end;
function Read(const B:TBytes;var P:Integer;N:Integer):UInt64;
var I:Integer;
begin if (N<0) or (N>8) or (P<0) or (P>Length(B)-N) then Invalid;Result:=0;for I:=1 to N do begin Result:=(Result shl 8) or B[P];Inc(P);end;end;
function Slice(const B:TBytes;var P:Integer;N:Integer):TBytes;
begin if (N<0) or (P<0) or (P>Length(B)-N) then Invalid;Result:=Copy(B,P,N);Inc(P,N);end;
function ReadSized(const B:TBytes;var P:Integer;Max:Integer):TBytes;
var N:Integer;
begin N:=Integer(Read(B,P,2));if N>Max then Invalid;Result:=Slice(B,P,N);end;
procedure SetDword(H:NativeUInt;const Name:string;Value:Cardinal);
begin Check(TSetProperty(DecodeApiPointer(SetSlot))(H,PWideChar(Name),@Value,SizeOf(Value),0));end;
function TPersistentDeviceKey.PropertyBytes(Handle:NativeUInt;const Name:string;Maximum:Cardinal):TBytes;
var Size,Actual:Cardinal;Span:TApiBuffer;
begin
 Size:=0;Check(TGetProperty(DecodeApiPointer(GetSlot))(Handle,PWideChar(Name),nil,0,Size,0));
 if (Size=0) or (Size>Maximum) then Invalid;SetLength(Result,Size);
 try Span:=TApiBuffer.WriteBytes(Result);Actual:=0;Check(TGetProperty(DecodeApiPointer(GetSlot))(Handle,PWideChar(Name),PByte(Span.Write(0,Size)),Size,Actual,0));Span.Completed(Size,Actual);if Actual<>Size then Invalid;
 except WipeBytes(Result);raise;end;
end;
function TPersistentDeviceKey.PropertyDword(Handle:NativeUInt;const Name:string):Cardinal;
var Actual:Cardinal;
begin Result:=0;Actual:=0;Check(TGetProperty(DecodeApiPointer(GetSlot))(Handle,PWideChar(Name),@Result,4,Actual,0));if Actual<>4 then Invalid;end;
function TPersistentDeviceKey.PasswordRequired(Handle:NativeUInt):Boolean;
var B:TBytes;
begin
 { PCPTool uses BYTE for NCRYPT_PCP_PASSWORD_REQUIRED_PROPERTY. }
 B:=PropertyBytes(Handle,CozyText_DeviceKey_PCP_PASSWORD_REQUIRED_5c13078a,1);try if Length(B)<>1 then Invalid;if B[0]>1 then Invalid;Result:=B[0]<>0;finally WipeBytes(B);end;
end;
{ Publish an attestation key only after all native initialization succeeds.
  A KSP may return a handle before reporting failure; the local owner retires
  that partial handle too. A retry must begin with a new, finalized key. }
procedure EnsureAttestationKey(var Key: NativeUInt; Provider: NativeUInt;
  CreateKey: TCreateKey; SetProperty: TSetProperty; FinalizeKey: TFinalize;
  FreeKey: TFree);
var Pending: NativeUInt; Bits, Usage: Cardinal;
begin
 if Key <> 0 then Exit;
 Pending := 0;
 try
  Check(CreateKey(Provider, Pending, CozyText_DeviceKey_RSA_2dc133d2, nil, 0, 0));
  if Pending = 0 then Invalid;
  Bits := 2048;
  Check(SetProperty(Pending, CozyText_DeviceKey_Length_d536c208, @Bits, SizeOf(Bits), 0));
  Usage := 8;
  Check(SetProperty(Pending, CozyText_DeviceKey_PCP_KEY_USAGE_POLICY_5c336c0a, @Usage, SizeOf(Usage), 0));
  Check(FinalizeKey(Pending, Silent));
  Key := Pending;
  Pending := 0;
 finally
  if Pending <> 0 then FreeKey(Pending);
 end;
end;
procedure TPersistentDeviceKey.OpenNamedKey(const Namespace:string);
var Name:string;Status:LongInt;
begin
 Name:=CozyText_DeviceKey_cozy_Client_Device_V2_afe74166+Namespace;
 Status:=TOpenKey(DecodeApiPointer(OpenKeySlot))(FProvider,FKey,PWideChar(Name),0,Silent);
 if (Cardinal(Status)=NteBadKeyset) or (Cardinal(Status)=NteNotFound) then begin
  Status:=TCreateKey(DecodeApiPointer(CreateKeySlot))(FProvider,FKey,CozyText_DeviceKey_RSA_2dc133d2,PWideChar(Name),0,0);
  if Cardinal(Status)=NteExists then Check(TOpenKey(DecodeApiPointer(OpenKeySlot))(FProvider,FKey,PWideChar(Name),0,Silent))
  else begin Check(Status);SetDword(FKey,CozyText_DeviceKey_Length_d536c208,2048);SetDword(FKey,CozyText_DeviceKey_Key_Usage_f41b66f7,2);SetDword(FKey,CozyText_DeviceKey_Export_Policy_4081fd22,0);Check(TFinalize(DecodeApiPointer(FinalizeSlot))(FKey,Silent));end;
 end else Check(Status);
 LoadPublicKey;
end;
procedure TPersistentDeviceKey.LoadPublicKey;
var B:TBytes;Size,Actual:Cardinal;Span:TApiBuffer;
begin
 if (FKey=0) or (PropertyDword(FKey,CozyText_DeviceKey_Length_d536c208)<>2048) or (PropertyDword(FKey,CozyText_DeviceKey_Export_Policy_4081fd22)<>0) or ((PropertyDword(FKey,CozyText_DeviceKey_Key_Usage_f41b66f7) and 2)=0) then Invalid;
 Size:=0;Check(TExport(DecodeApiPointer(ExportSlot))(FKey,0,CozyText_DeviceKey_RSAPUBLICBLOB_61c6df1f,nil,nil,0,Size,Silent));if (Size<280) or (Size>288) then Invalid;
 SetLength(B,Size);try Span:=TApiBuffer.WriteBytes(B);Actual:=0;Check(TExport(DecodeApiPointer(ExportSlot))(FKey,0,CozyText_DeviceKey_RSAPUBLICBLOB_61c6df1f,nil,PByte(Span.Write(0,Size)),Size,Actual,Silent));Span.Completed(Size,Actual);if Actual<>Size then Invalid;FPublicKey:=Encode(B);DevicePublicKeyID(FPublicKey);finally WipeBytes(B);end;
end;
constructor TPersistentDeviceKey.Create(const Namespace:string;RequirePlatform:Boolean);
var C:Char;ProviderName:string;
begin
 inherited Create;FGate:=TGameCallGate.Create;FLock:=TObject.Create;FPlatform:=RequirePlatform;
 if Length(Namespace)<>64 then Invalid;for C in Namespace do if not CharInSet(C,['0'..'9','a'..'f']) then Invalid;
 if FPlatform then ProviderName:=CozyText_DeviceKey_Microsoft_Platform_Crypto_Provider_4f52205c else ProviderName:=CozyText_DeviceKey_Microsoft_Software_Key_Storage_Provider_a762a8eb;
 Check(TOpenProvider(DecodeApiPointer(OpenProviderSlot))(FProvider,PWideChar(ProviderName),0));
 if FPlatform and (PropertyDword(FProvider,CozyText_DeviceKey_PCP_PLATFORM_TYPE_76105e34)<>2) then raise EDeviceSecurity.Create(CozyText_DeviceKey_DEVICE_TPM2_REQUIRED_64c4031f);
 OpenNamedKey(Namespace);
end;
destructor TPersistentDeviceKey.Destroy;
begin
 if FGate<>nil then FGate.CloseAndWait;
 if FAik<>0 then TFree(DecodeApiPointer(FreeSlot))(FAik);
{$IFDEF GAME_RECOVERY_DEVICE_PROBE}
 { Constructor failure/EOF cleanup affects only an exclusively created key.
   Existing original keys can never set FRecoveryOwned. }
 if FRecoveryOwned and (FKey<>0) then
   if TDelete(DecodeApiPointer(DeleteSlot))(FKey,Silent)=0 then FKey:=0;
 WipeText(FRecoveryKeyName);
{$ENDIF}
 if FKey<>0 then TFree(DecodeApiPointer(FreeSlot))(FKey);
 if FProvider<>0 then TFree(DecodeApiPointer(FreeSlot))(FProvider);
 WipeText(FPublicKey);FLock.Free;FGate.Free;inherited;
end;
function TPersistentDeviceKey.SignCore(const Text:string):string;
var Bytes,Digest,Sig:TBytes;Padding:TPadding;Size,Actual:Cardinal;InputSpan,OutputSpan:TApiBuffer;
begin
 if Length(Text)>16384 then Invalid;
 try Bytes:=TEncoding.UTF8.GetBytes(Text);SetLength(Digest,32);
 Digest:=DeviceSHA256(Bytes);
 Padding.Algorithm:=CozyText_DeviceKey_SHA256_a4121e60;Size:=0;Check(TSign(DecodeApiPointer(SignSlot))(FKey,@Padding,@Digest[0],32,nil,0,Size,Silent or 2));if Size<>256 then Invalid;SetLength(Sig,Size);Actual:=0;InputSpan:=TApiBuffer.ReadBytes(Digest);OutputSpan:=TApiBuffer.WriteBytes(Sig);RequireCngBuffers(InputSpan,OutputSpan,32,Size,False);
 Check(TSign(DecodeApiPointer(SignSlot))(FKey,@Padding,PByte(InputSpan.Read(0,32)),32,PByte(OutputSpan.Write(0,Size)),Size,Actual,Silent or 2));OutputSpan.Completed(Size,Actual);if Actual<>Size then Invalid;Result:=Encode(Sig);
 finally WipeBytes(Bytes);WipeBytes(Digest);WipeBytes(Sig);end;
end;
function TPersistentDeviceKey.GetPublicKey:string;
begin FGate.Enter;try TMonitor.Enter(FLock);try Result:=FPublicKey;finally TMonitor.Exit(FLock);end;finally FGate.Leave;end;end;
function TPersistentDeviceKey.GetIsPlatform:Boolean;
begin FGate.Enter;try TMonitor.Enter(FLock);try Result:=FPlatform;finally TMonitor.Exit(FLock);end;finally FGate.Leave;end;end;
function TPersistentDeviceKey.Sign(const Text:string):string;
begin FGate.Enter;try TMonitor.Enter(FLock);try Result:=SignCore(Text);finally TMonitor.Exit(FLock);end;finally FGate.Leave;end;end;
function TPersistentDeviceKey.TpmCommand(const Command:TBytes):TBytes;
var Context:NativeUInt;Actual,Size,Code:Cardinal;P:Integer;
begin
 Context:=0;Actual:=0;Check(TGetProperty(DecodeApiPointer(GetSlot))(FProvider,CozyText_DeviceKey_PCP_PLATFORMHANDLE_aa4ec853,@Context,SizeOf(Context),Actual,0));if (Actual<>SizeOf(Context)) or (Context=0) then Invalid;
 Size:=16384;SetLength(Result,Size);
 try Code:=TTbsSubmit(DecodeApiPointer(TbsSlot))(Context,0,200,Ptr(Command),Length(Command),@Result[0],Size);if Code<>0 then raise EDeviceSecurity.CreateFmt(CozyText_DeviceKey_DEVICE_TPM_COMMAND_8_8x_a3543e67,[Code]);
 if (Size<10) or (Size>16384) then Invalid;SetLength(Result,Size);P:=2;if Read(Result,P,4)<>Size then Invalid;Code:=Cardinal(Read(Result,P,4));if Code<>0 then raise EDeviceSecurity.CreateFmt(CozyText_DeviceKey_DEVICE_TPM_RESPONSE_8_8x_e90b0cd2,[Code]);
 except WipeBytes(Result);raise;end;
end;
function TPersistentDeviceKey.ReadTpmPublic(Handle:Cardinal):TBytes;
var Cmd,Response,Name,Qualified:TBytes;P:Integer;
begin
 try Put(Cmd,$8001,2);Put(Cmd,14,4);Put(Cmd,$173,4);Put(Cmd,Handle,4);Response:=TpmCommand(Cmd);P:=0;if Read(Response,P,2)<>$8001 then Invalid;P:=10;
 Result:=ReadSized(Response,P,2048);Name:=ReadSized(Response,P,68);Qualified:=ReadSized(Response,P,68);if (P<>Length(Response)) or (Length(Name)<>34) or (Length(Qualified)<>34) then Invalid;
 finally WipeBytes(Cmd);WipeBytes(Response);WipeBytes(Name);WipeBytes(Qualified);end;
end;
procedure TPersistentDeviceKey.Certify(const Nonce:TBytes;out Attest,Signature:TBytes);
var Cmd,Response:TBytes;P,ParameterSize,Start,N,I:Integer;
begin
 if Length(Nonce)<>32 then Invalid;
 if PasswordRequired(FKey) or PasswordRequired(FAik) then raise EDeviceSecurity.Create(CozyText_DeviceKey_DEVICE_TPM_AUTH_UNSUPPORTED_cb12d08c);
 try
 Put(Cmd,$8002,2);Put(Cmd,0,4);Put(Cmd,$148,4);Put(Cmd,PropertyDword(FKey,CozyText_DeviceKey_PCP_PLATFORMHANDLE_aa4ec853),4);Put(Cmd,PropertyDword(FAik,CozyText_DeviceKey_PCP_PLATFORMHANDLE_aa4ec853),4);Put(Cmd,18,4);
 for I:=1 to 2 do begin Put(Cmd,$40000009,4);Put(Cmd,0,2);Put(Cmd,0,1);Put(Cmd,0,2);end;
 Put(Cmd,Length(Nonce),2);Append(Cmd,Nonce);Put(Cmd,$10,2);
 N:=Length(Cmd);for I:=0 to 3 do Cmd[2+I]:=Byte(Cardinal(N) shr ((3-I)*8));
 Response:=TpmCommand(Cmd);P:=0;if Read(Response,P,2)<>$8002 then Invalid;P:=10;ParameterSize:=Integer(Read(Response,P,4));if (ParameterSize<6) or (ParameterSize>Length(Response)-P) then Invalid;Start:=P;
 Attest:=ReadSized(Response,P,2048);N:=P;if (Read(Response,P,2)<>$14) or (Read(Response,P,2)<>$0B) then Invalid;I:=Integer(Read(Response,P,2));if I<>256 then Invalid;
 { The complete TPMT_SIGNATURE is passed to the server, including algorithm. }
 P:=N+6+256;if P<>Start+ParameterSize then Invalid;Signature:=Copy(Response,N,262);
 for I:=1 to 2 do begin if Read(Response,P,2)<>0 then Invalid;if Read(Response,P,1)>1 then Invalid;if Read(Response,P,2)<>0 then Invalid;end;if P<>Length(Response) then Invalid;
 finally WipeBytes(Cmd);WipeBytes(Response);end;
end;
{ TPM 2.0 Part 3 PCR_Read / Quote, SHA-256 bank PCR 0..7. These commands
  use the PCP-owned TBS context and the already activated restricted AIK.
  Reading PCRs and producing a quote never changes TPM or platform state. }
function TPersistentDeviceKey.ReadQuotePcrs: TBytes;
var Cmd, Response, Digest: TBytes; P, I: Integer;
begin
 Result := nil;
 try
  try
  Put(Cmd,$8001,2);Put(Cmd,20,4);Put(Cmd,$17E,4);
  Put(Cmd,1,4);Put(Cmd,$0B,2);Put(Cmd,3,1);
  Put(Cmd,$FF,1);Put(Cmd,0,2);
  Response:=TpmCommand(Cmd);P:=0;
  if Read(Response,P,2)<>$8001 then Invalid;
  P:=10;
  Read(Response,P,4); { pcrUpdateCounter; quote digest binds the actual values. }
  if (Read(Response,P,4)<>1) or (Read(Response,P,2)<>$0B) or
    (Read(Response,P,1)<>3) or (Read(Response,P,1)<>$FF) or
    (Read(Response,P,2)<>0) or (Read(Response,P,4)<>8) then Invalid;
  for I:=0 to 7 do
  begin
   Digest:=ReadSized(Response,P,32);
   if Length(Digest)<>32 then Invalid;
   Append(Result,Digest);WipeBytes(Digest);
  end;
  if (P<>Length(Response)) or (Length(Result)<>256) then Invalid;
 except
  WipeBytes(Result);raise;
  end;
 finally
  WipeBytes(Cmd);WipeBytes(Response);WipeBytes(Digest);
 end;
end;

procedure TPersistentDeviceKey.QuotePcrs(const QualifyingDigest:TBytes;
  out Attest,Signature:TBytes);
var Cmd,Response:TBytes;P,ParameterSize,Start,N,I:Integer;
begin
 Attest:=nil;Signature:=nil;
 if Length(QualifyingDigest)<>32 then Invalid;
 if (FAik=0) or PasswordRequired(FAik) then
  raise EDeviceSecurity.Create(CozyText_DeviceKey_DEVICE_TPM_AUTH_UNSUPPORTED_cb12d08c);
 try
  Put(Cmd,$8002,2);Put(Cmd,0,4);Put(Cmd,$158,4);
  Put(Cmd,PropertyDword(FAik,CozyText_DeviceKey_PCP_PLATFORMHANDLE_aa4ec853),4);
  Put(Cmd,9,4);Put(Cmd,$40000009,4);Put(Cmd,0,2);Put(Cmd,0,1);Put(Cmd,0,2);
  Put(Cmd,32,2);Append(Cmd,QualifyingDigest);
  Put(Cmd,$14,2);Put(Cmd,$0B,2); { RSASSA/SHA-256, never NULL signature. }
  Put(Cmd,1,4);Put(Cmd,$0B,2);Put(Cmd,3,1);Put(Cmd,$FF,1);Put(Cmd,0,2);
  N:=Length(Cmd);for I:=0 to 3 do Cmd[2+I]:=Byte(Cardinal(N) shr ((3-I)*8));
  Response:=TpmCommand(Cmd);P:=0;if Read(Response,P,2)<>$8002 then Invalid;
  P:=10;ParameterSize:=Integer(Read(Response,P,4));
  if (ParameterSize<6) or (ParameterSize>Length(Response)-P) then Invalid;
  Start:=P;Attest:=ReadSized(Response,P,2048);N:=P;
  if (Read(Response,P,2)<>$14) or (Read(Response,P,2)<>$0B) or
    (Read(Response,P,2)<>256) then Invalid;
  Slice(Response,P,256);
  if P<>Start+ParameterSize then Invalid;
  Signature:=Copy(Response,N,262);
  if (Read(Response,P,2)<>0) or (Read(Response,P,1)>1) or
    (Read(Response,P,2)<>0) or (P<>Length(Response)) then Invalid;
 finally
  WipeBytes(Cmd);WipeBytes(Response);
 end;
end;

function QuoteMatches(const Attest, QualifyingDigest, Pcrs:TBytes):Boolean;
var P:Integer;Signer,Extra,Digest,Expected:TBytes;
begin
 Result:=False;P:=0;
 if (Length(QualifyingDigest)<>32) or (Length(Pcrs)<>256) then Exit;
 try
  if (Read(Attest,P,4)<>$FF544347) or (Read(Attest,P,2)<>$8018) then Exit;
  Signer:=ReadSized(Attest,P,68);
  if (Length(Signer)<>34) or (Signer[0]<>0) or (Signer[1]<>$0B) then Exit;
  Extra:=ReadSized(Attest,P,64);
  if (Length(Extra)<>32) or not CompareMem(@Extra[0],@QualifyingDigest[0],32) then Exit;
  Read(Attest,P,8);Read(Attest,P,4);Read(Attest,P,4);
  if Read(Attest,P,1)>1 then Exit; { safe=0 is uncertainty, not attack. }
  Read(Attest,P,8);
  if (Read(Attest,P,4)<>1) or (Read(Attest,P,2)<>$0B) or
    (Read(Attest,P,1)<>3) or (Read(Attest,P,1)<>$FF) or
    (Read(Attest,P,2)<>0) then Exit;
  Digest:=ReadSized(Attest,P,32);Expected:=DeviceSHA256(Pcrs);
  Result:=(Length(Digest)=32) and (Length(Expected)=32) and
    (P=Length(Attest)) and CompareMem(@Digest[0],@Expected[0],32);
 finally
  WipeBytes(Signer);WipeBytes(Extra);WipeBytes(Digest);WipeBytes(Expected);
 end;
end;

function TPersistentDeviceKey.TryCreatePcrQuote(const QualifyingDigest:TBytes;
  out Quote:TJSONObject):Boolean;
var Pcrs,Attest,Signature:TBytes;Attempt:Integer;Pending:TJSONObject;
begin
 Quote:=nil;Result:=False;Pending:=nil;
 if Length(QualifyingDigest)<>32 then Exit;
 FGate.Enter;
 try
  TMonitor.Enter(FLock);
  try
   if not FPlatform or (FAik=0) then Exit;
   try
    { Bounded retry handles PCR changes during Read/Quote without submitting
      a mismatched snapshot and without interpreting a normal change as attack. }
    for Attempt:=1 to 2 do
    begin
     WipeBytes(Pcrs);WipeBytes(Attest);WipeBytes(Signature);
     Pcrs:=ReadQuotePcrs;QuotePcrs(QualifyingDigest,Attest,Signature);
     if not QuoteMatches(Attest,QualifyingDigest,Pcrs) then Continue;
     Pending:=TJSONObject.Create;
     Pending.AddPair(CozyText_DeviceKey_version_5c837c80,TJSONNumber.Create(1));
     Pending.AddPair(CozyText_DeviceKey_attest_b00681b7,Encode(Attest));
     Pending.AddPair(CozyText_DeviceKey_signature_371c8e89,Encode(Signature));
     Pending.AddPair(CozyText_DeviceKey_pcrs_66d220c3,Encode(Pcrs));
     Quote:=Pending;Pending:=nil;Exit(True);
    end;
   except
    on E:EDeviceSecurity do Result:=False;
   end;
  finally
   Pending.Free;WipeBytes(Pcrs);WipeBytes(Attest);WipeBytes(Signature);
   TMonitor.Exit(FLock);
  end;
 finally FGate.Leave;end;
end;

function TPersistentDeviceKey.CreateEvidence(const NonceBase64:string):TJSONObject;
var Nonce,Ek,AkPublic,KeyPublic,Attest,Sig:TBytes;Evidence:TJSONObject;
begin
 FGate.Enter;
 try
  TMonitor.Enter(FLock);
  try
   if not FPlatform then raise EDeviceSecurity.Create(CozyText_DeviceKey_DEVICE_TPM_REQUIRED_0c105ba0);
   Nonce:=Decode(NonceBase64,32,32);
   EnsureAttestationKey(FAik,FProvider,
     TCreateKey(DecodeApiPointer(CreateKeySlot)),TSetProperty(DecodeApiPointer(SetSlot)),
     TFinalize(DecodeApiPointer(FinalizeSlot)),TFree(DecodeApiPointer(FreeSlot)));
   Ek:=PropertyBytes(FProvider,CozyText_DeviceKey_PCP_EKCERT_5cdb9eac,12288);
   AkPublic:=ReadTpmPublic(PropertyDword(FAik,CozyText_DeviceKey_PCP_PLATFORMHANDLE_aa4ec853));
   KeyPublic:=ReadTpmPublic(PropertyDword(FKey,CozyText_DeviceKey_PCP_PLATFORMHANDLE_aa4ec853));
   Certify(Nonce,Attest,Sig);
   Evidence:=TJSONObject.Create;
   try
    Evidence.AddPair(CozyText_DeviceKey_version_5c837c80,TJSONNumber.Create(1));
    Evidence.AddPair(CozyText_DeviceKey_ekCertificate_f7bb3b72,Encode(Ek));Evidence.AddPair(CozyText_DeviceKey_akPublic_4e7cb7d1,Encode(AkPublic));
    Evidence.AddPair(CozyText_DeviceKey_keyPublic_b9f391c3,Encode(KeyPublic));Evidence.AddPair(CozyText_DeviceKey_certify_ff61eef7,Encode(Attest));
    Evidence.AddPair(CozyText_DeviceKey_signature_371c8e89,Encode(Sig));
    Result:=Evidence;Evidence:=nil;
   finally Evidence.Free;end;
  finally
   WipeBytes(Nonce);WipeBytes(Ek);WipeBytes(AkPublic);WipeBytes(KeyPublic);
   WipeBytes(Attest);WipeBytes(Sig);TMonitor.Exit(FLock);
  end;
 finally FGate.Leave;end;
end;
function TPersistentDeviceKey.Activate(const ActivationBase64:string):string;
var Blob,Secret:TBytes;
begin
 FGate.Enter;try TMonitor.Enter(FLock);try
 if not FPlatform or (FAik=0) then raise EDeviceSecurity.Create(CozyText_DeviceKey_DEVICE_TPM_ACTIVATION_REQUIRED_0b7a869d);
 Blob:=Decode(ActivationBase64,300,2048);Check(TSetProperty(DecodeApiPointer(SetSlot))(FAik,CozyText_DeviceKey_PCP_TPM12_IDACTIVATION_ee67ee6d,Ptr(Blob),Length(Blob),0));Secret:=PropertyBytes(FAik,CozyText_DeviceKey_PCP_TPM12_IDACTIVATION_ee67ee6d,64);if Length(Secret)<>32 then Invalid;Result:=Encode(Secret);
 finally WipeBytes(Blob);WipeBytes(Secret);TMonitor.Exit(FLock);end;finally FGate.Leave;end;
end;
{$IFDEF GAME_DEVICE_KEY_PROBE}
function TPersistentDeviceKey.ProbePrivateExportBlocked:Boolean;
var Size:Cardinal;Status:LongInt;
begin
 FGate.Enter;try TMonitor.Enter(FLock);try Size:=0;
 Status:=TExport(DecodeApiPointer(ExportSlot))(FKey,0,CozyText_DeviceKey_RSAPRIVATEBLOB_d3e8a849,nil,nil,0,Size,Silent);Result:=Status<>0;
 finally TMonitor.Exit(FLock);end;finally FGate.Leave;end;
end;
{$ENDIF}
{$IFDEF GAME_DEVICE_IDENTITY_PROBE}
procedure TPersistentDeviceKey.DeleteProbeKey;
begin
 FGate.Enter;try TMonitor.Enter(FLock);try
 if FKey<>0 then begin Check(TDelete(DecodeApiPointer(DeleteSlot))(FKey,0));FKey:=0;end;
 finally TMonitor.Exit(FLock);end;finally FGate.Leave;end;
end;
{$ENDIF}
{$IFDEF GAME_RECOVERY_DEVICE_PROBE}
constructor TPersistentDeviceKey.OpenRecoveryProbe(const Namespace:string;
  RequirePlatform,CreateNew:Boolean);
var C:Char;ProviderName:string;ImplFlags:Cardinal;
begin
 inherited Create;FGate:=TGameCallGate.Create;FLock:=TObject.Create;
 FPlatform:=RequirePlatform;
 if Length(Namespace)<>64 then Invalid;
 for C in Namespace do if not CharInSet(C,['0'..'9','a'..'f']) then Invalid;
 if FPlatform then ProviderName:=CozyText_DeviceKey_Microsoft_Platform_Crypto_Provider_4f52205c
 else ProviderName:=CozyText_DeviceKey_Microsoft_Software_Key_Storage_Provider_a762a8eb;
 Check(TOpenProvider(DecodeApiPointer(OpenProviderSlot))(FProvider,PWideChar(ProviderName),0));
 ImplFlags:=PropertyDword(FProvider,CozyText_DeviceKey_Impl_Type_c99c1ee9);
 if FPlatform then begin
  if ((ImplFlags and 1)=0) or (PropertyDword(FProvider,CozyText_DeviceKey_PCP_PLATFORM_TYPE_76105e34)<>2) then
   raise EDeviceSecurity.Create(CozyText_DeviceKey_RECOVERY_PROBE_TPM2_REQUIRED_6728737f);
 end else if (ImplFlags and 2)=0 then
  raise EDeviceSecurity.Create(CozyText_DeviceKey_RECOVERY_PROBE_SOFTWARE_PROVIDER_REQUIRED_d9ac1fd9);
 FRecoveryKeyName:=CozyText_DeviceKey_cozy_Client_Device_V2_afe74166+Namespace;
 if CreateNew then begin
  { Never use NCRYPT_OVERWRITE_KEY_FLAG, never reopen NTE_EXISTS. }
  Check(TCreateKey(DecodeApiPointer(CreateKeySlot))(FProvider,FKey,CozyText_DeviceKey_RSA_2dc133d2,PWideChar(FRecoveryKeyName),0,0));
  if FKey=0 then Invalid;
  FRecoveryOwned:=True;
  SetDword(FKey,CozyText_DeviceKey_Length_d536c208,2048);SetDword(FKey,CozyText_DeviceKey_Key_Usage_f41b66f7,2);
  SetDword(FKey,CozyText_DeviceKey_Export_Policy_4081fd22,0);
  Check(TFinalize(DecodeApiPointer(FinalizeSlot))(FKey,Silent));
 end else begin
  { Do not call OpenNamedKey: its normal product creation behavior is forbidden
    when the operator asks to prove a key already associated with a backup. }
  Check(TOpenKey(DecodeApiPointer(OpenKeySlot))(FProvider,FKey,PWideChar(FRecoveryKeyName),0,Silent));
 end;
 LoadPublicKey;
 if not ProbePrivateExportBlocked then
  raise EDeviceSecurity.Create(CozyText_DeviceKey_RECOVERY_PROBE_PRIVATE_EXPORT_ALLOWED_ee83d601);
end;
function TPersistentDeviceKey.RecoveryProviderImplementation:Cardinal;
begin
 FGate.Enter;
 try TMonitor.Enter(FLock);
  try Result:=PropertyDword(FProvider,CozyText_DeviceKey_Impl_Type_c99c1ee9);finally TMonitor.Exit(FLock);end;
 finally FGate.Leave;end;
end;
procedure TPersistentDeviceKey.DeleteRecoveryProbeKey;
var Existing:NativeUInt;Status:LongInt;
begin
 FGate.Enter;
 try TMonitor.Enter(FLock);
  try
   if not FRecoveryOwned or (FKey=0) then
    raise EDeviceSecurity.Create(CozyText_DeviceKey_RECOVERY_PROBE_KEY_NOT_OWNED_4c86bb89);
   Check(TDelete(DecodeApiPointer(DeleteSlot))(FKey,Silent));
   FKey:=0;FRecoveryOwned:=False;WipeText(FPublicKey);
   Existing:=0;
   Status:=TOpenKey(DecodeApiPointer(OpenKeySlot))(FProvider,Existing,PWideChar(FRecoveryKeyName),0,Silent);
   if Existing<>0 then TFree(DecodeApiPointer(FreeSlot))(Existing);
   if Status=0 then raise EDeviceSecurity.Create(CozyText_DeviceKey_RECOVERY_PROBE_KEY_STILL_PRESENT_6928ce0f);
   if (Cardinal(Status)<>NteBadKeyset) and (Cardinal(Status)<>NteNotFound) then Check(Status);
  finally TMonitor.Exit(FLock);end;
 finally FGate.Leave;end;
end;
{$ENDIF}
{$IFDEF GAME_DEVICE_IDENTITY_PROBE}
{$I ..\..\Cozy.Tests\Cozy.Identity\Cozy.DeviceKeyContracts.inc}
{$ENDIF}
initialization
{$IFDEF GAME_DEVICE_KEY_PROBE}
 BindApiPointer(DeleteSlot,RequireProcAddressHash64(CozyText_DeviceKey_ncrypt_dll_141aaf12,HASH_NCryptDeleteKey));
{$ENDIF}
 BindApiPointer(OpenProviderSlot,RequireProcAddressHash64(CozyText_DeviceKey_ncrypt_dll_141aaf12,HASH_NCryptOpenStorageProvider));
 BindApiPointer(OpenKeySlot,RequireProcAddressHash64(CozyText_DeviceKey_ncrypt_dll_141aaf12,HASH_NCryptOpenKey));
 BindApiPointer(CreateKeySlot,RequireProcAddressHash64(CozyText_DeviceKey_ncrypt_dll_141aaf12,HASH_NCryptCreatePersistedKey));
 BindApiPointer(SetSlot,RequireProcAddressHash64(CozyText_DeviceKey_ncrypt_dll_141aaf12,HASH_NCryptSetProperty));
 BindApiPointer(GetSlot,RequireProcAddressHash64(CozyText_DeviceKey_ncrypt_dll_141aaf12,HASH_NCryptGetProperty));
 BindApiPointer(FinalizeSlot,RequireProcAddressHash64(CozyText_DeviceKey_ncrypt_dll_141aaf12,HASH_NCryptFinalizeKey));
 BindApiPointer(ExportSlot,RequireProcAddressHash64(CozyText_DeviceKey_ncrypt_dll_141aaf12,HASH_NCryptExportKey));
 BindApiPointer(SignSlot,RequireProcAddressHash64(CozyText_DeviceKey_ncrypt_dll_141aaf12,HASH_NCryptSignHash));
 BindApiPointer(FreeSlot,RequireProcAddressHash64(CozyText_DeviceKey_ncrypt_dll_141aaf12,HASH_NCryptFreeObject));
 BindApiPointer(TbsSlot,RequireProcAddressHash64(CozyText_DeviceKey_tbs_dll_f9906adf,HASH_Tbsip_Submit_Command));
end.
