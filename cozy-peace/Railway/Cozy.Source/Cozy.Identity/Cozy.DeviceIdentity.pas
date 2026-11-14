unit Cozy.DeviceIdentity;
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
interface
uses
{ Cozy central text imports. }
  Cozy.Strings.Identity,
 Cozy.Security, Cozy.Transport, Cozy.NHW.TpmQuote;
procedure EnsureDeviceIdentity(Transport:TConnectTransport;Security:TDeviceSecurity;
  const Stage,SessionID,SessionToken:string); overload;
procedure EnsureDeviceIdentity(Transport:TConnectTransport;Security:TDeviceSecurity;
  const Stage,SessionID,SessionToken:string; out Quoter:ICozyTpmQuoter); overload;
implementation
uses System.SysUtils, System.JSON, System.Diagnostics, System.NetEncoding,
  Cozy.DeviceKey, Cozy.DeviceIdentity.Contracts, Cozy.SensitiveText, Cozy.Api.Guid;
type
 TActivatedTpmQuoter=class(TInterfacedObject,ICozyTpmQuoter)
 private
  FKey:TPersistentDeviceKey;
 public
  constructor Create(var Key:TPersistentDeviceKey);
  destructor Destroy;override;
  function TryQuote(const QualifyingDigest:TBytes;out Quote:TJSONObject):Boolean;
 end;
constructor TActivatedTpmQuoter.Create(var Key:TPersistentDeviceKey);
begin inherited Create;FKey:=Key;Key:=nil;end;
destructor TActivatedTpmQuoter.Destroy;
begin FKey.Free;inherited;end;
function TActivatedTpmQuoter.TryQuote(const QualifyingDigest:TBytes;
 out Quote:TJSONObject):Boolean;
begin Result:=FKey.TryCreatePcrQuote(QualifyingDigest,Quote);end;

procedure EnsureDeviceIdentity(Transport:TConnectTransport;Security:TDeviceSecurity;
 const Stage,SessionID,SessionToken:string);
var Unused:ICozyTpmQuoter;
begin EnsureDeviceIdentity(Transport,Security,Stage,SessionID,SessionToken,Unused);end;

function DigestHex(const S:string):string;
var B,D:TBytes;I:Integer;E:TBase64Encoding;
const Digits=CozyText_DeviceIdentity_0123456789abcdef_203ca418;
begin
 E:=TBase64Encoding.Create(0);
 try
  B:=E.DecodeStringToBytes(S);
  if (Length(B)<>32) or (E.EncodeBytesToString(B)<>S) then
   raise EDeviceSecurity.Create(CozyText_DeviceIdentity_DEVICE_IDENTITY_RESPONSE_INVALID_3966fc72);
  D:=DeviceSHA256(B);SetLength(Result,64);
  for I:=0 to 31 do begin Result[I*2+1]:=Digits[(D[I] shr 4)+1];Result[I*2+2]:=Digits[(D[I] and 15)+1];end;
 finally WipeBytes(B);WipeBytes(D);E.Free;end;
end;
function Exchange(Transport:TConnectTransport;var Request:TDeviceIdentityRequest;
  BudgetMs:Cardinal):TJSONObject;
var Envelope:TJSONObject;V:TJSONValue;
begin
 Envelope:=nil;
 try
  if Request=nil then raise EDeviceSecurity.Create(CozyText_DeviceIdentity_DEVICE_IDENTITY_REQUEST_INVALID_4b16bc2b);
  Envelope:=Transport.PostJSON(CozyText_DeviceIdentity_device_404f0b5a,Request.Body,BudgetMs);
  if not IdentityBoolean(Envelope,CozyText_DeviceIdentity_ok_e0eb933e) then begin
   V:=Envelope.GetValue(CozyText_DeviceIdentity_error_ac2f1923);if V is TJSONString then raise EDeviceSecurity.Create(TJSONString(V).Value);
   raise EDeviceSecurity.Create(CozyText_DeviceIdentity_DEVICE_IDENTITY_SERVER_REJECTED_b1a3899e);
  end;
  V:=Envelope.GetValue(CozyText_DeviceIdentity_data_c49e730c);if not(V is TJSONObject) then raise EDeviceSecurity.Create(CozyText_DeviceIdentity_DEVICE_IDENTITY_RESPONSE_INVALID_3966fc72);
  { Only public policy/challenge/decision data are cloned. Request JSON and its
    token/activation boundary strings are destroyed together on EVERY return. }
  Result:=TJSONObject(V.Clone);
 finally Envelope.Free;FreeAndNil(Request);end;
end;
procedure EnsureDeviceIdentity(Transport:TConnectTransport;Security:TDeviceSecurity;
  const Stage,SessionID,SessionToken:string;out Quoter:ICozyTpmQuoter);
var Request:TDeviceIdentityRequest;PolicyJSON,ChallengeJSON,Response,Evidence:TJSONObject;
  Policy:TDeviceIdentityPolicy;Challenge:TDeviceIdentityChallenge;
  Key:TPersistentDeviceKey;SessionOwner,ActivationOwner:TCozySecret;
  RequestID,Context,Secret,Activation,Canonical,SecretDigest:string;
  G:TGUID;Clock:TStopwatch;ActivationCompleted:Boolean;
  function Budget:Cardinal;
  begin Result:=IdentityRemainingMs(Clock.ElapsedMilliseconds);end;
  procedure RequireTime;
  begin IdentityRemainingMs(Clock.ElapsedMilliseconds);end;
  function AuthBody(const Action:string):TDeviceIdentityRequest;
  begin Result:=TDeviceIdentityRequest.Create(Action,Stage,SessionID,Security.MachineID,SessionOwner);end;
begin
 Quoter:=nil;
 if (Transport=nil) or (Security=nil) or ((Stage<>'A') and (Stage<>'B') and (Stage<>'O')) then raise EDeviceSecurity.Create(CozyText_DeviceIdentity_DEVICE_IDENTITY_CONTEXT_INVALID_eedb57fd);
 Request:=nil;PolicyJSON:=nil;ChallengeJSON:=nil;Response:=nil;Evidence:=nil;Key:=nil;
 Clock:=TStopwatch.StartNew;ActivationCompleted:=False;
 try
  SessionOwner.Assign(SessionToken);
  Request:=AuthBody(CozyText_DeviceIdentity_policy_74a53f5e);PolicyJSON:=Exchange(Transport,Request,Budget);RequireTime;
  Policy:=ReadIdentityPolicy(PolicyJSON);FreeAndNil(PolicyJSON);
  Key:=TPersistentDeviceKey.Create(Policy.KeyNamespace,Policy.ProviderKind=CozyText_DeviceIdentity_PLATFORM_19753714);RequireTime;
  if WindowsApiCreateGUID(G)<>0 then raise EDeviceSecurity.Create(CozyText_DeviceIdentity_DEVICE_IDENTITY_RANDOM_FAILED_4da3e6be);RequestID:=LowerCase(Copy(GUIDToString(G),2,36));
  Request:=AuthBody(CozyText_DeviceIdentity_challenge_f83e5529);Request.Body.AddPair(CozyText_DeviceIdentity_requestId_b57dcdcc,RequestID);Request.Body.AddPair(CozyText_DeviceIdentity_publicKey_8761d8d7,Key.PublicKey);
  if Key.IsPlatform then Request.Body.AddPair(CozyText_DeviceIdentity_keyProvider_b5f0a7ae,CozyText_DeviceIdentity_PLATFORM_19753714) else Request.Body.AddPair(CozyText_DeviceIdentity_keyProvider_b5f0a7ae,CozyText_DeviceIdentity_SOFTWARE_56e82933);
  ChallengeJSON:=Exchange(Transport,Request,Budget);RequireTime;
  Context:=Stage+':'+SessionID+':'+Security.DeviceID;
  Challenge:=ReadIdentityChallenge(Policy,ChallengeJSON,Context,DevicePublicKeyID(Key.PublicKey),Key.IsPlatform);
  FreeAndNil(ChallengeJSON);
  Request:=AuthBody(CozyText_DeviceIdentity_complete_c4c3191f);Request.Body.AddPair(CozyText_DeviceIdentity_challengeId_8bd9f147,Challenge.ID);
  Request.Body.AddPair(CozyText_DeviceIdentity_signature_beb7e504,Key.Sign(Challenge.Canonical));Request.Body.AddPair(CozyText_DeviceIdentity_appSignature_ce7a48d1,Security.Sign(Challenge.Canonical));
  if Key.IsPlatform then begin Evidence:=Key.CreateEvidence(Challenge.Nonce);Request.Body.AddPair(CozyText_DeviceIdentity_tpmEvidence_9cb2943a,Evidence);Evidence:=nil;end;
  RequireTime;Response:=Exchange(Transport,Request,Budget);RequireTime;
  if IdentityText(Response,CozyText_DeviceIdentity_status_9c928e88,64)=CozyText_DeviceIdentity_TPM_ACTIVATION_REQUIRED_73c4a361 then begin
   ValidateIdentityActivation(Response,Challenge,Key.IsPlatform);RequireTime;
   Activation:=IdentityText(Response,CozyText_DeviceIdentity_activationBlob_3e3bafa6,4096);Secret:=Key.Activate(Activation);RequireTime;
   SecretDigest:=DigestHex(Secret);ValidateIdentityActivationDomain(Response,Challenge,SecretDigest);
   Canonical:=IdentityText(Response,CozyText_DeviceIdentity_activationCanonical_58e31c88);ActivationOwner.Assign(Secret,64);WipeText(Secret);WipeText(Activation);
   FreeAndNil(Response);RequireTime;Request:=AuthBody(CozyText_DeviceIdentity_tpmActivate_426165c2);Request.Body.AddPair(CozyText_DeviceIdentity_challengeId_8bd9f147,Challenge.ID);
   Request.AddActivationSecret(ActivationOwner);ActivationOwner.Clear;
   Request.Body.AddPair(CozyText_DeviceIdentity_signature_beb7e504,Key.Sign(Canonical));Request.Body.AddPair(CozyText_DeviceIdentity_appSignature_ce7a48d1,Security.Sign(Canonical));
   Response:=Exchange(Transport,Request,Budget);RequireTime;ActivationCompleted:=True;
  end;
  RequireTime;ValidateIdentityEnrolled(Response,Policy,ActivationCompleted);
  { Retain only the same AIK whose fresh ActivateCredential proof committed. }
  if ActivationCompleted and Key.IsPlatform then
   Quoter:=TActivatedTpmQuoter.Create(Key);
 finally
  { Caller owns the incoming session token; revoke ONLY operation-owned copies. }
  Evidence.Free;Request.Free;PolicyJSON.Free;ChallengeJSON.Free;Response.Free;Key.Free;
  SessionOwner.Clear;ActivationOwner.Clear;
  WipeText(Secret);WipeText(Activation);WipeText(Canonical);WipeText(SecretDigest);
  WipeText(Context);WipeText(RequestID);
  WipeText(Policy.KeyNamespace);WipeText(Policy.Mode);WipeText(Policy.ProviderKind);
  WipeText(Challenge.ID);WipeText(Challenge.Nonce);WipeText(Challenge.Context);
  WipeText(Challenge.Canonical);WipeText(Challenge.BindingID);
 end;
end;
end.
