program Cozy_DeviceIdentityProbe;
{$APPTYPE CONSOLE}
{$R+}
{$Q+}
{$IFNDEF GAME_DEVICE_IDENTITY_PROBE}{$MESSAGE FATAL 'Probe requires its isolated test build define'}{$ENDIF}
uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Handoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Handoff.pas',
  Cozy.Strings.Identity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Identity.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.Security in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Security.pas',
  Cozy.Strings.TestsIdentity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsIdentity.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}
 System.SysUtils,System.JSON,Cozy.ProtocolJson,Cozy.Security,Cozy.DeviceKey,Cozy.Api.Pointer,Cozy.SensitiveText,
  Cozy.DeviceIdentity.Contracts in '..\..\Cozy.Source\Cozy.Identity\Cozy.DeviceIdentity.Contracts.pas';
function InputObject:TJSONObject;
var Line:string;
begin Readln(Line);try Result:=ParseProtocolObject(Line,32768);finally WipeText(Line);end;end;
function Text(Obj:TJSONObject;const Name:string):string;
var V:TJSONValue;
begin V:=Obj.GetValue(Name);if not(V is TJSONString) then raise EInvalidOpException.Create(CozyText_DeviceIdentityProbe_PROBE_INPUT_INVALID_aff70f8c);Result:=V.Value;end;
function Flag(Obj:TJSONObject;const Name:string):Boolean;
var V:TJSONValue;
begin V:=Obj.GetValue(Name);if not(V is TJSONBool) then raise EInvalidOpException.Create(CozyText_DeviceIdentityProbe_PROBE_INPUT_INVALID_aff70f8c);Result:=V.Value=CozyText_DeviceIdentityProbe_true_234d78de;end;
procedure Output(Obj:TJSONObject);
var S:string;
begin try S:=Obj.ToJSON;Writeln(S);Flush(System.Output);finally WipeText(S);Obj.Free;end;end;
{$I Cozy.DeviceIdentityContracts.inc}
procedure Run;
var Input,Answer:TJSONObject;Key:TPersistentDeviceKey;Namespace,Nonce,Secret,Canonical,PublicBefore:string;Platform,RemoveKey:Boolean;
begin
 Input:=nil;Answer:=nil;Key:=nil;RemoveKey:=True;
 try
 Input:=InputObject;Namespace:=Text(Input,CozyText_DeviceIdentityProbe_namespace_32c6452c);Nonce:=Text(Input,CozyText_DeviceIdentityProbe_nonce_2ef09157);Platform:=Flag(Input,CozyText_DeviceIdentityProbe_platform_6144299b);
 if Copy(Namespace,1,8)<>CozyText_DeviceIdentityProbe_f00dface_c18b9216 then raise EInvalidOpException.Create(CozyText_DeviceIdentityProbe_PROBE_NAMESPACE_REQUIRED_84ef3216);
 Key:=TPersistentDeviceKey.Create(Namespace,Platform);PublicBefore:=Key.PublicKey;
 if not Key.ProbePrivateExportBlocked then raise EInvalidOpException.Create(CozyText_DeviceIdentityProbe_PROBE_PRIVATE_EXPORT_ALLOWED_664a72a7);
 Answer:=TJSONObject.Create;Answer.AddPair(CozyText_DeviceIdentityProbe_publicKey_a2a6e7d3,PublicBefore);Answer.AddPair(CozyText_DeviceIdentityProbe_signature_053a2f48,Key.Sign(CozyText_DeviceIdentityProbe_GAME_DEVICE_NATIVE_PROBE_V1_87c40972+#10+Nonce));Answer.AddPair(CozyText_DeviceIdentityProbe_privateExportBlocked_ca40458d,TJSONTrue.Create);
 if Platform then Answer.AddPair(CozyText_DeviceIdentityProbe_evidence_f44805c1,Key.CreateEvidence(Nonce));Output(Answer);Answer:=nil;FreeAndNil(Input);
 Input:=InputObject;
 if Platform then begin
  Secret:=Key.Activate(Text(Input,CozyText_DeviceIdentityProbe_activationBlob_370ff936));Canonical:=CozyText_DeviceIdentityProbe_GAME_DEVICE_NATIVE_ACTIVATE_V1_6b0750af+#10+Secret;
  Answer:=TJSONObject.Create;Answer.AddPair(CozyText_DeviceIdentityProbe_secret_ca1e0b37,Secret);Answer.AddPair(CozyText_DeviceIdentityProbe_signature_053a2f48,Key.Sign(Canonical));Output(Answer);Answer:=nil;FreeAndNil(Input);Input:=InputObject;
 end;
 RemoveKey:=not Flag(Input,CozyText_DeviceIdentityProbe_keepForReopen_cc11ef3b);
 if RemoveKey then Key.DeleteProbeKey;
 FreeAndNil(Key);Answer:=TJSONObject.Create;Answer.AddPair(CozyText_DeviceIdentityProbe_closed_7becee38,TJSONTrue.Create);Answer.AddPair(CozyText_DeviceIdentityProbe_deleted_2af34e64,TJSONBool.Create(RemoveKey));Output(Answer);Answer:=nil;
 finally
 if (Key<>nil) and RemoveKey then try Key.DeleteProbeKey;except end;
 Answer.Free;Input.Free;Key.Free;WipeText(Secret);WipeText(Canonical);WipeText(Namespace);WipeText(Nonce);WipeText(PublicBefore);
 end;
end;
begin
 try
  if (ParamCount=1) and (ParamStr(1)=CozyText_DeviceIdentityProbe_contracts_8746403f) then RunDeviceIdentityContracts
  else begin SealApiPointerStorage;RunDeviceKeyConstructionContracts;Run;end;
 except on E:Exception do begin Writeln(CozyText_DeviceIdentityProbe_JsonFixture_0965e325);Writeln(ErrOutput,E.ClassName+CozyText_DeviceIdentityProbe_Text_f5eb2ef0+E.Message);ExitCode:=1;end;end;
end.
