program Cozy_TransportProbe;
{$APPTYPE CONSOLE}
{$RANGECHECKS ON}
{$OVERFLOWCHECKS ON}
{$B-}
{$IFNDEF GAME_TRANSPORT_TESTS}{$MESSAGE FATAL 'GAME_TRANSPORT_TESTS required'}{$ENDIF}
uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Handoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Handoff.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Network in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Network.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.TestsNetwork in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsNetwork.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}
 System.SysUtils, System.JSON, System.Classes, System.SyncObjs,
  System.Diagnostics, System.NetEncoding, System.DateUtils, Winapi.Windows,
  Cozy.Transport in '..\..\Cozy.Source\Cozy.Network\Cozy.Transport.pas',
  Cozy.JsonEnvelope in '..\..\Cozy.Source\Cozy.Handoff\Cozy.JsonEnvelope.pas',
  Cozy.Server.Profile, Cozy.Api.Contracts, Cozy.ProtocolJson, Cozy.Integrity,
  Cozy.WinApi;
{$I ..\Cozy.Protocol\Cozy.ProtocolSchemaCases.inc}
type
  THandleCng = NativeUInt;
  TReplyMode = (rmNormal, rmWrongID, rmWrongDirection, rmWrongKey, rmBadTag,
    rmSameNonce, rmInvalidUTF8, rmInvalidJSON, rmDuplicateJSON, rmReplay, rmTruncated);
function BCryptOpenAlgorithmProvider(out A:THandleCng; Name,Impl:PWideChar; Flags:DWORD):LongInt; stdcall; external 'bcrypt.dll';
function BCryptCloseAlgorithmProvider(A:THandleCng; Flags:DWORD):LongInt; stdcall; external 'bcrypt.dll';
function BCryptGenerateKeyPair(A:THandleCng; out K:THandleCng; Bits,Flags:DWORD):LongInt; stdcall; external 'bcrypt.dll';
function BCryptFinalizeKeyPair(K:THandleCng; Flags:DWORD):LongInt; stdcall; external 'bcrypt.dll';
function BCryptExportKey(K,ExportKey:THandleCng; Blob:PWideChar; Output:PByte; Size:DWORD; out Actual:DWORD; Flags:DWORD):LongInt; stdcall; external 'bcrypt.dll';
function BCryptSetProperty(K:THandleCng; Name:PWideChar; Input:PByte; Size,Flags:DWORD):LongInt; stdcall; external 'bcrypt.dll';
function BCryptGenerateSymmetricKey(A:THandleCng; out K:THandleCng; Obj:PByte; ObjSize:DWORD; Secret:PByte; Size,Flags:DWORD):LongInt; stdcall; external 'bcrypt.dll';
function BCryptDestroyKey(K:THandleCng):LongInt; stdcall; external 'bcrypt.dll';
function BCryptGenRandom(A:THandleCng; B:PByte; N,Flags:DWORD):LongInt; stdcall; external 'bcrypt.dll';
function BCryptEncrypt(K:THandleCng; Input:PByte; N:DWORD; Padding:Pointer; IV:PByte; IVSize:DWORD; Output:PByte; Size:DWORD; out Actual:DWORD; Flags:DWORD):LongInt; stdcall; external 'bcrypt.dll';
function BCryptDecrypt(K:THandleCng; Input:PByte; N:DWORD; Padding:Pointer; IV:PByte; IVSize:DWORD; Output:PByte; Size:DWORD; out Actual:DWORD; Flags:DWORD):LongInt; stdcall; external 'bcrypt.dll';
var Checks:Integer;
procedure Check(Value:Boolean; const Name:string);
begin if not Value then raise Exception.Create(Name); TInterlocked.Increment(Checks); end;
procedure Cng(Status:LongInt);
begin if Status<>0 then raise Exception.Create(CozyText_TransportProbe_PROBE_CNG_FAILED_4667be8b); end;
procedure Wipe(var B:TBytes);
begin if Length(B)>0 then FillChar(B[0],Length(B),0); B:=nil; end;
function Encode(const B:TBytes):string;
var E:TBase64Encoding;
begin E:=TBase64Encoding.Create(0);try Result:=E.EncodeBytesToString(B);finally E.Free;end;end;
function Decode(const S:string):TBytes;
begin Result:=TNetEncoding.Base64.DecodeStringToBytes(S);end;
procedure Auth(out Info:TGameAuthenticatedCipherInfo; const Nonce,AAD:TBytes; var Tag:TBytes);
begin
  FillChar(Info,SizeOf(Info),0); Info.Size:=SizeOf(Info);Info.Version:=1;
  Info.Nonce:=@Nonce[0];Info.NonceSize:=Length(Nonce);
  Info.AuthData:=@AAD[0];Info.AuthDataSize:=Length(AAD);
  Info.Tag:=@Tag[0];Info.TagSize:=Length(Tag);
end;
function RequestBody:TJSONObject;
var Packet:TJSONObject;
begin
  Packet:=ParseProtocolRequest(ProtocolSchemaCases[1],32768);
  try Result:=TJSONObject(Packet.GetValue(CozyText_TransportProbe_body_84e6be3a).Clone);finally Packet.Free;end;
end;
type
  TFixture=class
  private
    FAlgorithm,FKey:THandleCng;
  public
    Profile:TConnectServerProfile;
    Transport:TConnectTransport;
    Mode:TReplyMode;
    StopAt,ExpireAt,ThrowAt,BlockAt:string;
    Entered,ReleaseStage:TEvent;
    LastRequest,PreviousReply,PlanText:string;
    WrongPeer:Boolean;
    RequestView,ReplyView:TApiBuffer;
    RequestSeen,ReplySeen,ExpiredStageSeen:Boolean;
    ExchangeCount:Integer;
    constructor Create;
    destructor Destroy;override;
    function Exchange(const Frame:string; out PeerPin:string):string;
    procedure Stage(const Name:string; const View:TApiBuffer);
    procedure ClearStages;
    procedure CheckReleased;
  end;
  TPostWorker=class(TThread)
  private FTransport:TConnectTransport;
  protected procedure Execute;override;
  public
    Code:string;
    Returned:TJSONObject;
    Done:TEvent;
    constructor Create(Transport:TConnectTransport);
    destructor Destroy;override;
  end;
  TDestroyWorker=class(TThread)
  private FTransport:TConnectTransport;
  protected procedure Execute;override;
  public
    Cancelled,Done:TEvent;
    Code:string;
    constructor Create(Transport:TConnectTransport);
    destructor Destroy;override;
  end;
constructor TDestroyWorker.Create(Transport:TConnectTransport);
begin
  inherited Create(True);FreeOnTerminate:=False;
  Cancelled:=TEvent.Create(nil,True,False,'');Done:=TEvent.Create(nil,True,False,'');
  FTransport:=Transport;
end;
destructor TDestroyWorker.Destroy;
begin
  inherited Destroy;
  { If Start failed or the RTL skipped Execute after Terminate, ownership still
    belongs here. Execute uses FreeAndNil, so this cannot free twice. }
  FreeAndNil(FTransport);Cancelled.Free;Done.Free;
end;
procedure TDestroyWorker.Execute;
begin
  try
    try
      if FTransport=nil then Exit;
      FTransport.CancelPending;
      if Cancelled<>nil then Cancelled.SetEvent;
      FreeAndNil(FTransport);
    except on E:Exception do Code:=E.ClassName+':'+E.Message;end;
  finally if Done<>nil then Done.SetEvent;end;
end;
constructor TFixture.Create;
var Blob:TBytes; Actual:DWORD; O:TJSONObject;
begin
  inherited Create;
  Entered:=TEvent.Create(nil,True,False,'');ReleaseStage:=TEvent.Create(nil,True,False,'');
  Cng(BCryptOpenAlgorithmProvider(FAlgorithm,CozyText_TransportProbe_RSA_b8d429b3,nil,0));
  Cng(BCryptGenerateKeyPair(FAlgorithm,FKey,2048,0));Cng(BCryptFinalizeKeyPair(FKey,0));
  Cng(BCryptExportKey(FKey,0,CozyText_TransportProbe_RSAPUBLICBLOB_e4010f5c,nil,0,Actual,0));SetLength(Blob,Actual);
  Cng(BCryptExportKey(FKey,0,CozyText_TransportProbe_RSAPUBLICBLOB_e4010f5c,@Blob[0],Length(Blob),Actual,0));
  SetLength(Blob,Actual);O:=TJSONObject.Create;
  try
    O.AddPair(CozyText_TransportProbe_version_de275fe7,TJSONNumber.Create(4));O.AddPair(CozyText_TransportProbe_protocol_d012c037,CozyText_TransportProbe_GAME_CONNECT_4_81d13dc6);
    O.AddPair(CozyText_TransportProbe_host_50e970d0,CozyText_TransportProbe_probe_invalid_bd41846d);O.AddPair(CozyText_TransportProbe_port_934328c5,TJSONNumber.Create(443));
    O.AddPair(CozyText_TransportProbe_serverKeyId_3c4df898,IntegritySHA256Bytes(Blob));O.AddPair(CozyText_TransportProbe_serverPublicKey_ea86d85f,Encode(Blob));
    O.AddPair(CozyText_TransportProbe_tlsServerName_4e14a03d,CozyText_TransportProbe_probe_invalid_bd41846d);O.AddPair(CozyText_TransportProbe_tlsCertificateSha256_0effdbe6,StringOfChar('a',64));
    Profile:=TConnectServerProfile.FromJSON(O.ToJSON);
  finally O.Free;end;
  Transport:=TConnectTransport.Create(Profile);
  Transport.ConfigureTest(
    function(const Frame:string;out PeerPin:string):string begin Result:=Exchange(Frame,PeerPin);end,
    procedure(const Name:string;const View:TApiBuffer) begin Stage(Name,View);end);
end;
destructor TFixture.Destroy;
begin
  Transport.Free;Profile.Free;ReleaseStage.Free;Entered.Free;
  if FKey<>0 then BCryptDestroyKey(FKey);
  if FAlgorithm<>0 then BCryptCloseAlgorithmProvider(FAlgorithm,0);
  inherited Destroy;
end;
function TFixture.Exchange(const Frame:string;out PeerPin:string):string;
var O,R,Packet:TJSONObject; Wrapped,KeyBytes,Nonce,Tag,Cipher,Plain,AAD:TBytes;
  A,K:THandleCng; Actual:DWORD; OAEP:TGameOaepPaddingInfo; Info:TGameAuthenticatedCipherInfo;
  ID,Direction,KeyID,Text:string;
const Gcm=CozyText_TransportProbe_ChainingModeGCM_fc66d3e7;
begin
  Inc(ExchangeCount);PeerPin:=Profile.TlsCertificateSha256;
  if WrongPeer then PeerPin:=StringOfChar('f',64);
  if Mode=rmReplay then Exit(PreviousReply);
  O:=nil;R:=nil;Packet:=nil;A:=0;K:=0;
  try
    O:=ParseProtocolObject(Frame,65536);ID:=O.GetValue(CozyText_TransportProbe_requestId_7876e4c6).Value;
    Check(ID<>LastRequest,CozyText_TransportProbe_OUTER_REQUEST_ID_REUSED_88a9eea5);LastRequest:=ID;
    Wrapped:=Decode(O.GetValue(CozyText_TransportProbe_wrappedKey_731f7972).Value);SetLength(KeyBytes,256);
    FillChar(OAEP,SizeOf(OAEP),0);OAEP.Algorithm:=CozyText_TransportProbe_SHA256_b7cfd0a9;
    Cng(BCryptDecrypt(FKey,@Wrapped[0],Length(Wrapped),@OAEP,nil,0,
      @KeyBytes[0],Length(KeyBytes),Actual,4));
    Check(Actual=32,CozyText_TransportProbe_REQUEST_AES_KEY_LENGTH_8a21edfc);
    Cng(BCryptOpenAlgorithmProvider(A,CozyText_TransportProbe_AES_ebd231d2,nil,0));
    Cng(BCryptSetProperty(A,CozyText_TransportProbe_ChainingMode_e93ace4c,PByte(PWideChar(Gcm)),(Length(Gcm)+1)*2,0));
    Cng(BCryptGenerateSymmetricKey(A,K,nil,0,@KeyBytes[0],32,0));Wipe(KeyBytes);
    Nonce:=Decode(O.GetValue(CozyText_TransportProbe_nonce_e8044a4e).Value);Tag:=Decode(O.GetValue(CozyText_TransportProbe_tag_6ac25e46).Value);
    Cipher:=Decode(O.GetValue(CozyText_TransportProbe_ciphertext_4b31d9c8).Value);SetLength(Plain,Length(Cipher));
    AAD:=TEncoding.UTF8.GetBytes(CozyText_TransportProbe_GAME_CONNECT_4_REQUEST_b79708ef+ID+#10+Profile.ServerKeyId);
    Auth(Info,Nonce,AAD,Tag);
    Cng(BCryptDecrypt(K,@Cipher[0],Length(Cipher),@Info,nil,0,@Plain[0],Length(Plain),Actual,0));
    Check(Actual=DWORD(Length(Plain)),CozyText_TransportProbe_REQUEST_GCM_LENGTH_26ebd598);
    Packet:=ParseProtocolRequest(TEncoding.UTF8.GetString(Plain),32768);
    Check(Packet.GetValue(CozyText_TransportProbe_operation_5f40fd6f).Value=CozyText_TransportProbe_bootstrap_c7f6bcad,CozyText_TransportProbe_REQUEST_WIRE_OPERATION_ab7075b7);
    Wipe(Plain);FreeAndNil(Packet);
    Direction:=CozyText_TransportProbe_RESPONSE_d1681164;KeyID:=Profile.ServerKeyId;
    if Mode=rmWrongDirection then Direction:=CozyText_TransportProbe_REQUEST_f43c025f;
    if Mode=rmWrongKey then KeyID:=StringOfChar('0',64);
    if Mode<>rmSameNonce then
    begin SetLength(Nonce,12);Cng(BCryptGenRandom(0,@Nonce[0],12,2));end;
    Text:=CozyText_TransportProbe_JsonFixture_10caf599+#$D55C+#$AE00+CozyText_TransportProbe_Text_492865d1;
    case Mode of
      rmInvalidJSON:Text:=CozyText_TransportProbe_JsonFixture_739e981d;
      rmDuplicateJSON:Text:=CozyText_TransportProbe_JsonFixture_14c3c2ac;
    end;
    if PlanText<>'' then
    begin
      Packet:=ParseProtocolObject(Text,524288);
      Packet.AddPair(CozyText_TransportProbe_tlsPinPlan_f7849715,ParseProtocolObject(PlanText,8192));
      Text:=Packet.ToJSON;FreeAndNil(Packet);
    end;
    Plain:=TEncoding.UTF8.GetBytes(Text);
    if Mode=rmInvalidUTF8 then begin Plain:=TBytes.Create($C0,$AF);end;
    AAD:=TEncoding.UTF8.GetBytes(CozyText_TransportProbe_GAME_CONNECT_4_3698b017+Direction+#10+ID+#10+KeyID);
    SetLength(Tag,16);SetLength(Cipher,Length(Plain));Auth(Info,Nonce,AAD,Tag);
    Cng(BCryptEncrypt(K,@Plain[0],Length(Plain),@Info,nil,0,@Cipher[0],Length(Cipher),Actual,0));
    Check(Actual=DWORD(Length(Plain)),CozyText_TransportProbe_REPLY_GCM_LENGTH_ef831665);
    if Mode=rmBadTag then Tag[0]:=Tag[0] xor 1;
    if Mode=rmWrongID then ID:=CozyText_TransportProbe_00000000_0000_0000_0000_000000000000_e03ba063;
    R:=TJSONObject.Create;R.AddPair('v',TJSONNumber.Create(1));R.AddPair(CozyText_TransportProbe_requestId_7876e4c6,ID);
    R.AddPair(CozyText_TransportProbe_nonce_e8044a4e,Encode(Nonce));R.AddPair(CozyText_TransportProbe_ciphertext_4b31d9c8,Encode(Cipher));R.AddPair(CozyText_TransportProbe_tag_6ac25e46,Encode(Tag));
    Result:=R.ToJSON;PreviousReply:=Result;
    if Mode=rmTruncated then SetLength(Result,Length(Result)-1);
  finally
    Packet.Free;R.Free;O.Free;Wipe(KeyBytes);Wipe(Plain);
    UniqueString(Text);if Text<>'' then FillChar(PChar(Text)^,Length(Text)*SizeOf(Char),0);Text:='';
    if K<>0 then BCryptDestroyKey(K);if A<>0 then BCryptCloseAlgorithmProvider(A,0);
  end;
end;
procedure TFixture.Stage(const Name:string;const View:TApiBuffer);
var Clock:TStopwatch;
begin
  if Name=CozyText_TransportProbe_request_plain_5615992f then begin RequestView:=View;RequestSeen:=True;end;
  if Name=CozyText_TransportProbe_authenticated_plain_6738c0cc then begin ReplyView:=View;ReplySeen:=True;end;
  if Name=StopAt then Transport.CancelPending;
  if Name=ThrowAt then raise Exception.Create(CozyText_TransportProbe_PROBE_STAGE_FAILURE_c0cb9f28);
  if Name=ExpireAt then
  begin ExpiredStageSeen:=True;Clock:=TStopwatch.StartNew;while Clock.ElapsedMilliseconds<1100 do TThread.Yield;end;
  if Name=BlockAt then
  begin
    Entered.SetEvent;
    if ReleaseStage.WaitFor(5000)<>wrSignaled then raise Exception.Create(CozyText_TransportProbe_PROBE_BARRIER_TIMEOUT_5e522955);
  end;
end;
procedure TFixture.ClearStages;
begin
  StopAt:='';ExpireAt:='';ThrowAt:='';BlockAt:='';
  RequestSeen:=False;ReplySeen:=False;ExpiredStageSeen:=False;
  RequestView:=Default(TApiBuffer);ReplyView:=Default(TApiBuffer);
  Entered.ResetEvent;ReleaseStage.ResetEvent;
end;
procedure RequireRevoked(const View:TApiBuffer;const Name:string);
var Rejected:Boolean; P:Pointer;
begin
  Rejected:=False;P:=nil;
  try P:=View.Read(0,1);except on E:EInvalidOpException do Rejected:=True;end;
  Check(Rejected and (P=nil),Name);
end;
procedure TFixture.CheckReleased;
begin
  if RequestSeen then RequireRevoked(RequestView,CozyText_TransportProbe_REQUEST_BUFFER_SCOPE_REVOKED_7516227c);
  if ReplySeen then RequireRevoked(ReplyView,CozyText_TransportProbe_REPLY_BUFFER_SCOPE_REVOKED_e58e0fd9);
end;
constructor TPostWorker.Create(Transport:TConnectTransport);
begin inherited Create(True);FreeOnTerminate:=False;Done:=TEvent.Create(nil,True,False,'');FTransport:=Transport;end;
destructor TPostWorker.Destroy;
begin
  { Drain before freeing fields, including a never-started/failed-start thread. }
  inherited Destroy;Returned.Free;Done.Free;
end;
procedure TPostWorker.Execute;
var Body:TJSONObject;
begin
  Body:=nil;
  try
    if FTransport=nil then Exit;
    try Body:=RequestBody;Returned:=FTransport.PostJSON(CozyText_TransportProbe_bootstrap_c7f6bcad,Body);
    except on E:EConnectTransport do Code:=E.Code;
      on E:Exception do Code:=E.ClassName+':'+E.Message;end;
  finally Body.Free;if Done<>nil then Done.SetEvent;end;
end;
procedure ExpectFailure(F:TFixture;const Expected:string;Budget:Cardinal=0;CheckCleanup:Boolean=True);
var Body,Reply:TJSONObject; Rejected:Boolean;
begin
  Body:=RequestBody;Reply:=nil;Rejected:=False;
  try
    try Reply:=F.Transport.PostJSON(CozyText_TransportProbe_bootstrap_c7f6bcad,Body,Budget);
    except on E:EConnectTransport do begin Check(E.Code=Expected,CozyText_TransportProbe_WRONG_FAILURE_0af5e708+E.Code);Rejected:=True;end;end;
    Check(Rejected and (Reply=nil),CozyText_TransportProbe_FAILED_REQUEST_RETURNED_JSON_2ccc7644);
    Check(Body.GetValue(CozyText_TransportProbe_action_09329459).Value=CozyText_TransportProbe_keylessPolicy_22a83910,CozyText_TransportProbe_BORROWED_BODY_MUTATED_e93b2df7);
  finally Reply.Free;Body.Free;end;
  if CheckCleanup then F.CheckReleased;
end;
procedure Success(F:TFixture);
var Body,Reply:TJSONObject;
begin
  Body:=RequestBody;Reply:=nil;
  try
    Reply:=F.Transport.PostJSON(CozyText_TransportProbe_bootstrap_c7f6bcad,Body);
    Check(Reply.GetValue(CozyText_TransportProbe_token_9dea2991).Value=CozyText_TransportProbe_probe_only_value_33c42b0a,CozyText_TransportProbe_OWNED_RESULT_INVALID_8dcdfc42);
    Check(Reply.GetValue(CozyText_TransportProbe_korean_f2c2d143).Value=#$D55C+#$AE00,CozyText_TransportProbe_STRICT_UTF8_ROUNDTRIP_b0c957c5);
    Check(Reply.GetValue(CozyText_TransportProbe_tlsPinPlan_f7849715)=nil,CozyText_TransportProbe_PIN_METADATA_LEAKED_TO_API_ed207711);
    Check(Body.GetValue(CozyText_TransportProbe_action_09329459).Value=CozyText_TransportProbe_keylessPolicy_22a83910,CozyText_TransportProbe_BORROWED_BODY_OWNERSHIP_57b9384f);
  finally Body.Free;Reply.Free;end;
  F.CheckReleased;
end;
procedure OwnedEncoder;
var I:Integer;Packet,Body:TJSONObject;Old:TBytes;Owner:TApiSensitiveBuffer;
  Scope:TApiSensitiveScope;Borrowed:TApiBuffer;Operation,Original:string;Rejected:Boolean;
begin
  for I:=Low(ProtocolSchemaCases) to High(ProtocolSchemaCases) do
  begin
    Packet:=ParseProtocolRequest(ProtocolSchemaCases[I],32768);Owner:=nil;Scope:=nil;
    try
      Body:=TJSONObject(Packet.GetValue(CozyText_TransportProbe_body_84e6be3a));Operation:=Packet.GetValue(CozyText_TransportProbe_operation_5f40fd6f).Value;
      Original:=Body.ToJSON;Old:=EncodeRequestEnvelope(Operation,Body,32768);
      Owner:=EncodeRequestEnvelopeOwned(Operation,Body,Length(Old));Scope:=Owner.OpenRead;
      Check((Owner.Capacity=NativeUInt(Length(Old))) and
        CompareMem(@Old[0],Scope.Buffer.Read(0,Owner.Capacity),Length(Old)),CozyText_TransportProbe_OWNED_ENCODER_WIRE_EQUAL_99776fb0);
      Check(Body.ToJSON=Original,CozyText_TransportProbe_ENCODER_BORROWED_BODY_CHANGED_f5faf456);Borrowed:=Scope.Buffer;
      FreeAndNil(Scope);FreeAndNil(Owner);RequireRevoked(Borrowed,CozyText_TransportProbe_ENCODER_SCOPE_REVOKED_70e82c8a);
      Rejected:=False;
      try Owner:=EncodeRequestEnvelopeOwned(Operation,Body,Length(Old)-1);
      except on E:EArgumentException do Rejected:=E.Message=CozyText_TransportProbe_REQUEST_ENVELOPE_LIMIT_cceb3b89;end;
      Check(Rejected and (Owner=nil),CozyText_TransportProbe_OWNED_ENCODER_EXACT_BOUND_89292af6);
    finally Scope.Free;Owner.Free;Wipe(Old);Packet.Free;end;
  end;
end;
procedure ConcurrentCancel(F:TFixture;const Stage:string);
var Worker:TPostWorker; Started,Rejected:Boolean;Before:Integer;
begin
  F.ClearStages;F.Mode:=rmNormal;F.BlockAt:=Stage;
  Worker:=TPostWorker.Create(F.Transport);Started:=False;
  try
    Worker.Start;Started:=True;
    Check(F.Entered.WaitFor(5000)=wrSignaled,CozyText_TransportProbe_REQUEST_DID_NOT_REACH_BARRIER_0933c12b);
    F.Transport.CancelPending;
    Rejected:=False;
    try F.Transport.ResetCancellationAfterJoin;
    except on E:EInvalidOpException do Rejected:=E.Message=CozyText_TransportProbe_TRANSPORT_STILL_IN_USE_cd19470f;end;
    Check(Rejected,CozyText_TransportProbe_RESET_BEFORE_JOIN_ACCEPTED_76a50322);
    Before:=F.ExchangeCount;
    ExpectFailure(F,CozyText_TransportProbe_CONNECT_CANCELLED_7cb16165,0,False);
    Check(F.ExchangeCount=Before,CozyText_TransportProbe_CANCELLED_NEW_REQUEST_REACHED_WIRE_32c72b95);
    F.ReleaseStage.SetEvent;
    Check(Worker.Done.WaitFor(5000)=wrSignaled,CozyText_TransportProbe_CANCELLED_REQUEST_DID_NOT_DRAIN_cb313a69);
    Worker.WaitFor;Started:=False;
    Check((Worker.Code=CozyText_TransportProbe_CONNECT_CANCELLED_7cb16165) and (Worker.Returned=nil),CozyText_TransportProbe_LATE_REPLY_PUBLISHED_a3a1a74e);
    F.CheckReleased;
  finally
    F.ReleaseStage.SetEvent;if Started then Worker.WaitFor;Worker.Free;
  end;
  F.ClearStages;F.Transport.ResetCancellationAfterJoin;
  { Even after reset, a valid ciphertext reply for the previous UUID cannot apply. }
  F.Mode:=rmReplay;ExpectFailure(F,CozyText_TransportProbe_CONNECT_INVALID_RESPONSE_2bea095f);
  F.Mode:=rmNormal;F.ClearStages;Success(F);
end;
procedure ConcurrentDestroy;
var F:TFixture;Worker:TPostWorker;Closer:TDestroyWorker;
  Started,CloseStarted:Boolean;
begin
  F:=TFixture.Create;Worker:=nil;Closer:=nil;Started:=False;CloseStarted:=False;
  try
    F.BlockAt:=CozyText_TransportProbe_authenticated_plain_6738c0cc;Worker:=TPostWorker.Create(F.Transport);
    Worker.Start;Started:=True;
    Check(F.Entered.WaitFor(5000)=wrSignaled,CozyText_TransportProbe_DESTROY_DECRYPT_BARRIER_3aa4771f);
    Closer:=TDestroyWorker.Create(F.Transport);F.Transport:=nil;
    Closer.Start;CloseStarted:=True;
    Check(Closer.Cancelled.WaitFor(5000)=wrSignaled,CozyText_TransportProbe_DESTROY_CANCEL_BARRIER_da1b6874);
    Check(Closer.Done.WaitFor(0)=wrTimeout,CozyText_TransportProbe_DESTROY_FREED_ADMITTED_CRYPTO_177bd8b1);
    F.ReleaseStage.SetEvent;
    Check(Worker.Done.WaitFor(5000)=wrSignaled,CozyText_TransportProbe_DESTROY_REQUEST_NOT_DRAINED_7906c359);
    Worker.WaitFor;Started:=False;
    Check(Closer.Done.WaitFor(5000)=wrSignaled,CozyText_TransportProbe_DESTROY_GATE_NOT_DRAINED_e9a40baf);
    Closer.WaitFor;CloseStarted:=False;
    Check((Worker.Code=CozyText_TransportProbe_CONNECT_CANCELLED_7cb16165) and (Worker.Returned=nil),CozyText_TransportProbe_DESTROY_PUBLISHED_REPLY_3cd5029c);
    Check(Closer.Code='',CozyText_TransportProbe_DESTROY_FAILED_66e96dde);F.CheckReleased;
  finally
    F.ReleaseStage.SetEvent;
    if Started then Worker.WaitFor;
    if CloseStarted then Closer.WaitFor;
    Worker.Free;Closer.Free;F.Free;
  end;
end;
function PlanFor(Profile:TConnectServerProfile):string;
var O:TJSONObject;NowMs:Int64;Stamp:TDateTime;
begin
  Stamp:=Now;NowMs:=DateTimeToUnix(Stamp,False)*1000+MilliSecondOf(Stamp);
  O:=TJSONObject.Create;
  try
    O.AddPair(CozyText_TransportProbe_version_de275fe7,TJSONNumber.Create(1));O.AddPair(CozyText_TransportProbe_generation_5b9795ac,TJSONNumber.Create(1));
    O.AddPair(CozyText_TransportProbe_host_50e970d0,Profile.Host);O.AddPair(CozyText_TransportProbe_port_934328c5,TJSONNumber.Create(Profile.Port));
    O.AddPair(CozyText_TransportProbe_serverKeyId_3c4df898,Profile.ServerKeyId);O.AddPair(CozyText_TransportProbe_tlsServerName_4e14a03d,Profile.TlsServerName);
    O.AddPair(CozyText_TransportProbe_currentPin_1078aab6,Profile.TlsCertificateSha256);O.AddPair(CozyText_TransportProbe_nextPin_f53c2a2c,StringOfChar('b',64));
    O.AddPair(CozyText_TransportProbe_issuedAt_42e8ddfc,TJSONNumber.Create(NowMs));O.AddPair(CozyText_TransportProbe_notBefore_06251c1a,TJSONNumber.Create(NowMs+60000));
    O.AddPair(CozyText_TransportProbe_oldNotAfter_f39ba572,TJSONNumber.Create(NowMs+120000));Result:=O.ToJSON;
  finally O.Free;end;
end;
procedure PinPlanCancellation;
var F:TFixture;
begin
  F:=TFixture.Create;
  try
    F.PlanText:=PlanFor(F.Profile);
    F.StopAt:=CozyText_TransportProbe_before_publication_0e2ed9b6;ExpectFailure(F,CozyText_TransportProbe_CONNECT_CANCELLED_7cb16165);
    Check(Pos(CozyText_TransportProbe_tlsPinState_dd99c042,F.Profile.ToJSON)=0,CozyText_TransportProbe_CANCELLED_PLAN_CHANGED_SHARED_TRUST_40ca00d0);
    F.ClearStages;F.Transport.ResetCancellationAfterJoin;
    F.ExpireAt:=CozyText_TransportProbe_before_publication_0e2ed9b6;ExpectFailure(F,CozyText_TransportProbe_CONNECT_TIMEOUT_56345c06,1000);
    Check(F.ExpiredStageSeen,CozyText_TransportProbe_PIN_EXPIRY_STAGE_NOT_REACHED_8e169028);
    Check(Pos(CozyText_TransportProbe_tlsPinState_dd99c042,F.Profile.ToJSON)=0,CozyText_TransportProbe_EXPIRED_PLAN_CHANGED_SHARED_TRUST_dfd864a1);
    F.ClearStages;F.WrongPeer:=True;ExpectFailure(F,CozyText_TransportProbe_CONNECT_FAILED_3097c983);
    Check(Pos(CozyText_TransportProbe_tlsPinState_dd99c042,F.Profile.ToJSON)=0,CozyText_TransportProbe_UNPINNED_PEER_CHANGED_SHARED_TRUST_c8964278);
    F.ClearStages;F.WrongPeer:=False;Success(F);
    Check(Pos(CozyText_TransportProbe_tlsPinState_dd99c042,F.Profile.ToJSON)>0,CozyText_TransportProbe_AUTHENTICATED_PLAN_NOT_COMMITTED_8c63731a);
  finally F.Free;end;
end;
procedure Run;
const Stages:array[0..4] of string=(CozyText_TransportProbe_request_plain_5615992f,CozyText_TransportProbe_before_decrypt_79fc0403,CozyText_TransportProbe_authenticated_plain_6738c0cc,CozyText_TransportProbe_parsed_json_d4bccdcf,CozyText_TransportProbe_before_publication_0e2ed9b6);
var F:TFixture; I,J:Integer;Mode:TReplyMode;Expected:string;Rejected:Boolean;T:TConnectTransport;
begin
  OwnedEncoder;PinPlanCancellation;ConcurrentDestroy;
  Rejected:=False;T:=nil;
  try T:=TConnectTransport.Create(nil);
  except on E:EConnectTransport do Rejected:=E.Code=CozyText_TransportProbe_CONNECT_PROFILE_REQUIRED_674114e0;end;
  T.Free;Check(Rejected,CozyText_TransportProbe_PARTIAL_CONSTRUCTOR_CLEANUP_37a91890);
  F:=TFixture.Create;
  try
    Success(F);
    for Mode:=rmWrongID to rmTruncated do
    begin
      F.ClearStages;F.Mode:=Mode;
      case Mode of
        rmWrongDirection,rmWrongKey,rmBadTag:Expected:=CozyText_TransportProbe_CONNECT_AUTHENTICATION_FAILED_2b760dbd;
        rmInvalidJSON,rmDuplicateJSON:Expected:=CozyText_TransportProbe_CONNECT_FAILED_3097c983;
      else Expected:=CozyText_TransportProbe_CONNECT_INVALID_RESPONSE_2bea095f;end;
      ExpectFailure(F,Expected);
      if Mode in [rmWrongID,rmWrongDirection,rmWrongKey,rmBadTag,rmSameNonce,rmReplay,rmTruncated] then
        Check(not F.ReplySeen,CozyText_TransportProbe_UNAUTHENTICATED_PLAINTEXT_EXPOSED_405f6f7c);
      F.ClearStages;F.Mode:=rmNormal;Success(F);
    end;
    for I:=Low(Stages) to High(Stages) do
    begin
      F.ClearStages;F.StopAt:=Stages[I];ExpectFailure(F,CozyText_TransportProbe_CONNECT_CANCELLED_7cb16165);
      F.ClearStages;F.Transport.ResetCancellationAfterJoin;Success(F);
      F.ClearStages;F.ExpireAt:=Stages[I];ExpectFailure(F,CozyText_TransportProbe_CONNECT_TIMEOUT_56345c06,1000);
      Check(F.ExpiredStageSeen,CozyText_TransportProbe_DEADLINE_STAGE_NOT_REACHED_fcb07fd5);
      F.ClearStages;F.ThrowAt:=Stages[I];
      if Stages[I]=CozyText_TransportProbe_before_publication_0e2ed9b6 then
      begin
        { Probe-only callback exceptions must still release Candidate and gate. }
        Rejected:=False;
        try Success(F);except on E:Exception do Rejected:=E.Message=CozyText_TransportProbe_PROBE_STAGE_FAILURE_c0cb9f28;end;
        Check(Rejected,CozyText_TransportProbe_PUBLICATION_EXCEPTION_NOT_OBSERVED_1dba5977);F.CheckReleased;
      end
      else ExpectFailure(F,CozyText_TransportProbe_CONNECT_FAILED_3097c983);
      F.ClearStages;F.Transport.ResetCancellationAfterJoin;Success(F);
    end;
    for J:=1 to 4 do
      for I:=1 to High(Stages) do ConcurrentCancel(F,Stages[I]);
    Writeln(CozyText_TransportProbe_PASS_37705799,Checks,CozyText_TransportProbe_transport_checks_actual_CNG_owned_UTF8_JSON_canc_7da26707);
  finally F.Free;end;
end;
begin
  try Run;
  except on E:Exception do begin Writeln(E.ClassName,CozyText_TransportProbe_Text_2d5976cf,E.Message);Halt(1);end;end;
end.
