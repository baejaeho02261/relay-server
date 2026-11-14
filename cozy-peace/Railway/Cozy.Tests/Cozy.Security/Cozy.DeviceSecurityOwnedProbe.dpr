program Cozy_DeviceSecurityOwnedProbe;
{$APPTYPE CONSOLE}
{$R+}
{$Q+}
{$B-}
{$IFNDEF GAME_DEVICE_SECURITY_TESTS}{$MESSAGE FATAL 'GAME_DEVICE_SECURITY_TESTS required'}{$ENDIF}
uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.Security in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Security.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}
  Cozy.Strings.TestsSecurity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsSecurity.pas',

  System.SysUtils, System.Classes, System.SyncObjs, System.Diagnostics,
  System.NetEncoding, Winapi.Windows,
  Cozy.Security in '..\..\Cozy.Source\Cozy.Security\Cozy.Security.pas',
  Cozy.Api.Contracts, Cozy.Api.Pointer;
type
  TCngHandle = NativeUInt;
  TPkcs1Padding = record Algorithm: PWideChar; end;
function BCryptOpenAlgorithmProvider(out A:TCngHandle; Name,Impl:PWideChar; Flags:DWORD):LongInt; stdcall; external 'bcrypt.dll';
function BCryptCloseAlgorithmProvider(A:TCngHandle; Flags:DWORD):LongInt; stdcall; external 'bcrypt.dll';
function BCryptImportKeyPair(A,ImportKey:TCngHandle; Blob:PWideChar; out Key:TCngHandle; Input:PByte; Count,Flags:DWORD):LongInt; stdcall; external 'bcrypt.dll';
function BCryptDestroyKey(Key:TCngHandle):LongInt; stdcall; external 'bcrypt.dll';
function BCryptVerifySignature(Key:TCngHandle; Padding:Pointer; Hash:PByte; HashCount:DWORD; Sig:PByte; SigCount,Flags:DWORD):LongInt; stdcall; external 'bcrypt.dll';
var Checks:Integer;
procedure Check(Value:Boolean; const Name:string);
begin if not Value then raise Exception.Create(Name); Inc(Checks); end;
procedure Cng(Status:LongInt);
begin if Status<>0 then raise Exception.Create(CozyText_DeviceSecurityOwnedProbe_PROBE_CNG_FAILED_f3dbe44e); end;
procedure RequireRevoked(const View:TApiBuffer);
var Rejected:Boolean; N:NativeUInt;
begin
  Rejected:=False; N:=0;
  try N:=View.Capacity; except on E:EInvalidOpException do Rejected:=E.Message=CozyText_DeviceSecurityOwnedProbe_API_SENSITIVE_VIEW_REVOKED_cd75fcaa; end;
  Check(Rejected and (N=0),CozyText_DeviceSecurityOwnedProbe_SCOPED_VIEW_NOT_REVOKED_c75022df);
end;
type
  TFixture=class
  public
    Security:TDeviceSecurity;
    InputView,DigestView,SignatureView:TApiBuffer;
    InputSeen,DigestSeen,SignatureSeen:Boolean;
    ThrowAt,BlockAt:string;
    Entered,ReleaseStage:TEvent;
    constructor Create;
    destructor Destroy;override;
    procedure Observe(const Stage:string; const View:TApiBuffer);
    procedure CheckRevoked;
    procedure ClearViews;
  end;
  TSignWorker=class(TThread)
  private FSecurity:TDeviceSecurity;
  protected procedure Execute;override;
  public
    Code,Signature:string;
    Done:TEvent;
    constructor Create(Security:TDeviceSecurity);
    destructor Destroy;override;
  end;
  TCloseWorker=class(TThread)
  private FSecurity:TDeviceSecurity;
  protected procedure Execute;override;
  public
    Code:string;
    Done:TEvent;
    constructor Create(Security:TDeviceSecurity);
    destructor Destroy;override;
  end;
constructor TFixture.Create;
begin
  inherited Create;
  Entered:=TEvent.Create(nil,True,False,'');
  ReleaseStage:=TEvent.Create(nil,True,False,'');
  Security:=TDeviceSecurity.Create;
  Security.TestObserver:=procedure(const Stage:string;const View:TApiBuffer) begin Observe(Stage,View);end;
end;
destructor TFixture.Destroy;
begin
  if ReleaseStage<>nil then ReleaseStage.SetEvent;
  Security.Free;
  ReleaseStage.Free;Entered.Free;
  inherited Destroy;
end;
procedure TFixture.Observe(const Stage:string; const View:TApiBuffer);
begin
  if Stage=CozyText_DeviceSecurityOwnedProbe_sign_input_a1ee8699 then begin InputView:=View;InputSeen:=True;end;
  if Stage=CozyText_DeviceSecurityOwnedProbe_sign_digest_208df152 then begin DigestView:=View;DigestSeen:=True;end;
  if Stage=CozyText_DeviceSecurityOwnedProbe_sign_signature_c8b7f2e2 then begin SignatureView:=View;SignatureSeen:=True;end;
  if Stage=ThrowAt then raise EInvalidOpException.Create(CozyText_DeviceSecurityOwnedProbe_PROBE_INJECTED_FAILURE_acc05bdc);
  if Stage=BlockAt then
  begin
    Entered.SetEvent;
    if ReleaseStage.WaitFor(10000)<>wrSignaled then raise Exception.Create(CozyText_DeviceSecurityOwnedProbe_PROBE_BLOCK_TIMEOUT_1d52981a);
  end;
end;
procedure TFixture.CheckRevoked;
begin
  if InputSeen then RequireRevoked(InputView);
  if DigestSeen then RequireRevoked(DigestView);
  if SignatureSeen then RequireRevoked(SignatureView);
end;
procedure TFixture.ClearViews;
begin
  InputView:=Default(TApiBuffer);DigestView:=Default(TApiBuffer);SignatureView:=Default(TApiBuffer);
  InputSeen:=False;DigestSeen:=False;SignatureSeen:=False;
  ThrowAt:='';BlockAt:='';Entered.ResetEvent;ReleaseStage.ResetEvent;
end;
constructor TSignWorker.Create(Security:TDeviceSecurity);
begin
  inherited Create(True);FreeOnTerminate:=False;FSecurity:=Security;
  Done:=TEvent.Create(nil,True,False,'');
end;
procedure TSignWorker.Execute;
begin
  try
    try Signature:=FSecurity.Sign(CozyText_DeviceSecurityOwnedProbe_native_concurrent_signing_3b76469b);
    except on E:Exception do Code:=E.Message; end;
  finally Done.SetEvent;end;
end;
destructor TSignWorker.Destroy;
begin inherited Destroy;WipeText(Signature);Done.Free;end;
constructor TCloseWorker.Create(Security:TDeviceSecurity);
begin
  inherited Create(True);FreeOnTerminate:=False;FSecurity:=Security;
  Done:=TEvent.Create(nil,True,False,'');
end;
procedure TCloseWorker.Execute;
begin
  try
    try FSecurity.Close;except on E:Exception do Code:=E.Message;end;
  finally Done.SetEvent;end;
end;
destructor TCloseWorker.Destroy;
begin inherited Destroy;Done.Free;end;
procedure VerifySignature(Security:TDeviceSecurity;const Text,Sig:string);
var Algorithm,Key:TCngHandle;PublicBlob,Bytes,Digest,Signature:TBytes;Padding:TPkcs1Padding;Encoding:TBase64Encoding;
begin
  Algorithm:=0;Key:=0;Encoding:=TBase64Encoding.Create(0);
  try
    PublicBlob:=Encoding.DecodeStringToBytes(Security.PublicKeyBlob);
    Signature:=Encoding.DecodeStringToBytes(Sig);
    Check((Length(Signature)=256) and (Length(Sig)=344),CozyText_DeviceSecurityOwnedProbe_SIGNATURE_WIDTH_6bcd16aa);
    Check(Encoding.EncodeBytesToString(Signature)=Sig,CozyText_DeviceSecurityOwnedProbe_CANONICAL_BASE64_bfe5076f);
    Bytes:=TEncoding.UTF8.GetBytes(Text);Digest:=DeviceSHA256(Bytes);
    Cng(BCryptOpenAlgorithmProvider(Algorithm,CozyText_DeviceSecurityOwnedProbe_RSA_06de8397,nil,0));
    Cng(BCryptImportKeyPair(Algorithm,0,CozyText_DeviceSecurityOwnedProbe_RSAPUBLICBLOB_3369ee46,Key,@PublicBlob[0],Length(PublicBlob),0));
    Padding.Algorithm:=CozyText_DeviceSecurityOwnedProbe_SHA256_7da5b670;
    Check(BCryptVerifySignature(Key,@Padding,@Digest[0],Length(Digest),@Signature[0],Length(Signature),2)=0,CozyText_DeviceSecurityOwnedProbe_REAL_CNG_SIGNATURE_VERIFY_5ee10da8);
    Digest[0]:=Digest[0] xor 1;
    Check(BCryptVerifySignature(Key,@Padding,@Digest[0],Length(Digest),@Signature[0],Length(Signature),2)<>0,CozyText_DeviceSecurityOwnedProbe_ALTERED_DIGEST_ACCEPTED_d932b753);
  finally
    if Key<>0 then BCryptDestroyKey(Key);
    if Algorithm<>0 then BCryptCloseAlgorithmProvider(Algorithm,0);
    WipeBytes(PublicBlob);WipeBytes(Bytes);WipeBytes(Digest);WipeBytes(Signature);Encoding.Free;
  end;
end;
procedure SigningCases;
const Stages:array[0..2] of string=(CozyText_DeviceSecurityOwnedProbe_sign_input_a1ee8699,CozyText_DeviceSecurityOwnedProbe_sign_digest_208df152,CozyText_DeviceSecurityOwnedProbe_sign_signature_c8b7f2e2);
var F:TFixture;I:Integer;Text,AliasText,Sig:string;Rejected:Boolean;
begin
  F:=TFixture.Create;
  try
    Text:=CozyText_DeviceSecurityOwnedProbe_Text_a68b698f+StringOfChar('x',4097);AliasText:=Text;
    Sig:=F.Security.Sign(Text);VerifySignature(F.Security,Text,Sig);
    Check((Text=AliasText) and (Length(Text)>4096),CozyText_DeviceSecurityOwnedProbe_CALLER_TEXT_MUTATED_b5020c9b);
    Check(F.InputSeen and F.DigestSeen and F.SignatureSeen,CozyText_DeviceSecurityOwnedProbe_MISSING_REAL_SIGN_STAGES_fec1001b);
    F.CheckRevoked;WipeText(Sig);
    for I:=0 to High(Stages) do
    begin
      F.ClearViews;F.ThrowAt:=Stages[I];Rejected:=False;
      try Sig:=F.Security.Sign(Text);except on E:EInvalidOpException do Rejected:=E.Message=CozyText_DeviceSecurityOwnedProbe_PROBE_INJECTED_FAILURE_acc05bdc;end;
      Check(Rejected and (Sig=''),CozyText_DeviceSecurityOwnedProbe_FAULT_PUBLISHED_SIGNATURE_1c8d4abb);F.CheckRevoked;
      F.ClearViews;Sig:=F.Security.Sign(Text);VerifySignature(F.Security,Text,Sig);F.CheckRevoked;WipeText(Sig);
    end;
    F.ClearViews;Sig:=F.Security.Sign('');VerifySignature(F.Security,'',Sig);F.CheckRevoked;WipeText(Sig);
    F.ClearViews;Rejected:=False;
    try Sig:=F.Security.Sign(StringOfChar('x',1024*1024+1));except on E:EDeviceSecurity do Rejected:=True;end;
    Check(Rejected and not F.InputSeen,CozyText_DeviceSecurityOwnedProbe_OVERSIZE_REACHED_SIGNER_278f5a6c);
  finally F.Free;WipeText(Text);WipeText(AliasText);WipeText(Sig);end;
end;
procedure HandoffCases;
var Parent:TDeviceSecurity;F:TFixture;Role,Claim,Nonce,Canonical,Delegation,Expected,Actual:string;I:Integer;
begin
  Parent:=TDeviceSecurity.Create;
  try
    for I:=0 to 1 do
    begin
      if I=0 then Role:='B' else Role:='O';
      F:=TFixture.Create;
      try
        Claim:=CozyText_DeviceSecurityOwnedProbe_bounded_claim_08884e4a+Role+#10+StringOfChar('x',123);
        Nonce:=StringOfChar('A',64);
        Canonical:=HandoffCanonical(CozyText_DeviceSecurityOwnedProbe_DELEGATION_e23dd667,Role,Claim,F.Security.DeviceID,Nonce);
        Delegation:=Parent.Sign(Canonical);
        F.Security.AcceptDelegation(Parent.DeviceID,Role,Claim,Nonce,Delegation);
        Canonical:=HandoffCanonical(CozyText_DeviceSecurityOwnedProbe_CLAIM_50a56d67,Role,Claim,F.Security.DeviceID,Nonce);
        Expected:=F.Security.Sign(Canonical);F.CheckRevoked;F.ClearViews;
        Actual:=F.Security.SignHandoffClaim(Role,Claim);
        Check(Actual=Expected,CozyText_DeviceSecurityOwnedProbe_OWNED_CANONICAL_CHANGED_WIRE_SIGNATURE_cd4931bb);
        VerifySignature(F.Security,Canonical,Actual);F.CheckRevoked;
        F.Security.CompleteHandoff;
        Check(F.Security.DelegationSignature='',CozyText_DeviceSecurityOwnedProbe_HANDOFF_LIVE_BINDING_NOT_CLEARED_59564f6a);
      finally
        F.Free;WipeText(Claim);WipeText(Canonical);WipeText(Delegation);WipeText(Expected);WipeText(Actual);
      end;
    end;
  finally Parent.Free;end;
end;
procedure CloseDuringSign(const Stage:string);
var F:TFixture;Signer:TSignWorker;Closer:TCloseWorker;Clock:TStopwatch;SignStarted,CloseStarted,Rejected:Boolean;Unused:string;
begin
  F:=TFixture.Create;Signer:=nil;Closer:=nil;SignStarted:=False;CloseStarted:=False;
  try
    F.BlockAt:=Stage;Signer:=TSignWorker.Create(F.Security);Closer:=TCloseWorker.Create(F.Security);
    Signer.Start;SignStarted:=True;
    Check(F.Entered.WaitFor(5000)=wrSignaled,CozyText_DeviceSecurityOwnedProbe_SIGN_STAGE_NOT_REACHED_ae8ad70b);
    Closer.Start;CloseStarted:=True;
    Clock:=TStopwatch.StartNew;
    while not F.Security.TestIsClosing and (Clock.ElapsedMilliseconds<5000) do
      Closer.Done.WaitFor(1);
    Check(F.Security.TestIsClosing,CozyText_DeviceSecurityOwnedProbe_CLOSE_NOT_OBSERVED_8a1d3ca3);
    Check(Closer.Done.WaitFor(0)=wrTimeout,CozyText_DeviceSecurityOwnedProbe_CLOSE_DID_NOT_DRAIN_ADMITTED_SIGNER_1144c4c7);
    F.ReleaseStage.SetEvent;
    Check(Signer.Done.WaitFor(5000)=wrSignaled,CozyText_DeviceSecurityOwnedProbe_SIGNER_DID_NOT_STOP_3246afb3);
    Check(Closer.Done.WaitFor(5000)=wrSignaled,CozyText_DeviceSecurityOwnedProbe_CLOSE_DID_NOT_JOIN_281b3a08);
    Signer.WaitFor;Closer.WaitFor;
    Check((Signer.Code=CozyText_DeviceSecurityOwnedProbe_OBJECT_CLOSING_3a6c16dc) and (Signer.Signature=''),CozyText_DeviceSecurityOwnedProbe_CLOSE_PUBLISHED_SIGNATURE_00e3b8f3);
    Check(Closer.Code='',CozyText_DeviceSecurityOwnedProbe_CLOSE_FAILED_26fb6790);F.CheckRevoked;
    Rejected:=False;
    try Unused:=F.Security.Sign(CozyText_DeviceSecurityOwnedProbe_afterclose_aa3fb467);except on E:EInvalidOpException do Rejected:=E.Message=CozyText_DeviceSecurityOwnedProbe_OBJECT_CLOSING_3a6c16dc;end;
    Check(Rejected and (Unused=''),CozyText_DeviceSecurityOwnedProbe_CLOSED_SIGNER_REUSED_be432859);
  finally
    F.ReleaseStage.SetEvent;
    if SignStarted then Signer.WaitFor;
    if CloseStarted then Closer.WaitFor;
    Signer.Free;Closer.Free;F.Free;WipeText(Unused);
  end;
end;
begin
  try
    SealApiPointerStorage;
    SigningCases;HandoffCases;
    CloseDuringSign(CozyText_DeviceSecurityOwnedProbe_sign_input_a1ee8699);CloseDuringSign(CozyText_DeviceSecurityOwnedProbe_sign_digest_208df152);CloseDuringSign(CozyText_DeviceSecurityOwnedProbe_sign_signature_c8b7f2e2);
    Writeln(CozyText_DeviceSecurityOwnedProbe_PASS_7004e6d5,Checks,CozyText_DeviceSecurityOwnedProbe_real_CNG_ownership_wire_and_Close_drain_checks_n_1b4a49d2);
  except on E:Exception do begin Writeln(CozyText_DeviceSecurityOwnedProbe_FAIL_bafd246a,E.Message);ExitCode:=1;end;end;
end.
