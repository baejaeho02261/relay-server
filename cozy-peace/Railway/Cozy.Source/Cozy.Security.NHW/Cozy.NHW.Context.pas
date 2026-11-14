unit Cozy.NHW.Context;

{$B-}{$Q+}{$R+}

interface

uses Winapi.Windows, System.SysUtils, System.SyncObjs, System.JSON,
  Cozy.NHW.Logging;

type
  { Fixed-size records deliberately contain no managed strings. They are
    bounded RAM observations, not authority. A server receipt is required
    before a peer can be classified as first party. }
  TCozyActorIdentity = record
    PID: Cardinal;
    CreationTime: UInt64;
    Role: string[1];
    Phase: string[24];
    Identity, ImageSHA256: string[64];
    ImageSHA512: string[128];
    PeerID, GrantID: string[48];
    ExpiresTick: UInt64;
  end;
  TCozySecurityPhase = (cspBootstrap, cspAttested, cspIssuance, cspRuntime,
    cspHandoff, cspShutdown);
  TCozyCapabilityDecision = (ccdObserve, ccdExpected, ccdSuspicious, ccdForbidden);
  TCozyDetectionContext = record
    ActorClass: string[12];
    ActorRole, TargetRole: string[1];
    ActorIdentity, TargetIdentity: string[64];
    Phase: string[24];
    Capability: string[24];
    AccessMask: Cardinal;
    TokenDelta: Word;
    Coverage: string[24];
    PeerID, GrantID: string[48];
    Baseline, ContextMixed: Boolean;
  end;
  TCozySecurityContext = class
  private
    FLock: TCriticalSection;
    FRole, FPhase, FParentIdentity, FSessionID, FEpoch: string;
    FLocal: TCozyActorIdentity;
    FPeers: array[0..2] of TCozyActorIdentity;
    FLastServerSequence: UInt64;
    FPreparing: LongInt;
    FClosed: Boolean;
  public
    constructor Create(const Role: string);
    destructor Destroy; override;
    procedure SetPhase(const Phase: string);
    procedure SetParentIdentity(const Identity: string);
    procedure SetLocalIdentity(const Identity: TCozyActorIdentity);
    procedure BindSession(const SessionID: string);
    procedure PrepareLocalIdentity;
    function LocalIdentity: string;
    function PeerPayload: TJSONValue;
    procedure ApplyServerReceipt(Value: TJSONValue; const Epoch: string;
      RequestStarted: UInt64 = 0);
    function Observation(const Capability: string = 'UNKNOWN'): TCozyDetectionContext;
    function OwnBaselineObservation(TargetPID: Cardinal): TCozyDetectionContext;
    function ActorObservation(ActorPID: Cardinal; ActorCreation: UInt64;
      TargetPID: Cardinal; const Capability: string; AccessMask: Cardinal;
      Baseline: Boolean): TCozyDetectionContext;
    procedure Clear;
  end;

function NHWCaptureProcessIdentity(ProcessHandle, ImageHandle: THandle;
  ProcessID: Cardinal; out Identity: TCozyActorIdentity): Boolean;
function NHWStableProcessIdentity(ProcessHandle, ImageHandle: THandle;
  ProcessID: Cardinal): string;
function NHWContextJSON(const Context: TCozyDetectionContext): TJSONObject;
function NHWContextRisk(const Context: TCozyDetectionContext): Integer;
function NHWSameObservationContext(const A, B: TCozyDetectionContext): Boolean;
function NHWMergeObservationContext(const A, B: TCozyDetectionContext): TCozyDetectionContext;
procedure NHWEnterSensorContext(Context: TCozySecurityContext);
procedure NHWLeaveSensorContext;
procedure NHWBeginContextCycle(Baseline: Boolean);
procedure NHWNoteAccessContext(Kind: TDetectionKind; ActorPID: Cardinal;
  ActorCreation: UInt64; TargetPID: Cardinal; const Capability: string;
  AccessMask: Cardinal; Baseline: Boolean = False);
procedure NHWNoteTokenDelta(Kind: TDetectionKind; TargetPID: Cardinal; DeltaMask: Word);
procedure NHWNoteTokenBaseline(TargetPID: Cardinal);
function NHWReadDetectionContext(Kind: TDetectionKind;
  Fallback: TCozySecurityContext): TCozyDetectionContext;
function NHWContextObservations: TDetectionKinds;

implementation

uses System.Classes, System.Generics.Collections, Cozy.NHW.Attestation.Hash, Cozy.NHW.WinPointers,
  Cozy.NHW.Observer.Protocol, Cozy.NHW.Cancellation;

threadvar
  ActiveContext: TCozySecurityContext;
  CycleContext: array[TDetectionKind] of TCozyDetectionContext;
  CycleKinds, ObservationKinds: TDetectionKinds;
  CycleBaseline: Boolean;

procedure WipeText(var Text: string);
begin
  UniqueString(Text);
  if Text<>'' then FillChar(PChar(Text)^,Length(Text)*SizeOf(Char),0);
  Text:='';
end;

function HashHex(const Data: TBytes; SHA512: Boolean): string;
var Small: TSHA256Digest; Large: TSHA512Digest; I: Integer;
begin
  Result:='';
  if SHA512 then
  begin
    if not HashBytesSHA512(Data,Large) then Exit;
    for I:=0 to High(Large) do Result:=Result+IntToHex(Large[I],2).ToLower;
    FillChar(Large,SizeOf(Large),0);
  end
  else
  begin
    if not HashBytesSHA256(Data,Small) then Exit;
    for I:=0 to High(Small) do Result:=Result+IntToHex(Small[I],2).ToLower;
    FillChar(Small,SizeOf(Small),0);
  end;
end;

function HashText(const Text: string): string;
var Bytes: TBytes;
begin
  Bytes:=TEncoding.UTF8.GetBytes(Text);
  try Result:=HashHex(Bytes,False);
  finally
    if Length(Bytes)<>0 then FillChar(Bytes[0],Length(Bytes),0);
    Bytes:=nil;
  end;
end;

function IsHex(const Text: string; Size: Integer): Boolean;
var I: Integer;
begin
  Result := Length(Text) = Size;
  if not Result then Exit;
  for I := 1 to Size do
    if not CharInSet(Text[I], ['0'..'9', 'a'..'f']) then Exit(False);
end;

function FileTimeValue(const V: TFileTime): UInt64;
begin Result := (UInt64(V.dwHighDateTime) shl 32) or V.dwLowDateTime; end;

function NHWCaptureProcessIdentity(ProcessHandle, ImageHandle: THandle;
  ProcessID: Cardinal; out Identity: TCozyActorIdentity): Boolean;
const MaxImageBytes = 64 * 1024 * 1024;
var BeforeInfo, AfterInfo: TByHandleFileInformation;
  C, E, K, U, Again: TFileTime; Stream: THandleStream; Bytes: TBytes;
  Size, Position: Int64; Offset, Chunk: Integer; Started: UInt64;
  SHA256, SHA512, Canonical: string;
begin
  Result := False; Identity := Default(TCozyActorIdentity);
  try ResolveWinPointers; except Exit; end;
  if (ProcessID = 0) or (ProcessHandle = 0) or
    (ImageHandle = 0) or (ImageHandle = INVALID_HANDLE_VALUE) then Exit;
  if not WinGetProcessTimes(ProcessHandle, C, E, K, U) or
    (FileTimeValue(C) = 0) or
    not WinGetFileInformationByHandle(ImageHandle, BeforeInfo) then Exit;
  if (BeforeInfo.dwFileAttributes and
    (FILE_ATTRIBUTE_DIRECTORY or FILE_ATTRIBUTE_REPARSE_POINT)) <> 0 then Exit;
  if (BeforeInfo.nFileSizeHigh <> 0) or (BeforeInfo.nFileSizeLow < 64) or
    (BeforeInfo.nFileSizeLow > MaxImageBytes) then Exit;
  { Caller owns this handle's file position exclusively during capture.
    Handoff uses its already verified pinned image before publishing workers. }
  Stream := THandleStream.Create(ImageHandle);
  Bytes := nil;
  try
    Position := Stream.Position;
    try
      Size := Stream.Size;
      if Size <> BeforeInfo.nFileSizeLow then Exit;
      SetLength(Bytes, Integer(Size));
      Stream.Position := 0;
      Offset := 0; Started := ObserverClockTick;
      while Offset < Length(Bytes) do
      begin
        if NHWCancellationRequested or (ObserverClockTick - Started > 30000) then Exit;
        Chunk := Length(Bytes) - Offset;
        if Chunk > 65536 then Chunk := 65536;
        if Stream.Read(Bytes[Offset], Chunk) <> Chunk then Exit;
        Inc(Offset, Chunk);
      end;
      if (Bytes[0] <> $4d) or (Bytes[1] <> $5a) then Exit;
      SHA256 := HashHex(Bytes,False);
      SHA512 := HashHex(Bytes,True);
      if not WinGetFileInformationByHandle(ImageHandle, AfterInfo) or
        (BeforeInfo.dwVolumeSerialNumber <> AfterInfo.dwVolumeSerialNumber) or
        (BeforeInfo.nFileIndexHigh <> AfterInfo.nFileIndexHigh) or
        (BeforeInfo.nFileIndexLow <> AfterInfo.nFileIndexLow) or
        (BeforeInfo.nFileSizeHigh <> AfterInfo.nFileSizeHigh) or
        (BeforeInfo.nFileSizeLow <> AfterInfo.nFileSizeLow) or
        (FileTimeValue(BeforeInfo.ftLastWriteTime) <> FileTimeValue(AfterInfo.ftLastWriteTime)) or
        not WinGetProcessTimes(ProcessHandle, Again, E, K, U) or
        (FileTimeValue(C) <> FileTimeValue(Again)) then Exit;
      if not IsHex(SHA256, 64) or not IsHex(SHA512, 128) then Exit;
      Canonical := 'COZY-NHW-PROCESS-V1' + #10 + UIntToStr(ProcessID) + #10 +
        IntToHex(FileTimeValue(C), 16).ToLower + #10 + SHA256;
      Identity.PID := ProcessID;
      Identity.CreationTime := FileTimeValue(C);
      Identity.ImageSHA256 := ShortString(SHA256);
      Identity.ImageSHA512 := ShortString(SHA512);
      Identity.Identity := ShortString(HashText(Canonical));
      Result := True;
    finally Stream.Position := Position; end;
  finally
    if Length(Bytes) <> 0 then FillChar(Bytes[0], Length(Bytes), 0);
    Bytes := nil; Stream.Free;
    WipeText(Canonical); WipeText(SHA256); WipeText(SHA512);
  end;
end;

function NHWStableProcessIdentity(ProcessHandle, ImageHandle: THandle;
  ProcessID: Cardinal): string;
var Identity: TCozyActorIdentity;
begin
  Result := '';
  try
    if NHWCaptureProcessIdentity(ProcessHandle, ImageHandle, ProcessID, Identity) then
      Result := string(Identity.Identity);
  except Result := ''; end;
  FillChar(Identity, SizeOf(Identity), 0);
end;

constructor TCozySecurityContext.Create(const Role: string);
begin
  inherited Create;
  if (Role <> 'A') and (Role <> 'B') and (Role <> 'O') then
    raise EArgumentException.Create('NHW_CONTEXT_ROLE_INVALID');
  FLock := TCriticalSection.Create;
  FRole := Role; FPhase := Role + '_BOOTSTRAP';
end;

destructor TCozySecurityContext.Destroy;
begin if FLock<>nil then Clear; FLock.Free; inherited Destroy; end;

procedure TCozySecurityContext.Clear;
begin
  if FLock=nil then Exit;
  FLock.Acquire;
  try
    FClosed := True;
    FillChar(FLocal, SizeOf(FLocal), 0);
    FillChar(FPeers, SizeOf(FPeers), 0);
    FLastServerSequence := 0;
    WipeText(FParentIdentity); WipeText(FSessionID); WipeText(FEpoch);
  finally FLock.Release; end;
end;

function ValidRolePhase(const Role, Phase: string): Boolean;
begin
  Result:=(Phase=Role+'_BOOTSTRAP') or (Phase=Role+'_ATTESTED') or
    (Phase=Role+'_SHUTDOWN') or
    ((Role='A') and ((Phase='A_ISSUANCE') or (Phase='A_HANDOFF_TO_B'))) or
    ((Role='B') and ((Phase='B_RUNTIME') or (Phase='B_HANDOFF_TO_O'))) or
    ((Role='O') and (Phase='O_RUNTIME'));
end;

procedure TCozySecurityContext.SetPhase(const Phase: string);
begin
  if (Phase <> FRole + '_BOOTSTRAP') and (Phase <> FRole + '_ATTESTED') and
    (Phase <> FRole + '_SHUTDOWN') and
    not ((FRole = 'A') and ((Phase = 'A_ISSUANCE') or (Phase = 'A_HANDOFF_TO_B'))) and
    not ((FRole = 'B') and ((Phase = 'B_RUNTIME') or (Phase = 'B_HANDOFF_TO_O'))) and
    not ((FRole = 'O') and (Phase = 'O_RUNTIME')) then
    raise EArgumentException.Create('NHW_CONTEXT_PHASE_INVALID');
  FLock.Acquire;
  try if not FClosed then FPhase := Phase; finally FLock.Release; end;
end;

procedure TCozySecurityContext.SetParentIdentity(const Identity: string);
begin
  if (Identity <> '') and not IsHex(Identity, 64) then
    raise EArgumentException.Create('NHW_CONTEXT_PARENT_INVALID');
  FLock.Acquire;
  try
    if FClosed then Exit;
    if (FParentIdentity <> '') and (FParentIdentity <> Identity) then
      raise EArgumentException.Create('NHW_CONTEXT_PARENT_CHANGED');
    FParentIdentity := Identity;
  finally FLock.Release; end;
end;

procedure TCozySecurityContext.SetLocalIdentity(const Identity: TCozyActorIdentity);
begin
  if (Identity.PID = 0) or (Identity.CreationTime = 0) or
    not IsHex(string(Identity.Identity),64) or
    not IsHex(string(Identity.ImageSHA256),64) or
    not IsHex(string(Identity.ImageSHA512),128) then Exit;
  FLock.Acquire;
  try
    if FClosed then Exit;
    if (FLocal.Identity <> '') and (FLocal.Identity <> Identity.Identity) then
      raise EArgumentException.Create('NHW_CONTEXT_LOCAL_CHANGED');
    FLocal := Identity; FLocal.Role := ShortString(FRole);
  finally FLock.Release; end;
end;

procedure TCozySecurityContext.BindSession(const SessionID: string);
begin
  FLock.Acquire;
  try
    if FClosed then Exit;
    if FSessionID = SessionID then Exit;
    FillChar(FPeers, SizeOf(FPeers), 0);
    FLastServerSequence := 0; WipeText(FEpoch);
    FSessionID := SessionID;
  finally FLock.Release; end;
end;

procedure TCozySecurityContext.PrepareLocalIdentity;
var Handle: THandle; Identity: TCozyActorIdentity;
begin
  FLock.Acquire;
  try if FClosed or (FLocal.Identity<>'') then Exit; finally FLock.Release; end;
  if TInterlocked.CompareExchange(FPreparing,1,0)<>0 then Exit;
  try
  try
  ResolveWinPointers;
  Handle := WinCreateFile(PWideChar(ParamStr(0)), GENERIC_READ,
    FILE_SHARE_READ or FILE_SHARE_DELETE, nil, OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL or FILE_FLAG_OPEN_REPARSE_POINT, 0);
  if (Handle = 0) or (Handle = INVALID_HANDLE_VALUE) then Exit;
  try
    if NHWCaptureProcessIdentity(WinCurrentProcess, Handle,
      WinCurrentProcessId, Identity) then SetLocalIdentity(Identity);
  finally WinCloseHandle(Handle); FillChar(Identity, SizeOf(Identity), 0); end;
  except
    { Identity unavailable is UNKNOWN. Keep independent sensors running. }
  end;
  finally TInterlocked.Exchange(FPreparing,0); end;
end;

function TCozySecurityContext.LocalIdentity: string;
begin
  FLock.Acquire;
  try Result := string(FLocal.Identity); finally FLock.Release; end;
end;

function TCozySecurityContext.PeerPayload: TJSONValue;
var Obj: TJSONObject;
begin
  FLock.Acquire;
  try
    if FClosed or (FLocal.Identity = '') then Exit(TJSONNull.Create);
    Obj := TJSONObject.Create;
    Obj.AddPair('pid', TJSONNumber.Create(Int64(FLocal.PID)));
    Obj.AddPair('creationTime', IntToHex(FLocal.CreationTime,16).ToLower);
    Obj.AddPair('imageSha256', string(FLocal.ImageSHA256));
    Obj.AddPair('imageSha512', string(FLocal.ImageSHA512));
    Obj.AddPair('parentIdentity', FParentIdentity);
    Obj.AddPair('phase', FPhase);
    Result := Obj;
  finally FLock.Release; end;
end;

function Text(Obj: TJSONObject; const Name: string): string;
var V: TJSONValue;
begin
  V := Obj.GetValue(Name);
  if not (V is TJSONString) then raise EConvertError.Create('NHW_PEER_RECEIPT_INVALID');
  Result := V.Value;
end;

function Number(Obj: TJSONObject; const Name: string): Int64;
var V: TJSONValue;
begin
  V := Obj.GetValue(Name);
  if not (V is TJSONNumber) or not TryStrToInt64(V.Value,Result) then
    raise EConvertError.Create('NHW_PEER_RECEIPT_INVALID');
end;

procedure TCozySecurityContext.ApplyServerReceipt(Value: TJSONValue; const Epoch: string;
  RequestStarted: UInt64);
var Obj, Item: TJSONObject; List: TJSONArray; Peers: array[0..2] of TCozyActorIdentity;
  I, J, SelfIndex: Integer; Sequence, Created, RequestElapsed, ReceivedAt: UInt64; TTL, PID: Int64;
  S, OwnIdentity, OwnPeerID, Canonical: string;
begin
  FillChar(Peers,SizeOf(Peers),0); Canonical:='';
  try
  if (Value = nil) or (Value is TJSONNull) then Exit;
  if not (Value is TJSONObject) then raise EConvertError.Create('NHW_PEER_RECEIPT_INVALID');
  Obj := TJSONObject(Value);
  if (Number(Obj,'version') <> 1) or (Text(Obj,'epoch') <> Epoch) or
    (Text(Obj,'scope') <> 'SERVER_BOUND_CLIENT_OBSERVATION') then
    raise EConvertError.Create('NHW_PEER_RECEIPT_INVALID');
  S := Text(Obj,'serverSequence');
  if not IsHex(S,16) or not TryStrToUInt64('$'+S,Sequence) or (Sequence=0) then
    raise EConvertError.Create('NHW_PEER_RECEIPT_INVALID');
  TTL := Number(Obj,'ttlMs');
  if (TTL < 1) or (TTL > 30000) then raise EConvertError.Create('NHW_PEER_RECEIPT_INVALID');
  ReceivedAt:=ObserverClockTick; RequestElapsed:=0;
  if RequestStarted<>0 then
  begin
    if RequestStarted>ReceivedAt then Exit;
    RequestElapsed:=ReceivedAt-RequestStarted;
  end;
  if RequestElapsed>=UInt64(TTL) then Exit;
  Dec(TTL,Int64(RequestElapsed));
  OwnIdentity := Text(Obj,'selfIdentity');
  OwnPeerID := Text(Obj,'selfPeerId');
  if not IsHex(OwnIdentity,64) or not IsHex(OwnPeerID,48) then
    raise EConvertError.Create('NHW_PEER_RECEIPT_INVALID');
  SelfIndex := -1;
  if not (Obj.GetValue('peers') is TJSONArray) then
    raise EConvertError.Create('NHW_PEER_RECEIPT_INVALID');
  List := TJSONArray(Obj.GetValue('peers'));
  if List.Count > 3 then raise EConvertError.Create('NHW_PEER_RECEIPT_INVALID');
  FillChar(Peers,SizeOf(Peers),0);
  for I := 0 to List.Count - 1 do
  begin
    if not (List.Items[I] is TJSONObject) then raise EConvertError.Create('NHW_PEER_RECEIPT_INVALID');
    Item := TJSONObject(List.Items[I]);
    PID := Number(Item,'pid');
    S := Text(Item,'creationTime');
    if (PID < 1) or (PID > High(Cardinal)) or not IsHex(S,16) or
      not TryStrToUInt64('$'+S,Created) or (Created=0) then
      raise EConvertError.Create('NHW_PEER_RECEIPT_INVALID');
    Peers[I].PID := Cardinal(PID); Peers[I].CreationTime := Created;
    S := Text(Item,'role');
    if (S <> 'A') and (S <> 'B') and (S <> 'O') then
      raise EConvertError.Create('NHW_PEER_RECEIPT_INVALID');
    Peers[I].Role := ShortString(S);
    S := Text(Item,'phase');
    if not ValidRolePhase(string(Peers[I].Role),S) then raise EConvertError.Create('NHW_PEER_RECEIPT_INVALID');
    Peers[I].Phase := ShortString(S);
    S := Text(Item,'identity'); if not IsHex(S,64) then raise EConvertError.Create('NHW_PEER_RECEIPT_INVALID');
    Peers[I].Identity := ShortString(S);
    S := Text(Item,'imageSha256'); if not IsHex(S,64) then raise EConvertError.Create('NHW_PEER_RECEIPT_INVALID');
    Peers[I].ImageSHA256 := ShortString(S);
    Canonical := 'COZY-NHW-PROCESS-V1' + #10 + UIntToStr(Peers[I].PID) + #10 +
      IntToHex(Peers[I].CreationTime,16).ToLower + #10 + S;
    if HashText(Canonical) <> string(Peers[I].Identity) then
      raise EConvertError.Create('NHW_PEER_IDENTITY_INVALID');
    S := Text(Item,'imageSha512'); if not IsHex(S,128) then raise EConvertError.Create('NHW_PEER_RECEIPT_INVALID');
    Peers[I].ImageSHA512 := ShortString(S);
    S := Text(Item,'peerId'); if not IsHex(S,48) then raise EConvertError.Create('NHW_PEER_RECEIPT_INVALID');
    Peers[I].PeerID := ShortString(S);
    if (S=OwnPeerID) and (string(Peers[I].Identity)=OwnIdentity) then SelfIndex:=I;
    for J:=0 to I-1 do
      if (Peers[J].Role=Peers[I].Role) or (Peers[J].Identity=Peers[I].Identity) or
        (Peers[J].PeerID=Peers[I].PeerID) or
        ((Peers[J].PID=Peers[I].PID) and (Peers[J].CreationTime=Peers[I].CreationTime)) then
        raise EConvertError.Create('NHW_PEER_DUPLICATE');
    S := Text(Item,'grantId'); if (S<>'') and not IsHex(S,48) then raise EConvertError.Create('NHW_PEER_RECEIPT_INVALID');
    Peers[I].GrantID := ShortString(S);
    PID := Number(Item,'ttlMs');
    if (PID<1) or (PID>30000) then raise EConvertError.Create('NHW_PEER_RECEIPT_INVALID');
    if RequestElapsed>=UInt64(PID) then Exit;
    Dec(PID,Int64(RequestElapsed));
    if PID>TTL then PID:=TTL;
    Peers[I].ExpiresTick := ReceivedAt + UInt64(PID);
  end;
  if SelfIndex<0 then raise EConvertError.Create('NHW_PEER_SELF_MISSING');
  FLock.Acquire;
  try
    if FClosed or (FSessionID='') or (OwnIdentity <> string(FLocal.Identity)) then Exit;
    if (Peers[SelfIndex].PID<>FLocal.PID) or
      (Peers[SelfIndex].CreationTime<>FLocal.CreationTime) or
      (Peers[SelfIndex].ImageSHA256<>FLocal.ImageSHA256) or
      (Peers[SelfIndex].ImageSHA512<>FLocal.ImageSHA512) or
      (string(Peers[SelfIndex].Role)<>FRole) then
      raise EConvertError.Create('NHW_PEER_SELF_CHANGED');
    if (FEpoch<>'') and (FEpoch<>Epoch) then
    begin
      FillChar(FPeers,SizeOf(FPeers),0);
      raise EConvertError.Create('NHW_PEER_EPOCH_CHANGED');
    end;
    if Sequence <= FLastServerSequence then Exit;
    FEpoch := Epoch; FLastServerSequence := Sequence; Move(Peers, FPeers, SizeOf(FPeers));
  finally FLock.Release; end;
  finally FillChar(Peers,SizeOf(Peers),0); WipeText(Canonical); end;
end;

function TCozySecurityContext.Observation(const Capability: string): TCozyDetectionContext;
begin
  Result := Default(TCozyDetectionContext);
  Result.ActorClass := 'UNKNOWN'; Result.ActorRole := '?';
  Result.TargetRole := '?'; Result.Coverage := 'UNKNOWN';
  Result.Capability := ShortString(Capability); Result.Phase := 'UNKNOWN';
  FLock.Acquire;
  try
    if FClosed then Exit;
    Result.Phase := ShortString(FPhase); Result.TargetRole := ShortString(FRole);
    Result.TargetIdentity := FLocal.Identity;
  finally FLock.Release; end;
end;

function TCozySecurityContext.OwnBaselineObservation(TargetPID: Cardinal): TCozyDetectionContext;
var Local: TCozyActorIdentity;
begin
  FLock.Acquire;
  try Local:=FLocal; finally FLock.Release; end;
  { This identifies the code performing its own initial query; it does NOT
    identify who caused any later mutation. Token deltas keep UNKNOWN actor. }
  if (Local.PID=TargetPID) and (Local.CreationTime<>0) and (Local.Identity<>'') then
    Result:=ActorObservation(Local.PID,Local.CreationTime,TargetPID,'TOKEN_STATE',0,True)
  else Result:=ActorObservation(0,0,TargetPID,'TOKEN_STATE',0,True);
  FillChar(Local,SizeOf(Local),0);
end;

function TCozySecurityContext.ActorObservation(ActorPID: Cardinal;
  ActorCreation: UInt64; TargetPID: Cardinal; const Capability: string;
  AccessMask: Cardinal; Baseline: Boolean): TCozyDetectionContext;
var I: Integer; Peer: TCozyActorIdentity; Tick: UInt64;
begin
  Result := Observation(Capability); Result.AccessMask := AccessMask;
  Result.Baseline := Baseline; Tick := ObserverClockTick;
  FLock.Acquire;
  try
    if FClosed then Exit;
    if TargetPID <> FLocal.PID then
    begin Result.TargetRole := '?'; Result.TargetIdentity := ''; end;
    if (ActorPID=0) or (ActorCreation=0) then Exit;
    Result.ActorClass := 'EXTERNAL';
    if FSessionID<>'' then
      Result.ActorIdentity:=ShortString(HashText('COZY-NHW-EXTERNAL-V1'+#10+
        FSessionID+#10+UIntToStr(ActorPID)+#10+IntToHex(ActorCreation,16).ToLower));
    if (ActorPID=FLocal.PID) and (ActorCreation=FLocal.CreationTime) then
    begin
      Result.ActorClass := 'SELF'; Result.ActorRole := ShortString(FRole);
      Result.ActorIdentity := FLocal.Identity;
    end;
    for I := 0 to High(FPeers) do
    begin
      Peer := FPeers[I];
      if (Peer.PID<>ActorPID) or (Peer.CreationTime<>ActorCreation) or
        (Peer.ExpiresTick<=Tick) then Continue;
      Result.ActorIdentity := Peer.Identity;
      Result.ActorRole := ShortString(Peer.Role);
      Result.PeerID := Peer.PeerID; Result.GrantID := Peer.GrantID;
      if ActorPID<>FLocal.PID then
      begin
        Result.ActorClass := ShortString('TRUSTED_'+string(Peer.Role));
        Result.Phase := Peer.Phase;
      end;
      Break;
    end;
  finally FLock.Release; end;
end;

function NHWContextJSON(const Context: TCozyDetectionContext): TJSONObject;
begin
  Result := TJSONObject.Create;
  Result.AddPair('actorClass', string(Context.ActorClass));
  Result.AddPair('actorRole', string(Context.ActorRole));
  Result.AddPair('actorIdentity', string(Context.ActorIdentity));
  Result.AddPair('targetRole', string(Context.TargetRole));
  Result.AddPair('targetIdentity', string(Context.TargetIdentity));
  Result.AddPair('phase', string(Context.Phase));
  Result.AddPair('capability', string(Context.Capability));
  Result.AddPair('accessMask', TJSONNumber.Create(Int64(Context.AccessMask)));
  Result.AddPair('tokenDelta', TJSONNumber.Create(Context.TokenDelta));
  Result.AddPair('coverage', string(Context.Coverage));
  Result.AddPair('peerId', string(Context.PeerID));
  Result.AddPair('grantId', string(Context.GrantID));
  Result.AddPair('baseline', TJSONBool.Create(Context.Baseline));
  Result.AddPair('contextMixed', TJSONBool.Create(Context.ContextMixed));
end;

function NHWSameObservationContext(const A, B: TCozyDetectionContext): Boolean;
begin
  Result := (A.ActorClass=B.ActorClass) and (A.ActorRole=B.ActorRole) and
    (A.ActorIdentity=B.ActorIdentity) and (A.TargetRole=B.TargetRole) and
    (A.TargetIdentity=B.TargetIdentity) and (A.Phase=B.Phase) and
    (A.Capability=B.Capability) and (A.PeerID=B.PeerID) and
    (A.GrantID=B.GrantID) and (A.Baseline=B.Baseline) and
    (A.ContextMixed=B.ContextMixed);
end;

function NHWContextRisk(const Context: TCozyDetectionContext): Integer;
begin
  Result:=0;
  if (Context.TokenDelta and $ff)<>0 then Exit(4);
  if ((Context.Capability='PROCESS_ACCESS') and ((Context.AccessMask and $2a)<>0)) or
    ((Context.Capability='THREAD_ACCESS') and ((Context.AccessMask and $10)<>0)) or
    ((Context.Capability='TOKEN_ACCESS') and ((Context.AccessMask and $1e7)<>0)) then Exit(3);
  if Context.AccessMask<>0 then Result:=1;
end;

function NHWMergeObservationContext(const A, B: TCozyDetectionContext): TCozyDetectionContext;
begin
  Result := A;
  { Mask namespaces are not interchangeable. Keep the stronger concrete
    capability when a bounded mixed record contains different observations. }
  if NHWContextRisk(B)>NHWContextRisk(A) then Result:=B;
  if A.Capability=B.Capability then
  begin
    Result.AccessMask := A.AccessMask or B.AccessMask;
    Result.TokenDelta := A.TokenDelta or B.TokenDelta;
  end;
  if not NHWSameObservationContext(A,B) then
  begin
    Result.ActorClass := 'UNKNOWN'; Result.ActorRole := '?';
    Result.ActorIdentity := ''; Result.PeerID := ''; Result.GrantID := '';
    Result.Baseline := False; Result.ContextMixed := True;
    if A.TargetIdentity<>B.TargetIdentity then
    begin Result.TargetIdentity:=''; Result.TargetRole:='?'; end;
    if A.Phase<>B.Phase then Result.Phase:='UNKNOWN';
  end;
  if A.Coverage<>B.Coverage then Result.Coverage:='UNKNOWN';
end;

procedure NHWEnterSensorContext(Context: TCozySecurityContext);
begin ActiveContext:=Context; NHWBeginContextCycle(False); end;

procedure NHWLeaveSensorContext;
begin
  ActiveContext:=nil; CycleKinds:=[]; ObservationKinds:=[];
  FillChar(CycleContext,SizeOf(CycleContext),0);
end;

procedure NHWBeginContextCycle(Baseline: Boolean);
begin
  CycleKinds:=[]; ObservationKinds:=[]; CycleBaseline:=Baseline;
  FillChar(CycleContext,SizeOf(CycleContext),0);
end;

procedure Note(Kind: TDetectionKind; const Context: TCozyDetectionContext);
begin
  if Kind in CycleKinds then CycleContext[Kind]:=NHWMergeObservationContext(CycleContext[Kind],Context)
  else CycleContext[Kind]:=Context;
  Include(CycleKinds,Kind);
end;

procedure NHWNoteAccessContext(Kind: TDetectionKind; ActorPID: Cardinal;
  ActorCreation: UInt64; TargetPID: Cardinal; const Capability: string;
  AccessMask: Cardinal; Baseline: Boolean);
begin
  if ActiveContext=nil then Exit;
  Note(Kind,ActiveContext.ActorObservation(ActorPID,ActorCreation,TargetPID,
    Capability,AccessMask,Baseline));
  Include(ObservationKinds,Kind);
end;

procedure NHWNoteTokenDelta(Kind: TDetectionKind; TargetPID: Cardinal; DeltaMask: Word);
var Context: TCozyDetectionContext;
begin
  if ActiveContext=nil then Exit;
  Context:=ActiveContext.ActorObservation(0,0,TargetPID,'TOKEN_STATE',0,False);
  Context.TokenDelta:=DeltaMask;
  Note(Kind,Context);
  Include(ObservationKinds,Kind);
end;

procedure NHWNoteTokenBaseline(TargetPID: Cardinal);
var Context: TCozyDetectionContext;
begin
  if ActiveContext=nil then Exit;
  Context:=ActiveContext.OwnBaselineObservation(TargetPID);
  { The first complete self-query is kept separately from later token
    mutation evidence. The server still checks exact registered identity. }
  Note(dkTokenObject,Context); Note(dkTokenRights,Context);
  Include(ObservationKinds,dkTokenObject); Include(ObservationKinds,dkTokenRights);
end;

function NHWReadDetectionContext(Kind: TDetectionKind;
  Fallback: TCozySecurityContext): TCozyDetectionContext;
begin
  if Kind in CycleKinds then Exit(CycleContext[Kind]);
  if Fallback<>nil then Result:=Fallback.Observation else
  begin
    Result:=Default(TCozyDetectionContext);
    Result.ActorClass:='UNKNOWN'; Result.ActorRole:='?'; Result.TargetRole:='?';
    Result.Phase:='UNKNOWN'; Result.Capability:='UNKNOWN'; Result.Coverage:='UNKNOWN';
  end;
  Result.Baseline:=CycleBaseline;
  if Kind in [dkETWLoss,dkCoverageGap,dkObservationUncertain,dkSensorPressure,
    dkTraceGap,dkKernelTelemetryGap] then Result.Coverage:='TRANSIENT_GAP';
end;

function NHWContextObservations: TDetectionKinds;
begin Result:=ObservationKinds; end;

end.
