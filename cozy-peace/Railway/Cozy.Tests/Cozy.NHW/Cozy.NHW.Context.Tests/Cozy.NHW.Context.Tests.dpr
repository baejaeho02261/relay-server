program Cozy_NHW_Context_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}{$MESSAGE FATAL 'WIN64_REQUIRED'}{$ENDIF}
{$B-}{$Q+}{$R+}

uses System.SysUtils, System.JSON, Cozy.NHW.Context, Cozy.NHW.Logging,
  Cozy.NHW.DetectionJournal, Cozy.NHW.WinPointers;

const
  AIdentity = 'af5c6fcf40ffd17ada6c1ccacd06f7fa6cb34b33d9fce4acaf3112c46f35c8e8';
  BIdentity = '42fd341b8052fe3b751960b12d63436688781a7588aec6a34a248b9161d2030e';

procedure Check(Value: Boolean; const MessageText: string);
begin if not Value then raise Exception.Create(MessageText); end;

function Peer(const Role, Phase, Identity, Image, PeerID: string;
  PID: Cardinal; Created: UInt64): TJSONObject;
begin
  Result:=TJSONObject.Create;
  Result.AddPair('peerId',PeerID); Result.AddPair('role',Role);
  Result.AddPair('phase',Phase); Result.AddPair('identity',Identity);
  Result.AddPair('pid',TJSONNumber.Create(Int64(PID)));
  Result.AddPair('creationTime',IntToHex(Created,16).ToLower);
  Result.AddPair('imageSha256',StringOfChar(Image[1],64));
  Result.AddPair('imageSha512',StringOfChar('d',128));
  Result.AddPair('grantId',StringOfChar('e',48));
  Result.AddPair('expiresAt',TJSONNumber.Create(Int64(1900000030000)));
  Result.AddPair('ttlMs',TJSONNumber.Create(30000));
end;

function Receipt(Sequence: Integer; const APhase: string): TJSONObject;
var Peers: TJSONArray;
begin
  Result:=TJSONObject.Create;
  Result.AddPair('version',TJSONNumber.Create(1));
  Result.AddPair('selfPeerId',StringOfChar('b',48));
  Result.AddPair('selfIdentity',BIdentity);
  Result.AddPair('epoch','1900000000000');
  Result.AddPair('serverSequence',IntToHex(Sequence,16).ToLower);
  Result.AddPair('expiresAt',TJSONNumber.Create(Int64(1900000030000)));
  Result.AddPair('ttlMs',TJSONNumber.Create(30000));
  Result.AddPair('scope','SERVER_BOUND_CLIENT_OBSERVATION');
  Peers:=TJSONArray.Create;
  Peers.AddElement(Peer('A',APhase,AIdentity,'a',StringOfChar('a',48),1000,1));
  Peers.AddElement(Peer('B','B_BOOTSTRAP',BIdentity,'b',StringOfChar('b',48),2000,2));
  Result.AddPair('peers',Peers);
end;

procedure PeerBinding;
var Context: TCozySecurityContext; Identity: TCozyActorIdentity;
  Seen: TCozyDetectionContext; Value: TJSONObject;
begin
  Context:=TCozySecurityContext.Create('B');
  try
    Identity:=Default(TCozyActorIdentity);
    Identity.PID:=2000; Identity.CreationTime:=2;
    Identity.Identity:=BIdentity;
    Identity.ImageSHA256:=ShortString(StringOfChar('b',64));
    Identity.ImageSHA512:=ShortString(StringOfChar('d',128));
    Context.SetLocalIdentity(Identity);
    Context.BindSession('111111111111111111111111');
    Seen:=Context.Observation;
    Check((Seen.ActorClass='UNKNOWN') and (Seen.TargetRole='B'),
      'target identity manufactured an actor');
    Seen:=Context.ActorObservation(1000,1,2000,'PROCESS_ACCESS',$1000,False);
    Check((Seen.ActorClass='EXTERNAL') and (Seen.PeerID=''),
      'process classified first party without a server receipt');
    Value:=Receipt(1,'A_HANDOFF_TO_B');
    try Context.ApplyServerReceipt(Value,'1900000000000'); finally Value.Free; end;
    Seen:=Context.ActorObservation(1000,1,2000,'PROCESS_ACCESS',$1000,False);
    Check((Seen.ActorClass='TRUSTED_A') and (Seen.Phase='A_HANDOFF_TO_B') and
      (Seen.ActorIdentity=AIdentity), 'same-epoch approved peer not bound');
    Seen:=Context.ActorObservation(1000,1,2000,'PROCESS_ACCESS',$20,False);
    Check((Seen.AccessMask=$20) and (NHWContextRisk(Seen)=3),
      'first party identity suppressed forbidden VM_WRITE evidence');
    Seen:=Context.ActorObservation(1000,99,2000,'PROCESS_ACCESS',$1000,False);
    Check((Seen.ActorClass='EXTERNAL') and (Seen.PeerID=''),
      'PID reuse inherited trust');
    Value:=Receipt(2,'A_SHUTDOWN');
    try Context.ApplyServerReceipt(Value,'1900000000000'); finally Value.Free; end;
    Value:=Receipt(1,'A_HANDOFF_TO_B');
    try Context.ApplyServerReceipt(Value,'1900000000000'); finally Value.Free; end;
    Seen:=Context.ActorObservation(1000,1,2000,'PROCESS_ACCESS',$1000,False);
    Check(Seen.Phase='A_SHUTDOWN','replayed receipt rolled back cached peer state');
    Context.BindSession('222222222222222222222222');
    Seen:=Context.ActorObservation(1000,1,2000,'PROCESS_ACCESS',$1000,False);
    Check(Seen.ActorClass='EXTERNAL','cross-session binding inherited peer cache');
    Context.Clear;
    Check(Context.LocalIdentity='','shutdown retained local peer identity');
  finally Context.Free; end;
end;

procedure MixedContextAndJournal;
var Context: TCozySecurityContext; Baseline, Dangerous, Mixed, Other: TCozyDetectionContext;
  Journal: TNHWDetectionJournal; Batch, Original: TNHWDetectionBatch;
  I, Found: Integer;
begin
  Context:=TCozySecurityContext.Create('A');
  Journal:=TNHWDetectionJournal.Create;
  try
    Baseline:=Context.Observation('TOKEN_STATE'); Baseline.Baseline:=True;
    Dangerous:=Context.Observation('TOKEN_ACCESS'); Dangerous.AccessMask:=$20;
    Dangerous.ActorClass:='EXTERNAL';
    Mixed:=NHWMergeObservationContext(Baseline,Dangerous);
    Check(Mixed.ContextMixed and not Mixed.Baseline and (Mixed.ActorClass='UNKNOWN') and
      (Mixed.Capability='TOKEN_ACCESS') and (Mixed.AccessMask=$20) and
      (Mixed.TokenDelta=0),'mixed context lost the concrete token modification evidence');
    Baseline.TokenDelta:=2; Baseline.Baseline:=False;
    Mixed:=NHWMergeObservationContext(Baseline,Dangerous);
    Check((Mixed.Capability='TOKEN_STATE') and (Mixed.TokenDelta=2) and
      (Mixed.AccessMask=0),'mixed mask namespaces produced an invalid wire record');
    Journal.AppendContext([dkTokenRights],ndoEngine,1000,1,$04,80,False,Dangerous);
    Check(Journal.Read(Original),'initial token violation missing');
    Other:=Dangerous; Other.AccessMask:=$08;
    Journal.AppendContext([dkTokenRights],ndoEngine,1001,1,$04,10,False,Other);
    Check(Journal.Read(Batch) and (Batch.Records[0].LastTick=1000) and
      (Batch.Records[0].Context.AccessMask=$20),
      'later benign sample refreshed or erased pending attack');
    Journal.Acknowledge(Original);
    Check(Journal.Read(Batch) and (Batch.Records[0].LastTick=1001) and
      (Batch.Records[0].Context.AccessMask=$08),
      'benign follow-up was discarded instead of delivered after the cause');
    Journal.Acknowledge(Batch);
    for I:=1 to 5 do
    begin
      Other:=Dangerous;
      Other.ActorIdentity:=ShortString(StringOfChar(Char(Ord('0')+I),64));
      Journal.AppendContext([dkProcess],ndoEngine,UInt64(2000+I),1,$01,80,False,Other);
    end;
    Check(Journal.Read(Batch),'bounded actor contexts missing');
    Found:=0;
    for I:=0 to Batch.Count-1 do
      if Batch.Records[I].Kind=dkProcess then
      begin
        Inc(Found);
        Check(Batch.Records[I].Context.AccessMask=$20,'overflow discarded dangerous rights');
      end;
    Check(Found=4,'actor journal exceeded its bounded context lanes');
    Other:=Dangerous; Other.AccessMask:=$08;
    Other.ActorIdentity:=ShortString(StringOfChar('6',64));
    Journal.AppendContext([dkProcess],ndoEngine,2006,1,$01,10,False,Other);
    Check(Journal.Read(Batch),'overflow cause disappeared');
    for I:=0 to Batch.Count-1 do
      if (Batch.Records[I].Kind=dkProcess) and Batch.Records[I].Context.ContextMixed then
        Check((Batch.Records[I].LastTick=2005) and (Batch.Records[I].Context.AccessMask=$20),
          'benign overflow revived stale strong evidence');
  finally Journal.Free; Context.Free; end;
end;

begin
  try
    ResolveWinPointers;
    PeerBinding;
    MixedContextAndJournal;
    Writeln('PASS peer lifetime, PID reuse, first-party capabilities, mixed contexts, bounded journal');
  except
    on E: Exception do begin Writeln('FAIL ',E.ClassName,': ',E.Message); Halt(1); end;
  end;
end.
