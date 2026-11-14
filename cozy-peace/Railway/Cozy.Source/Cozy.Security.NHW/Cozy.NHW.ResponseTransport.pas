unit Cozy.NHW.ResponseTransport;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}

interface

uses
  System.Classes, System.SyncObjs, System.JSON, Cozy.Transport, Cozy.Security,
  Cozy.NHW.Guard, Cozy.NHW.ResponsePath.Dispatch, Cozy.NHW.DetectionJournal, Cozy.NHW.Context;

type
  TCozyNHWResponseStopped = reference to procedure;
  TCozyNHWResponseReader = reference to function(Channel: TResponsePathChannel;
    out State: TCozyNHWKernelState): Boolean;

  { Every channel owns its transport, worker, cancellation, retry and sequence.
    These workers run independently of ordinary evidence/authority requests. }
  TCozyNHWResponseChannel = class
  private
    FTransport: TConnectTransport;
    FSecurity: TDeviceSecurity;
    FReader: TCozyNHWResponseReader;
    FServerStop: TCozyNHWResponseStopped;
    FDetectionGuard: TCozyNHWGuard;
    FWake: TEvent;
    FWorker: TThread;
    FChannel: TResponsePathChannel;
    FStage, FSessionID, FSessionToken: string;
    FLastSequence: UInt64;
    FStop: LongInt;
    FFlush: LongInt;
    FDraining: LongInt;
    FLastAttempt, FLastPeerReport, FPendingReceiptStarted: UInt64;
    FPeerReported: LongInt;
    FPendingPeer: TJSONValue;
    FPendingBatch: TNHWDetectionBatch;
    FPendingEvent: TResponsePathEvent;
    FPendingBody: TJSONObject;
    FPendingEpoch: string;
    FPendingTrust: Integer;
    FPendingConfirmed, FHasPending: Boolean;
    procedure ClearPending;
    procedure SubmitTrust(var Event: TResponsePathEvent; Confirmed: Boolean;
      Trust: Integer; const Batch: TNHWDetectionBatch);
    procedure SubmitDriver(var Event: TResponsePathEvent; Confirmed: Boolean;
      Trust: Integer; const Batch: TNHWDetectionBatch);
    procedure SubmitIntegrity(var Event: TResponsePathEvent; Confirmed: Boolean;
      Trust: Integer; const Batch: TNHWDetectionBatch);
    function PrepareBatch(out Batch: TNHWDetectionBatch): Boolean;
  public
    constructor Create(Transport: TConnectTransport; Security: TDeviceSecurity;
      const Reader: TCozyNHWResponseReader; Channel: TResponsePathChannel;
      const Stage, SessionID, SessionToken: string;
      const ServerStop: TCozyNHWResponseStopped = nil;
      DetectionGuard: TCozyNHWGuard = nil);
    destructor Destroy; override;
    procedure Start;
    procedure RequestStop;
    procedure WakeForFlush;
    procedure EndFlush;
    function HasPending: Boolean;
    procedure Join;
    function Stopping: Boolean;
    function Wait: Boolean;
    procedure TrustStep;
    procedure DriverStep;
    procedure IntegrityStep;
  end;

implementation

uses
  System.SysUtils, System.RegularExpressions, Cozy.Integrity,
  Cozy.NHW.Observer.Protocol, Cozy.NHW.SessionTrustLadder, Cozy.NHW.Logging,
  Cozy.NHW.KernelTrust.CorrelationPolicy;

type
  TTrustWorker = class(TThread)
  private FOwner: TCozyNHWResponseChannel;
  protected procedure Execute; override;
  public constructor Create(Owner: TCozyNHWResponseChannel);
  end;
  TDriverWorker = class(TThread)
  private FOwner: TCozyNHWResponseChannel;
  protected procedure Execute; override;
  public constructor Create(Owner: TCozyNHWResponseChannel);
  end;
  TIntegrityWorker = class(TThread)
  private FOwner: TCozyNHWResponseChannel;
  protected procedure Execute; override;
  public constructor Create(Owner: TCozyNHWResponseChannel);
  end;

constructor TTrustWorker.Create(Owner: TCozyNHWResponseChannel);
begin
  FOwner := Owner;
  inherited Create(False);
  FreeOnTerminate := False;
end;
constructor TDriverWorker.Create(Owner: TCozyNHWResponseChannel);
begin
  FOwner := Owner;
  inherited Create(False);
  FreeOnTerminate := False;
end;
constructor TIntegrityWorker.Create(Owner: TCozyNHWResponseChannel);
begin
  FOwner := Owner;
  inherited Create(False);
  FreeOnTerminate := False;
end;

procedure TTrustWorker.Execute;
begin
  while not FOwner.Stopping do
  begin
    try FOwner.TrustStep; except { Unknown delivery, never an attack vote. } end;
    if not FOwner.Wait then Exit;
  end;
end;
procedure TDriverWorker.Execute;
begin
  while not FOwner.Stopping do
  begin
    try FOwner.DriverStep; except { This channel cannot disable another. } end;
    if not FOwner.Wait then Exit;
  end;
end;
procedure TIntegrityWorker.Execute;
begin
  while not FOwner.Stopping do
  begin
    try FOwner.IntegrityStep; except { No fail-open authority is granted. } end;
    if not FOwner.Wait then Exit;
  end;
end;

function ReadText(Document: TJSONObject; const Name: string; Limit: Integer): string;
var Value: TJSONValue;
begin
  Value := Document.GetValue(Name);
  if not (Value is TJSONString) then raise EConvertError.Create('NHW_RESPONSE_INVALID');
  Result := Value.Value;
  if (Result = '') or (Length(Result) > Limit) then raise EConvertError.Create('NHW_RESPONSE_INVALID');
end;

function ReadNumber(Document: TJSONObject; const Name: string): Int64;
var Value: TJSONValue;
begin
  Value := Document.GetValue(Name);
  if not (Value is TJSONNumber) or not TryStrToInt64(Value.Value, Result) or
    (Result < 1) or (Result > 9007199254740991) then
    raise EConvertError.Create('NHW_RESPONSE_INVALID');
end;

function ReadBoolean(Document: TJSONObject; const Name: string): Boolean;
var Value: TJSONValue;
begin
  Value := Document.GetValue(Name);
  if not (Value is TJSONBool) then raise EConvertError.Create('NHW_RESPONSE_INVALID');
  Result := TJSONBool(Value).AsBoolean;
end;

function Data(Response: TJSONObject): TJSONObject;
var Value: TJSONValue;
begin
  if (Response = nil) or not ReadBoolean(Response, 'ok') then
    raise EConvertError.Create('NHW_RESPONSE_UNAVAILABLE');
  Value := Response.GetValue('data');
  if not (Value is TJSONObject) then raise EConvertError.Create('NHW_RESPONSE_INVALID');
  Result := TJSONObject(Value);
end;

constructor TCozyNHWResponseChannel.Create(Transport: TConnectTransport;
  Security: TDeviceSecurity; const Reader: TCozyNHWResponseReader;
  Channel: TResponsePathChannel; const Stage, SessionID, SessionToken: string;
  const ServerStop: TCozyNHWResponseStopped; DetectionGuard: TCozyNHWGuard);
begin
  inherited Create;
  if (Transport = nil) or (Security = nil) or not Assigned(Reader) or
    ((Stage <> 'A') and (Stage <> 'B') and (Stage <> 'O')) then
    raise EArgumentException.Create('NHW_RESPONSE_CONTEXT_INVALID');
  FWake := TEvent.Create(nil, True, False, '');
  FTransport := Transport.Fork;
  FSecurity := Security;
  FReader := Reader;
  FServerStop := ServerStop;
  FDetectionGuard := DetectionGuard;
  FChannel := Channel;
  FStage := Stage;
  FSessionID := SessionID;
  FSessionToken := SessionToken;
end;

destructor TCozyNHWResponseChannel.Destroy;
begin
  RequestStop;
  Join;
  FTransport.Free;
  FWake.Free;
  ClearPending;
  FReader := nil; FServerStop := nil;
  FDetectionGuard := nil;
  FSecurity := nil;
  WipeText(FSessionToken);
  WipeText(FSessionID);
  inherited Destroy;
end;

procedure TCozyNHWResponseChannel.Start;
begin
  if (FWorker <> nil) or Stopping then Exit;
  { All owner fields are ready. Running-thread construction avoids a failed
    Start leaving a suspended worker for destruction to join forever. }
  case FChannel of
    rpcTrust: FWorker := TTrustWorker.Create(Self);
    rpcDriver: FWorker := TDriverWorker.Create(Self);
    rpcIntegrity: FWorker := TIntegrityWorker.Create(Self);
  end;
end;
procedure TCozyNHWResponseChannel.RequestStop;
begin
  TInterlocked.Exchange(FStop, 1);
  if FWake <> nil then FWake.SetEvent;
  if FTransport <> nil then FTransport.CancelPending;
end;
procedure TCozyNHWResponseChannel.Join;
begin
  if FWorker = nil then Exit;
  FWorker.WaitFor;
  FreeAndNil(FWorker);
end;
function TCozyNHWResponseChannel.Stopping: Boolean;
begin Result := TInterlocked.CompareExchange(FStop, 0, 0) <> 0; end;
function TCozyNHWResponseChannel.Wait: Boolean;
begin
  FWake.WaitFor(50);
  FWake.ResetEvent;
  Result := not Stopping;
end;

procedure TCozyNHWResponseChannel.WakeForFlush;
begin
  TInterlocked.Exchange(FDraining, 1);
  TInterlocked.Exchange(FFlush, 1);
  FWake.SetEvent;
end;

procedure TCozyNHWResponseChannel.EndFlush;
begin
  TInterlocked.Exchange(FDraining, 0);
end;

function TCozyNHWResponseChannel.HasPending: Boolean;
begin
  Result := (FDetectionGuard <> nil) and
    ((TInterlocked.CompareExchange(FPeerReported,0,0)=0) or
      FDetectionGuard.HasPendingDetections(FChannel));
end;

function TCozyNHWResponseChannel.PrepareBatch(out Batch: TNHWDetectionBatch): Boolean;
var FlushRequested: Boolean;
begin
  Batch := Default(TNHWDetectionBatch);
  Result := False;
  if Stopping or (FDetectionGuard = nil) or (FLastSequence = High(UInt64)) then Exit;
  { This monotonic OS clock is available before pointer bootstrap, including
    when the sensor worker reports a startup availability failure. Flush is
    a one-shot wake, not a permanent bypass of the retry backoff. }
  FlushRequested := TInterlocked.Exchange(FFlush, 0) <> 0;
  if (FLastAttempt <> 0) and not FlushRequested and
    (ObserverClockTick - FLastAttempt < 1000) then Exit;
  if FHasPending then begin Batch := FPendingBatch; Result := True; end
  else Result := FDetectionGuard.ReadDetectionBatch(FChannel, Batch);
  if not Result and (FDetectionGuard <> nil) then
    Result := (TInterlocked.CompareExchange(FPeerReported,0,0)=0) or
      ((FLastPeerReport<>0) and (ObserverClockTick-FLastPeerReport>=10000));
  if Result then
  begin
    FDetectionGuard.SecurityContext.PrepareLocalIdentity;
    FLastAttempt := ObserverClockTick;
  end;
end;

{ Same evidence exclusions and confirmation thresholds as the existing engine.
  Unsupported/local-only policy evidence is preserved for diagnostics, but does
  not become authority merely because it was copied into a response message. }
function AuthorityKinds(const Kinds: TDetectionKinds): TDetectionKinds;
begin
  Result := Kinds - [dkKernelTelemetryGap, dkVulnerableDriver,
    dkKernelMappingEvidence, dkDriverTimelineKernel, dkDriverSignerAttestation,
    dkDriverLoadProvenance, dkDriverServiceTimeline, dkCodeIntegrityPolicy];
end;

procedure TCozyNHWResponseChannel.TrustStep;
var
  Event: TResponsePathEvent;
  State: TCozyNHWKernelState;
  Batch: TNHWDetectionBatch;
  Confirmed: Boolean;
  I: Integer;
begin
  if (FChannel <> rpcTrust) or not PrepareBatch(Batch) then Exit;
  try
    State := Default(TCozyNHWKernelState);
    if not FHasPending then
    begin
    Confirmed := False;
    if Assigned(FReader) and FReader(rpcTrust, State) then
      Confirmed := EvaluateKernelCorrelation(AuthorityKinds(State.ObservationKinds),
        State.SessionTrust, True).CanInvalidate and
        (State.TrustReceipt.Channel = rpcTrust) and
        (State.TrustResponse.Channel = rpcTrust) and
        (State.TrustReceipt.Sequence <> 0) and
        (State.TrustReceipt.Sequence = State.TrustResponse.Sequence) and
        (State.TrustReceipt.Digest <> 0) and
        (State.TrustReceipt.Digest = State.TrustResponse.Digest) and
        (State.TrustReceipt.Tick = State.TrustResponse.Tick) and
        (State.TrustResponse.Tick <= ObserverClockTick) and
        (ObserverClockTick - State.TrustResponse.Tick <= 90000);
    for I := 0 to Batch.Count - 1 do
      if Confirmed and (Batch.Records[I].Origin = ndoKernelTrust) and
        (Batch.Records[I].Kind in AuthorityKinds(State.ObservationKinds)) then
      begin
        Batch.Records[I].Correlated := True;
        if Batch.Records[I].Confidence < 75 then Batch.Records[I].Confidence := 75;
      end;
    Event := Default(TResponsePathEvent);
    Event.Channel := rpcTrust;
    Event.Sequence := FLastSequence + 1;
    Event.Tick := ObserverClockTick;
    FPendingPeer := FDetectionGuard.SecurityContext.PeerPayload;
    FPendingBatch := Batch;
    FPendingEvent := Event;
    FPendingConfirmed := Confirmed;
    FPendingTrust := Ord(State.SessionTrust);
    FHasPending := True;
    end;
    SubmitTrust(FPendingEvent, FPendingConfirmed, FPendingTrust, FPendingBatch);
    FLastSequence := FPendingEvent.Sequence;
    FDetectionGuard.AcknowledgeDetectionBatch(rpcTrust, FPendingBatch);
    TInterlocked.Exchange(FPeerReported,1);
    FLastPeerReport := ObserverClockTick;
    ClearPending;
    { Progress during a bounded drain may send the next batch immediately.
      A failed send retains its retry delay and immutable pending batch. }
    if TInterlocked.CompareExchange(FDraining, 0, 0) <> 0 then FLastAttempt := 0;
  finally
    FillChar(Batch, SizeOf(Batch), 0);
    FillChar(State, SizeOf(State), 0);
  end;
end;
procedure TCozyNHWResponseChannel.DriverStep;
var
  Event: TResponsePathEvent;
  State: TCozyNHWKernelState;
  Batch: TNHWDetectionBatch;
  Confirmed: Boolean;
  I: Integer;
begin
  if (FChannel <> rpcDriver) or not PrepareBatch(Batch) then Exit;
  try
    State := Default(TCozyNHWKernelState);
    if not FHasPending then
    begin
    Confirmed := False;
    if Assigned(FReader) and FReader(rpcDriver, State) then
      Confirmed := EvaluateKernelCorrelation(AuthorityKinds(State.ObservationKinds),
        State.SessionTrust, True).CanInvalidate and
        (State.DriverReceipt.Channel = rpcDriver) and
        (State.DriverResponse.Channel = rpcDriver) and
        (State.DriverReceipt.Sequence <> 0) and
        (State.DriverReceipt.Sequence = State.DriverResponse.Sequence) and
        (State.DriverReceipt.Digest <> 0) and
        (State.DriverReceipt.Digest = State.DriverResponse.Digest) and
        (State.DriverReceipt.Tick = State.DriverResponse.Tick) and
        (State.DriverResponse.Tick <= ObserverClockTick) and
        (ObserverClockTick - State.DriverResponse.Tick <= 90000);
    for I := 0 to Batch.Count - 1 do
      if Confirmed and (Batch.Records[I].Origin = ndoKernelTrust) and
        (Batch.Records[I].Kind in AuthorityKinds(State.ObservationKinds)) then
      begin
        Batch.Records[I].Correlated := True;
        if Batch.Records[I].Confidence < 75 then Batch.Records[I].Confidence := 75;
      end;
    Event := Default(TResponsePathEvent);
    Event.Channel := rpcDriver;
    Event.Sequence := FLastSequence + 1;
    Event.Tick := ObserverClockTick;
    FPendingPeer := FDetectionGuard.SecurityContext.PeerPayload;
    FPendingBatch := Batch;
    FPendingEvent := Event;
    FPendingConfirmed := Confirmed;
    FPendingTrust := Ord(State.SessionTrust);
    FHasPending := True;
    end;
    SubmitDriver(FPendingEvent, FPendingConfirmed, FPendingTrust, FPendingBatch);
    FLastSequence := FPendingEvent.Sequence;
    FDetectionGuard.AcknowledgeDetectionBatch(rpcDriver, FPendingBatch);
    TInterlocked.Exchange(FPeerReported,1);
    FLastPeerReport := ObserverClockTick;
    ClearPending;
    { Progress during a bounded drain may send the next batch immediately.
      A failed send retains its retry delay and immutable pending batch. }
    if TInterlocked.CompareExchange(FDraining, 0, 0) <> 0 then FLastAttempt := 0;
  finally
    FillChar(Batch, SizeOf(Batch), 0);
    FillChar(State, SizeOf(State), 0);
  end;
end;
procedure TCozyNHWResponseChannel.IntegrityStep;
var
  Event: TResponsePathEvent;
  State: TCozyNHWKernelState;
  Batch: TNHWDetectionBatch;
  Confirmed: Boolean;
  I: Integer;
begin
  if (FChannel <> rpcIntegrity) or not PrepareBatch(Batch) then Exit;
  try
    State := Default(TCozyNHWKernelState);
    if not FHasPending then
    begin
    Confirmed := False;
    if Assigned(FReader) and FReader(rpcIntegrity, State) then
      Confirmed := EvaluateKernelCorrelation(AuthorityKinds(State.ObservationKinds),
        State.SessionTrust, True).CanInvalidate and
        (State.IntegrityReceipt.Channel = rpcIntegrity) and
        (State.IntegrityResponse.Channel = rpcIntegrity) and
        (State.IntegrityReceipt.Sequence <> 0) and
        (State.IntegrityReceipt.Sequence = State.IntegrityResponse.Sequence) and
        (State.IntegrityReceipt.Digest <> 0) and
        (State.IntegrityReceipt.Digest = State.IntegrityResponse.Digest) and
        (State.IntegrityReceipt.Tick = State.IntegrityResponse.Tick) and
        (State.IntegrityResponse.Tick <= ObserverClockTick) and
        (ObserverClockTick - State.IntegrityResponse.Tick <= 90000);
    for I := 0 to Batch.Count - 1 do
      if Confirmed and (Batch.Records[I].Origin = ndoKernelTrust) and
        (Batch.Records[I].Kind in AuthorityKinds(State.ObservationKinds)) then
      begin
        Batch.Records[I].Correlated := True;
        if Batch.Records[I].Confidence < 75 then Batch.Records[I].Confidence := 75;
      end;
    Event := Default(TResponsePathEvent);
    Event.Channel := rpcIntegrity;
    Event.Sequence := FLastSequence + 1;
    Event.Tick := ObserverClockTick;
    FPendingPeer := FDetectionGuard.SecurityContext.PeerPayload;
    FPendingBatch := Batch;
    FPendingEvent := Event;
    FPendingConfirmed := Confirmed;
    FPendingTrust := Ord(State.SessionTrust);
    FHasPending := True;
    end;
    SubmitIntegrity(FPendingEvent, FPendingConfirmed, FPendingTrust, FPendingBatch);
    FLastSequence := FPendingEvent.Sequence;
    FDetectionGuard.AcknowledgeDetectionBatch(rpcIntegrity, FPendingBatch);
    TInterlocked.Exchange(FPeerReported,1);
    FLastPeerReport := ObserverClockTick;
    ClearPending;
    { Progress during a bounded drain may send the next batch immediately.
      A failed send retains its retry delay and immutable pending batch. }
    if TInterlocked.CompareExchange(FDraining, 0, 0) <> 0 then FLastAttempt := 0;
  finally
    FillChar(Batch, SizeOf(Batch), 0);
    FillChar(State, SizeOf(State), 0);
  end;
end;

{ Encoding is shared, control flow is not. This routine cannot send a
  request, acknowledge a journal, change trust or end a session. }
procedure EncodeDetectionPayload(var Event: TResponsePathEvent;
  Confirmed: Boolean; Trust: Integer; const Batch: TNHWDetectionBatch;
  Peer: TJSONValue; out PayloadText, DigestText: string);
var
  Payload, Detection: TJSONObject;
  Detections: TJSONArray;
  I: Integer;
  DetectionText: string;
begin
  PayloadText := ''; DigestText := '';
  if (Batch.Count < 0) or (Batch.Count > NHWDetectionBatchCapacity) then
    raise EArgumentOutOfRangeException.Create('NHW_DETECTION_BATCH_INVALID');
  Payload := TJSONObject.Create;
  Detection := nil; Detections := nil;
  try
    Detections := TJSONArray.Create;
    for I := 0 to Batch.Count - 1 do
    begin
      Detection := TJSONObject.Create;
      Detection.AddPair('id', NHWDetectionName(Batch.Records[I].Kind));
      Detection.AddPair('source', NHWDetectionSource(Batch.Records[I].Origin));
      Detection.AddPair('firstTick', IntToHex(Int64(Batch.Records[I].FirstTick),16).ToLower);
      Detection.AddPair('lastTick', IntToHex(Int64(Batch.Records[I].LastTick),16).ToLower);
      Detection.AddPair('count', TJSONNumber.Create(Batch.Records[I].Count));
      Detection.AddPair('families', TJSONNumber.Create(Batch.Records[I].Families));
      Detection.AddPair('confidence', TJSONNumber.Create(Batch.Records[I].Confidence));
      Detection.AddPair('correlation', TJSONBool.Create(Batch.Records[I].Correlated));
      Detection.AddPair('attestationSequence',
        IntToHex(Int64(Batch.Records[I].AttestationSequence),16).ToLower);
      Detection.AddPair('localOnly', TJSONBool.Create(not Batch.Records[I].Correlated));
      if Batch.Records[I].ObservedOnly then
        Detection.AddPair('signal', 'OBSERVED')
      else
        Detection.AddPair('signal', 'DETECTED');
      Detection.AddPair('context', NHWContextJSON(Batch.Records[I].Context));
      Detections.AddElement(Detection); Detection := nil;
    end;
    DetectionText := Detections.ToJSON;
    DigestText := Copy(IntegritySHA512Text(DetectionText), 1, 16).ToLower;
    Event.Digest := StrToUInt64('$' + DigestText);
    Payload.AddPair('version', TJSONNumber.Create(5));
    Payload.AddPair('sequence', IntToHex(Int64(Event.Sequence),16).ToLower);
    Payload.AddPair('tick', IntToHex(Int64(Event.Tick),16).ToLower);
    Payload.AddPair('digest', DigestText);
    Payload.AddPair('confirmed', TJSONBool.Create(Confirmed));
    Payload.AddPair('trust', TJSONNumber.Create(Trust));
    Payload.AddPair('detections', Detections); Detections := nil;
    if Peer=nil then Payload.AddPair('peer',TJSONNull.Create)
    else Payload.AddPair('peer',TJSONObject.ParseJSONValue(Peer.ToJSON));
    PayloadText := Payload.ToJSON;
    if Length(TEncoding.UTF8.GetBytes(PayloadText))>16384 then
      raise EConvertError.Create('NHW_CONTEXT_PAYLOAD_TOO_LARGE');
  finally
    Payload.Free; Detection.Free; Detections.Free;
    WipeText(DetectionText);
  end;
end;

procedure TCozyNHWResponseChannel.SubmitTrust(var Event: TResponsePathEvent;
  Confirmed: Boolean; Trust: Integer; const Batch: TNHWDetectionBatch);
var
  Body, Answer, Challenge, Reply: TJSONObject;
  PayloadText, Binding, Canonical, Nonce, Epoch, ID, SequenceText,
    DigestText, MachineID: string;
  ExpiresAt: Int64;
  ReceiptStarted: UInt64;
  procedure Bind(Obj: TJSONObject; const Action: string);
  begin
    Obj.AddPair('action', Action);
    Obj.AddPair('stage', FStage);
    Obj.AddPair('sessionId', FSessionID);
    Obj.AddPair('sessionToken', FSessionToken);
    Obj.AddPair('machineId', MachineID);
    Obj.AddPair('binding', Binding);
  end;
begin
  if (FChannel <> rpcTrust) or (Event.Channel <> rpcTrust) then
    raise EConvertError.Create('NHW_RESPONSE_CHANNEL_INVALID');
  if Stopping then raise EAbort.Create('NHW_RESPONSE_STOPPED');
  Body := nil; Answer := nil;
  try
    SequenceText := IntToHex(Int64(Event.Sequence),16).ToLower;
    EncodeDetectionPayload(Event, Confirmed, Trust, Batch, FPendingPeer, PayloadText, DigestText);
    Binding := IntegritySHA512Text(PayloadText);
    MachineID := FSecurity.MachineID;
    if FPendingBody = nil then
    begin
    Body := TJSONObject.Create;
    Bind(Body, 'nhwTrustChallenge');
    Answer := FTransport.PostJSON('security', Body, 3000);
    Challenge := Data(Answer);
    if (Challenge.Count <> 6) or (ReadNumber(Challenge, 'version') <> 1) or
      (ReadText(Challenge,'channel',16) <> 'trust') then
      raise EConvertError.Create('NHW_RESPONSE_INVALID');
    ID := ReadText(Challenge,'challengeId',48);
    Nonce := ReadText(Challenge,'nonce',48);
    Epoch := ReadText(Challenge,'epoch',20);
    ExpiresAt := ReadNumber(Challenge,'expiresAt');
    if not TRegEx.IsMatch(ID, '^[a-f0-9]{48}$') or
      not TRegEx.IsMatch(Nonce, '^[a-f0-9]{48}$') or
      not TRegEx.IsMatch(Epoch, '^[1-9][0-9]{0,15}$') then
      raise EConvertError.Create('NHW_RESPONSE_INVALID');
    FreeAndNil(Answer);
    FreeAndNil(Body);
    if Stopping then raise EAbort.Create('NHW_RESPONSE_STOPPED');
    Canonical := 'COZY-NHW-TRUST-RESPONSE-V1' + #10 +
      FStage + #10 + FSessionID + #10 + MachineID + #10 + Binding + #10 +
      ID + #10 + Nonce + #10 + Epoch + #10 + IntToStr(ExpiresAt) + #10 + Binding;
    Body := TJSONObject.Create;
    Bind(Body, 'nhwTrustSubmit');
    Body.AddPair('challengeId', ID);
    Body.AddPair('payload', PayloadText);
    Body.AddPair('signature', FSecurity.Sign(Canonical));
    FPendingBody := Body; Body := nil;
    FPendingEpoch := Epoch;
    end
    else Epoch := FPendingEpoch;
    { An identical signed submission may return a cached original receipt.
      Keep the first send clock through lost ACKs and nonce replacement so
      retrying delivery cannot renew that receipt's peer TTL. }
    if FPendingReceiptStarted = 0 then
      FPendingReceiptStarted := ObserverClockTick;
    ReceiptStarted := FPendingReceiptStarted;
    Answer := FTransport.PostJSON('security', FPendingBody, 3000);
    { A challenge can expire before commit. Only an authenticated explicit
      expiry retires the nonce; a lost reply retries the exact same request. }
    if (Answer <> nil) and (Answer.GetValue('error') <> nil) and
      (Answer.GetValue('error').Value = 'SECURITY_CHALLENGE_INVALID') then
    begin
      FreeAndNil(FPendingBody);
      WipeText(FPendingEpoch);
      { A new nonce is a new delivery attempt, not a new observation. Keep
        the old record ticks and advance only the envelope clock so stale
        evidence cannot look fresh after an outage. }
      FPendingEvent.Tick := ObserverClockTick;
    end;
    Reply := Data(Answer);
    if (Reply.Count <> 10) or (ReadNumber(Reply,'version') <> 1) or
      (ReadText(Reply,'channel',16) <> 'trust') or
      (ReadText(Reply,'sequence',16) <> SequenceText) or
      (ReadText(Reply,'digest',16) <> DigestText) or
      (ReadText(Reply,'epoch',20) <> Epoch) or
      (ReadText(Reply,'scope',16) <> 'OWNED_A_B_O') or
      not ReadBoolean(Reply,'accepted') or ReadBoolean(Reply,'attested') then
      raise EConvertError.Create('NHW_RESPONSE_INVALID');
    { The reply acknowledges reporting only. It is never used as permission. }
    if ReadBoolean(Reply,'stopped') then
    begin
      if FDetectionGuard<>nil then FDetectionGuard.SecurityContext.Clear;
      if Assigned(FServerStop) then FServerStop();
    end
    else if FDetectionGuard<>nil then
      FDetectionGuard.SecurityContext.ApplyServerReceipt(Reply.GetValue('peerContext'),Epoch,ReceiptStarted);
  finally
    Answer.Free;
    Body.Free;
    WipeText(PayloadText); WipeText(Canonical); WipeText(Nonce);
  end;
end;

procedure TCozyNHWResponseChannel.SubmitDriver(var Event: TResponsePathEvent;
  Confirmed: Boolean; Trust: Integer; const Batch: TNHWDetectionBatch);
var
  Body, Answer, Challenge, Reply: TJSONObject;
  PayloadText, Binding, Canonical, Nonce, Epoch, ID, SequenceText,
    DigestText, MachineID: string;
  ExpiresAt: Int64;
  ReceiptStarted: UInt64;
  procedure Bind(Obj: TJSONObject; const Action: string);
  begin
    Obj.AddPair('action', Action);
    Obj.AddPair('stage', FStage);
    Obj.AddPair('sessionId', FSessionID);
    Obj.AddPair('sessionToken', FSessionToken);
    Obj.AddPair('machineId', MachineID);
    Obj.AddPair('binding', Binding);
  end;
begin
  if (FChannel <> rpcDriver) or (Event.Channel <> rpcDriver) then
    raise EConvertError.Create('NHW_RESPONSE_CHANNEL_INVALID');
  if Stopping then raise EAbort.Create('NHW_RESPONSE_STOPPED');
  Body := nil; Answer := nil;
  try
    SequenceText := IntToHex(Int64(Event.Sequence),16).ToLower;
    EncodeDetectionPayload(Event, Confirmed, Trust, Batch, FPendingPeer, PayloadText, DigestText);
    Binding := IntegritySHA512Text(PayloadText);
    MachineID := FSecurity.MachineID;
    if FPendingBody = nil then
    begin
    Body := TJSONObject.Create;
    Bind(Body, 'nhwDriverChallenge');
    Answer := FTransport.PostJSON('security', Body, 3000);
    Challenge := Data(Answer);
    if (Challenge.Count <> 6) or (ReadNumber(Challenge, 'version') <> 1) or
      (ReadText(Challenge,'channel',16) <> 'driver') then
      raise EConvertError.Create('NHW_RESPONSE_INVALID');
    ID := ReadText(Challenge,'challengeId',48);
    Nonce := ReadText(Challenge,'nonce',48);
    Epoch := ReadText(Challenge,'epoch',20);
    ExpiresAt := ReadNumber(Challenge,'expiresAt');
    if not TRegEx.IsMatch(ID, '^[a-f0-9]{48}$') or
      not TRegEx.IsMatch(Nonce, '^[a-f0-9]{48}$') or
      not TRegEx.IsMatch(Epoch, '^[1-9][0-9]{0,15}$') then
      raise EConvertError.Create('NHW_RESPONSE_INVALID');
    FreeAndNil(Answer);
    FreeAndNil(Body);
    if Stopping then raise EAbort.Create('NHW_RESPONSE_STOPPED');
    Canonical := 'COZY-NHW-DRIVER-RESPONSE-V1' + #10 +
      FStage + #10 + FSessionID + #10 + MachineID + #10 + Binding + #10 +
      ID + #10 + Nonce + #10 + Epoch + #10 + IntToStr(ExpiresAt) + #10 + Binding;
    Body := TJSONObject.Create;
    Bind(Body, 'nhwDriverSubmit');
    Body.AddPair('challengeId', ID);
    Body.AddPair('payload', PayloadText);
    Body.AddPair('signature', FSecurity.Sign(Canonical));
    FPendingBody := Body; Body := nil;
    FPendingEpoch := Epoch;
    end
    else Epoch := FPendingEpoch;
    { An identical signed submission may return a cached original receipt.
      Keep the first send clock through lost ACKs and nonce replacement so
      retrying delivery cannot renew that receipt's peer TTL. }
    if FPendingReceiptStarted = 0 then
      FPendingReceiptStarted := ObserverClockTick;
    ReceiptStarted := FPendingReceiptStarted;
    Answer := FTransport.PostJSON('security', FPendingBody, 3000);
    { A challenge can expire before commit. Only an authenticated explicit
      expiry retires the nonce; a lost reply retries the exact same request. }
    if (Answer <> nil) and (Answer.GetValue('error') <> nil) and
      (Answer.GetValue('error').Value = 'SECURITY_CHALLENGE_INVALID') then
    begin
      FreeAndNil(FPendingBody);
      WipeText(FPendingEpoch);
      { A new nonce is a new delivery attempt, not a new observation. Keep
        the old record ticks and advance only the envelope clock so stale
        evidence cannot look fresh after an outage. }
      FPendingEvent.Tick := ObserverClockTick;
    end;
    Reply := Data(Answer);
    if (Reply.Count <> 10) or (ReadNumber(Reply,'version') <> 1) or
      (ReadText(Reply,'channel',16) <> 'driver') or
      (ReadText(Reply,'sequence',16) <> SequenceText) or
      (ReadText(Reply,'digest',16) <> DigestText) or
      (ReadText(Reply,'epoch',20) <> Epoch) or
      (ReadText(Reply,'scope',16) <> 'OWNED_A_B_O') or
      not ReadBoolean(Reply,'accepted') or ReadBoolean(Reply,'attested') then
      raise EConvertError.Create('NHW_RESPONSE_INVALID');
    { The reply acknowledges reporting only. It is never used as permission. }
    if ReadBoolean(Reply,'stopped') then
    begin
      if FDetectionGuard<>nil then FDetectionGuard.SecurityContext.Clear;
      if Assigned(FServerStop) then FServerStop();
    end
    else if FDetectionGuard<>nil then
      FDetectionGuard.SecurityContext.ApplyServerReceipt(Reply.GetValue('peerContext'),Epoch,ReceiptStarted);
  finally
    Answer.Free;
    Body.Free;
    WipeText(PayloadText); WipeText(Canonical); WipeText(Nonce);
  end;
end;

procedure TCozyNHWResponseChannel.SubmitIntegrity(var Event: TResponsePathEvent;
  Confirmed: Boolean; Trust: Integer; const Batch: TNHWDetectionBatch);
var
  Body, Answer, Challenge, Reply: TJSONObject;
  PayloadText, Binding, Canonical, Nonce, Epoch, ID, SequenceText,
    DigestText, MachineID: string;
  ExpiresAt: Int64;
  ReceiptStarted: UInt64;
  procedure Bind(Obj: TJSONObject; const Action: string);
  begin
    Obj.AddPair('action', Action);
    Obj.AddPair('stage', FStage);
    Obj.AddPair('sessionId', FSessionID);
    Obj.AddPair('sessionToken', FSessionToken);
    Obj.AddPair('machineId', MachineID);
    Obj.AddPair('binding', Binding);
  end;
begin
  if (FChannel <> rpcIntegrity) or (Event.Channel <> rpcIntegrity) then
    raise EConvertError.Create('NHW_RESPONSE_CHANNEL_INVALID');
  if Stopping then raise EAbort.Create('NHW_RESPONSE_STOPPED');
  Body := nil; Answer := nil;
  try
    SequenceText := IntToHex(Int64(Event.Sequence),16).ToLower;
    EncodeDetectionPayload(Event, Confirmed, Trust, Batch, FPendingPeer, PayloadText, DigestText);
    Binding := IntegritySHA512Text(PayloadText);
    MachineID := FSecurity.MachineID;
    if FPendingBody = nil then
    begin
    Body := TJSONObject.Create;
    Bind(Body, 'nhwIntegrityChallenge');
    Answer := FTransport.PostJSON('security', Body, 3000);
    Challenge := Data(Answer);
    if (Challenge.Count <> 6) or (ReadNumber(Challenge, 'version') <> 1) or
      (ReadText(Challenge,'channel',16) <> 'integrity') then
      raise EConvertError.Create('NHW_RESPONSE_INVALID');
    ID := ReadText(Challenge,'challengeId',48);
    Nonce := ReadText(Challenge,'nonce',48);
    Epoch := ReadText(Challenge,'epoch',20);
    ExpiresAt := ReadNumber(Challenge,'expiresAt');
    if not TRegEx.IsMatch(ID, '^[a-f0-9]{48}$') or
      not TRegEx.IsMatch(Nonce, '^[a-f0-9]{48}$') or
      not TRegEx.IsMatch(Epoch, '^[1-9][0-9]{0,15}$') then
      raise EConvertError.Create('NHW_RESPONSE_INVALID');
    FreeAndNil(Answer);
    FreeAndNil(Body);
    if Stopping then raise EAbort.Create('NHW_RESPONSE_STOPPED');
    Canonical := 'COZY-NHW-INTEGRITY-RESPONSE-V1' + #10 +
      FStage + #10 + FSessionID + #10 + MachineID + #10 + Binding + #10 +
      ID + #10 + Nonce + #10 + Epoch + #10 + IntToStr(ExpiresAt) + #10 + Binding;
    Body := TJSONObject.Create;
    Bind(Body, 'nhwIntegritySubmit');
    Body.AddPair('challengeId', ID);
    Body.AddPair('payload', PayloadText);
    Body.AddPair('signature', FSecurity.Sign(Canonical));
    FPendingBody := Body; Body := nil;
    FPendingEpoch := Epoch;
    end
    else Epoch := FPendingEpoch;
    { An identical signed submission may return a cached original receipt.
      Keep the first send clock through lost ACKs and nonce replacement so
      retrying delivery cannot renew that receipt's peer TTL. }
    if FPendingReceiptStarted = 0 then
      FPendingReceiptStarted := ObserverClockTick;
    ReceiptStarted := FPendingReceiptStarted;
    Answer := FTransport.PostJSON('security', FPendingBody, 3000);
    { A challenge can expire before commit. Only an authenticated explicit
      expiry retires the nonce; a lost reply retries the exact same request. }
    if (Answer <> nil) and (Answer.GetValue('error') <> nil) and
      (Answer.GetValue('error').Value = 'SECURITY_CHALLENGE_INVALID') then
    begin
      FreeAndNil(FPendingBody);
      WipeText(FPendingEpoch);
      { A new nonce is a new delivery attempt, not a new observation. Keep
        the old record ticks and advance only the envelope clock so stale
        evidence cannot look fresh after an outage. }
      FPendingEvent.Tick := ObserverClockTick;
    end;
    Reply := Data(Answer);
    if (Reply.Count <> 10) or (ReadNumber(Reply,'version') <> 1) or
      (ReadText(Reply,'channel',16) <> 'integrity') or
      (ReadText(Reply,'sequence',16) <> SequenceText) or
      (ReadText(Reply,'digest',16) <> DigestText) or
      (ReadText(Reply,'epoch',20) <> Epoch) or
      (ReadText(Reply,'scope',16) <> 'OWNED_A_B_O') or
      not ReadBoolean(Reply,'accepted') or ReadBoolean(Reply,'attested') then
      raise EConvertError.Create('NHW_RESPONSE_INVALID');
    { The reply acknowledges reporting only. It is never used as permission. }
    if ReadBoolean(Reply,'stopped') then
    begin
      if FDetectionGuard<>nil then FDetectionGuard.SecurityContext.Clear;
      if Assigned(FServerStop) then FServerStop();
    end
    else if FDetectionGuard<>nil then
      FDetectionGuard.SecurityContext.ApplyServerReceipt(Reply.GetValue('peerContext'),Epoch,ReceiptStarted);
  finally
    Answer.Free;
    Body.Free;
    WipeText(PayloadText); WipeText(Canonical); WipeText(Nonce);
  end;
end;

procedure TCozyNHWResponseChannel.ClearPending;
begin
  FPendingReceiptStarted := 0;
  FreeAndNil(FPendingPeer);
  FreeAndNil(FPendingBody);
  WipeText(FPendingEpoch);
  FillChar(FPendingBatch, SizeOf(FPendingBatch), 0);
  FillChar(FPendingEvent, SizeOf(FPendingEvent), 0);
  FPendingTrust := 0;
  FPendingConfirmed := False;
  FHasPending := False;
end;

end.
