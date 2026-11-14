unit Cozy.NHW.Authority;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}

interface

uses
  System.JSON, Cozy.ServerAuthority, Cozy.NHW.Guard,
  Cozy.NHW.SessionEpochGuard, Cozy.NHW.ServerNonceAttestation,
  Cozy.NHW.SessionInvalidation, Cozy.NHW.TpmQuote,
  Cozy.NHW.ResponseTransport, Cozy.NHW.ResponsePath.Dispatch,
  Cozy.Transport, Cozy.Security;

type
  TCozyNHWKernelReader = reference to function(out State: TCozyNHWKernelState): Boolean;

  { One instance per A/B/O session, owned by the serialized API worker. The reader
    copies the last sensor result and does not hold its lock during TBS or I/O. }
  TCozyNHWAuthority = class(TInterfacedObject, ICozyAuthorityExtension)
  private
    FReader: TCozyNHWKernelReader;
    FPathReader: TCozyNHWResponseReader;
    FServerStop: TCozyNHWResponseStopped;
    FDetectionGuard: TCozyNHWGuard;
    FReplay: TSessionEpochGuard;
    FPending: TServerNonceAttestation;
    FInvalidation: TSessionInvalidationLatch;
    FLastSequence: UInt64;
    FQuoteProvider: ICozyTpmQuoter;
    FResponses: array[TResponsePathChannel] of TCozyNHWResponseChannel;
    FResponseContext: string;
  public
    constructor Create(const Reader: TCozyNHWKernelReader;
      const PathReader: TCozyNHWResponseReader = nil;
      const ServerStop: TCozyNHWResponseStopped = nil;
      DetectionGuard: TCozyNHWGuard = nil);
    destructor Destroy; override;
    procedure SetQuoteProvider(const Quoter: ICozyTpmQuoter);
    procedure ConfigureResponses(Transport: TConnectTransport;
      Security: TDeviceSecurity; const Stage, SessionID, SessionToken: string);
    function AddEvidence(const EncodedChallenge: string;
      Document: TJSONObject): TAuthorityExtensionResult;
    function ApplyVerdict(const EncodedVerdict: string; ExpectedAccepted: Boolean): Boolean;
    procedure RetireObservation;
    procedure FlushSecurityReports(TimeoutMS: Cardinal = 3500);
  end;

implementation

uses
  System.SysUtils, System.Classes, System.NetEncoding, Cozy.Integrity,
  Cozy.NHW.Attestation.Transport,
  Cozy.NHW.ResponsePathMesh, Cozy.NHW.SessionTrustLadder, Cozy.NHW.Observer.Protocol;

const
  ChallengeFrameBytes = 60;
  CompactEvidenceFrameBytes = 179;
  VerdictFrameBytes = 93;
  ObservationFreshMilliseconds = 90000;

function DecodeFrame(const Encoded: string; ExpectedBytes: Integer;
  out Frame: TBytes): Boolean;
var Encoding: TBase64Encoding;
begin
  Frame := nil;
  Result := False;
  if Length(Encoded) <> ((ExpectedBytes + 2) div 3) * 4 then Exit;
  Encoding := TBase64Encoding.Create(0);
  try
    try
      Frame := Encoding.DecodeStringToBytes(Encoded);
      Result := (Length(Frame) = ExpectedBytes) and
        (Encoding.EncodeBytesToString(Frame) = Encoded);
    except
      Result := False;
    end;
  finally
    if not Result then WipeBytes(Frame);
    Encoding.Free;
  end;
end;

function EncodeFrame(const Frame: TBytes): string;
var Encoding: TBase64Encoding;
begin
  Encoding := TBase64Encoding.Create(0);
  try
    Result := Encoding.EncodeBytesToString(Frame);
  finally
    Encoding.Free;
  end;
end;

function FreshReceipt(const Receipt, Response: TResponsePathEvent;
  Channel: TResponsePathChannel; Digest, ObservedAt, NowTick: UInt64): Boolean;
begin
  Result := (Receipt.Channel = Channel) and (Response.Channel = Channel) and
    (Receipt.Sequence <> 0) and (Receipt.Sequence = Response.Sequence) and
    (Receipt.Tick <> 0) and (Receipt.Tick = Response.Tick) and
    (Receipt.Tick <= ObservedAt) and (Receipt.Tick <= NowTick) and
    (NowTick - Receipt.Tick <= ObservationFreshMilliseconds) and
    (Receipt.Digest <> 0) and (Receipt.Digest = Response.Digest) and
    (Receipt.Digest = Digest);
end;

procedure AddReceipt(Document: TJSONObject; const Name: string;
  const Event: TResponsePathEvent);
var Value: TJSONObject;
begin
  Value := TJSONObject.Create;
  try
    Value.AddPair('sequence', IntToHex(Int64(Event.Sequence), 16).ToLower);
    Value.AddPair('tick', IntToHex(Int64(Event.Tick), 16).ToLower);
    Value.AddPair('digest', IntToHex(Int64(Event.Digest), 16).ToLower);
    Document.AddPair(Name, Value);
    Value := nil;
  finally
    Value.Free;
  end;
end;

constructor TCozyNHWAuthority.Create(const Reader: TCozyNHWKernelReader;
  const PathReader: TCozyNHWResponseReader;
  const ServerStop: TCozyNHWResponseStopped; DetectionGuard: TCozyNHWGuard);
begin
  inherited Create;
  FReader := Reader;
  FPathReader := PathReader;
  FServerStop := ServerStop;
  FDetectionGuard := DetectionGuard;
  FReplay := TSessionEpochGuard.Create;
  FInvalidation := TSessionInvalidationLatch.Create;
end;

destructor TCozyNHWAuthority.Destroy;
var Channel: TResponsePathChannel;
begin
  for Channel := Low(TResponsePathChannel) to High(TResponsePathChannel) do
    if FResponses[Channel] <> nil then FResponses[Channel].RequestStop;
  for Channel := Low(TResponsePathChannel) to High(TResponsePathChannel) do
    FreeAndNil(FResponses[Channel]);
  FQuoteProvider := nil;
  RetireObservation;
  FInvalidation.Free;
  FReplay.Free;
  FReader := nil; FPathReader := nil; FServerStop := nil;
  FDetectionGuard := nil;
  inherited Destroy;
end;

procedure TCozyNHWAuthority.SetQuoteProvider(const Quoter: ICozyTpmQuoter);
begin
  FQuoteProvider := Quoter;
end;

procedure TCozyNHWAuthority.ConfigureResponses(Transport: TConnectTransport;
  Security: TDeviceSecurity; const Stage, SessionID, SessionToken: string);
var
  Channel: TResponsePathChannel;
  Context: string;
begin
  if (Transport = nil) or (Security = nil) then
    raise EArgumentException.Create('NHW_RESPONSE_CONTEXT_INVALID');
  Context := IntegritySHA512Text(Transport.BindingID + '|' + Security.DeviceID +
    '|' + Stage + '|' + SessionID + '|' + SessionToken);
  if (FResponseContext <> '') and (FResponseContext <> Context) then
    raise EArgumentException.Create('NHW_RESPONSE_CONTEXT_CHANGED');
  if FDetectionGuard<>nil then FDetectionGuard.SecurityContext.BindSession(SessionID);
  FResponseContext := Context;
  if not Assigned(FPathReader) then Exit;
  for Channel := Low(TResponsePathChannel) to High(TResponsePathChannel) do
    if FResponses[Channel] = nil then
    begin
      try
        FResponses[Channel] := TCozyNHWResponseChannel.Create(Transport, Security,
          FPathReader,
          Channel, Stage, SessionID, SessionToken, FServerStop, FDetectionGuard);
        FResponses[Channel].Start;
      except
        { Resource/network setup failure is unknown. Each other path is still
          attempted and the unavailable channel can retry on the next call. }
        FreeAndNil(FResponses[Channel]);
      end;
    end;
end;

procedure TCozyNHWAuthority.RetireObservation;
begin
  { A missing response retires only this attempt. The session's replay window
    and authenticated rejection latch survive retries and transport failures. }
  FreeAndNil(FPending);
end;

function TCozyNHWAuthority.AddEvidence(const EncodedChallenge: string;
  Document: TJSONObject): TAuthorityExtensionResult;
var
  Challenge: TAttestationChallengeFrame;
  State: TCozyNHWKernelState;
  Evidence: TServerAttestationEvidence;
  Frame, BootLog, QuoteInput, QuoteDigest: TBytes;
  NowTick: UInt64;
  Responses, Quote: TJSONObject;
begin
  Challenge := Default(TAttestationChallengeFrame);
  Evidence := Default(TServerAttestationEvidence);
  State := Default(TCozyNHWKernelState);
  try
  RetireObservation;
  Result := aerInvalid;
  if FInvalidation.Invalidated or (Document = nil) then Exit;
  if not DecodeFrame(EncodedChallenge, ChallengeFrameBytes, Frame) then Exit;
  try
    if not ParseAttestationChallengeFrame(Frame, Challenge) then Exit;
  finally
    WipeBytes(Frame);
  end;
  if (Challenge.ServerSequence <= FLastSequence) or
    not FReplay.AcceptChallenge(Challenge.Epoch, Challenge.Nonce) then Exit;
  FLastSequence := Challenge.ServerSequence;
  if FDetectionGuard <> nil then
    FDetectionGuard.NoteAttestationSequence(Challenge.ServerSequence);
  FInvalidation.BeginEpoch(Challenge.Epoch);

  Result := aerUnavailable;
  if not Assigned(FReader) then Exit;
  try
    if not FReader(State) then Exit;
  except
    Exit;
  end;
  NowTick := ObserverClockTick;
  if not State.BootIdentityValid or (State.Tick = 0) or (State.Tick > NowTick) or
    (NowTick - State.Tick > ObservationFreshMilliseconds) or
    ((State.VoteMask and $F8) <> 0) then Exit;
  if ((State.VoteMask and RESPONSE_VOTE_TRUST) <> 0) and not
    FreshReceipt(State.TrustReceipt, State.TrustResponse, rpcTrust,
      State.TrustDigest, State.Tick, NowTick) then Exit;
  if ((State.VoteMask and RESPONSE_VOTE_DRIVER) <> 0) and not
    FreshReceipt(State.DriverReceipt, State.DriverResponse, rpcDriver,
      State.DriverDigest, State.Tick, NowTick) then Exit;
  if ((State.VoteMask and RESPONSE_VOTE_INTEGRITY) <> 0) and not
    FreshReceipt(State.IntegrityReceipt, State.IntegrityResponse, rpcIntegrity,
      State.IntegrityDigest, State.Tick, NowTick) then Exit;

  FPending := TServerNonceAttestation.Create;
  if not FPending.BeginChallengeEx(Challenge.Epoch, Challenge.ServerSequence,
    Challenge.Nonce, NowTick) then Exit(aerInvalid);
  Responses := nil; Quote := nil;
  try
    if not FPending.BuildEvidence(State.BootIdentity, State.BootIdentityValid,
      State.SessionTrust, State.VoteMask, State.TrustDigest, State.DriverDigest,
      State.IntegrityDigest, NowTick, Evidence, BootLog) then Exit;
    { The compact wire frame retains the measured log size and digest. Raw WBCL
      stays local and never establishes hardware-backed identity by itself. }
    if not BuildAttestationEvidenceFrame(Evidence, nil, Frame) or
      (Length(Frame) <> CompactEvidenceFrameBytes) then Exit(aerInvalid);
    Responses := TJSONObject.Create;
    if (State.VoteMask and RESPONSE_VOTE_TRUST) <> 0 then
      AddReceipt(Responses, 'trust', State.TrustReceipt);
    if (State.VoteMask and RESPONSE_VOTE_DRIVER) <> 0 then
      AddReceipt(Responses, 'driver', State.DriverReceipt);
    if (State.VoteMask and RESPONSE_VOTE_INTEGRITY) <> 0 then
      AddReceipt(Responses, 'integrity', State.IntegrityReceipt);
    if FQuoteProvider <> nil then
    begin
      QuoteInput := TEncoding.UTF8.GetBytes('COZY-NHW-PCR-QUOTE-V1' + #0);
      SetLength(QuoteInput, Length(QuoteInput) + Length(Frame));
      if Length(Frame) > 0 then
        Move(Frame[0], QuoteInput[Length(QuoteInput) - Length(Frame)], Length(Frame));
      QuoteDigest := DeviceSHA256(QuoteInput);
      if FQuoteProvider.TryQuote(QuoteDigest, Quote) then
      begin
        if Quote = nil then Exit(aerInvalid);
        Document.AddPair('nhwQuote', Quote);
        Quote := nil;
      end;
    end;
    Document.AddPair('nhwEvidence', EncodeFrame(Frame));
    Document.AddPair('nhwResponses', Responses);
    Responses := nil;
    if State.SessionInvalidated and (State.SessionTrust = kstUntrusted) and
      State.ResponseQuorum and ResponsePathQuorum(State.VoteMask) then
      Document.AddPair('nhwInvalidated', TJSONBool.Create(True));
    Result := aerAdded;
  finally
    WipeBytes(BootLog);
    WipeBytes(Frame); WipeBytes(QuoteInput); WipeBytes(QuoteDigest);
    Quote.Free; Responses.Free;
  end;
  finally
    FillChar(Challenge, SizeOf(Challenge), 0);
    FillChar(Evidence, SizeOf(Evidence), 0);
    FillChar(State, SizeOf(State), 0);
    WipeBytes(BootLog); WipeBytes(Frame);
    WipeBytes(QuoteInput); WipeBytes(QuoteDigest);
  end;
end;

function TCozyNHWAuthority.ApplyVerdict(const EncodedVerdict: string;
  ExpectedAccepted: Boolean): Boolean;
var
  Frame: TBytes;
  Verdict: TAttestationVerdictFrame;
  Tick: UInt64;
begin
  Verdict := Default(TAttestationVerdictFrame);
  try
  Result := False;
  if (FPending = nil) or FInvalidation.Invalidated then Exit;
  if not DecodeFrame(EncodedVerdict, VerdictFrameBytes, Frame) then Exit;
  try
    if not ParseAttestationVerdictFrame(Frame, Verdict) or
      (Verdict.Accepted <> ExpectedAccepted) then Exit;
    Tick := ObserverClockTick;
    if not FPending.ApplyVerdictEx(Verdict.Epoch, Verdict.ServerSequence,
      Verdict.Nonce, Verdict.BindingDigest, Verdict.Accepted, Tick) then Exit;
    FInvalidation.ApplyServerVerdict(Verdict.Epoch, Verdict.Accepted, Tick);
    Result := True;
  finally
    WipeBytes(Frame);
  end;
  finally
    FillChar(Verdict, SizeOf(Verdict), 0);
    WipeBytes(Frame);
  end;
end;

procedure TCozyNHWAuthority.FlushSecurityReports(TimeoutMS: Cardinal);
var Channel: TResponsePathChannel; Started: UInt64; Pending: Boolean;
begin
  if TimeoutMS > 7000 then TimeoutMS := 7000;
  Started := ObserverClockTick;
  for Channel := Low(TResponsePathChannel) to High(TResponsePathChannel) do
    if FResponses[Channel] <> nil then FResponses[Channel].WakeForFlush;
  try
  repeat
    Pending := False;
    for Channel := Low(TResponsePathChannel) to High(TResponsePathChannel) do
      if (FResponses[Channel] <> nil) and FResponses[Channel].HasPending then
        Pending := True;
    if not Pending or (ObserverClockTick - Started >= TimeoutMS) then Exit;
    { Never pump UI callbacks or re-enter authority while stopping. The three
      response workers own their transports and continue independently. }
    TThread.Sleep(10);
  until False;
  finally
    for Channel := Low(TResponsePathChannel) to High(TResponsePathChannel) do
      if FResponses[Channel] <> nil then FResponses[Channel].EndFlush;
  end;
end;

end.
