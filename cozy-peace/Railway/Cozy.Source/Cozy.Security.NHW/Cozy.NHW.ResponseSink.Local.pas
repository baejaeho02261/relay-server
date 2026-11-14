unit Cozy.NHW.ResponseSink.Local;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Cozy.NHW.ResponsePath.Dispatch,
  Cozy.NHW.ResponseSink.Trust,
  Cozy.NHW.ResponseSink.Driver,
  Cozy.NHW.ResponseSink.Integrity;

type
  TLocalResponseSinkSet = class
  private
    FTrust: TTrustLocalResponseSink;
    FDriver: TDriverLocalResponseSink;
    FIntegrity: TIntegrityLocalResponseSink;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure TrustReceive(const Event: TResponsePathEvent);
    procedure DriverReceive(const Event: TResponsePathEvent);
    procedure IntegrityReceive(const Event: TResponsePathEvent);
    function VoteMask(Tick: UInt64): Byte;
    function Quorum(Tick: UInt64): Boolean;
    procedure ReadReceipts(out Trust, Driver, Integrity: TResponsePathEvent);
  end;

implementation

const
  LOCAL_RESPONSE_FRESH_MS = 90000;
  LOCAL_VOTE_TRUST = $01;
  LOCAL_VOTE_DRIVER = $02;
  LOCAL_VOTE_INTEGRITY = $04;

constructor TLocalResponseSinkSet.Create;
begin
  inherited Create;
  FTrust := TTrustLocalResponseSink.Create;
  FDriver := TDriverLocalResponseSink.Create;
  FIntegrity := TIntegrityLocalResponseSink.Create;
  Reset;
end;

destructor TLocalResponseSinkSet.Destroy;
begin
  FIntegrity.Free;
  FDriver.Free;
  FTrust.Free;
  inherited Destroy;
end;

procedure TLocalResponseSinkSet.Reset;
begin
  FTrust.Reset;
  FDriver.Reset;
  FIntegrity.Reset;
end;

procedure TLocalResponseSinkSet.TrustReceive(const Event: TResponsePathEvent);
begin
  FTrust.Receive(Event);
end;

procedure TLocalResponseSinkSet.DriverReceive(const Event: TResponsePathEvent);
begin
  FDriver.Receive(Event);
end;

procedure TLocalResponseSinkSet.IntegrityReceive(const Event: TResponsePathEvent);
begin
  FIntegrity.Receive(Event);
end;

function TLocalResponseSinkSet.VoteMask(Tick: UInt64): Byte;
begin
  Result := 0;
  if FTrust.Fresh(Tick, LOCAL_RESPONSE_FRESH_MS) then
    Result := Result or LOCAL_VOTE_TRUST;
  if FDriver.Fresh(Tick, LOCAL_RESPONSE_FRESH_MS) then
    Result := Result or LOCAL_VOTE_DRIVER;
  if FIntegrity.Fresh(Tick, LOCAL_RESPONSE_FRESH_MS) then
    Result := Result or LOCAL_VOTE_INTEGRITY;
end;

function TLocalResponseSinkSet.Quorum(Tick: UInt64): Boolean;
var
  Mask: Byte;
  N: Integer;
begin
  Mask := VoteMask(Tick);
  N := 0;
  if (Mask and LOCAL_VOTE_TRUST) <> 0 then Inc(N);
  if (Mask and LOCAL_VOTE_DRIVER) <> 0 then Inc(N);
  if (Mask and LOCAL_VOTE_INTEGRITY) <> 0 then Inc(N);
  Result := N >= 2;
end;

procedure TLocalResponseSinkSet.ReadReceipts(out Trust, Driver,
  Integrity: TResponsePathEvent);
begin
  Trust.Channel := rpcTrust;
  Trust.Sequence := FTrust.LastSequence;
  Trust.Tick := FTrust.LastTick;
  Trust.Digest := FTrust.LastDigest;
  Driver.Channel := rpcDriver;
  Driver.Sequence := FDriver.LastSequence;
  Driver.Tick := FDriver.LastTick;
  Driver.Digest := FDriver.LastDigest;
  Integrity.Channel := rpcIntegrity;
  Integrity.Sequence := FIntegrity.LastSequence;
  Integrity.Tick := FIntegrity.LastTick;
  Integrity.Digest := FIntegrity.LastDigest;
end;

end.
