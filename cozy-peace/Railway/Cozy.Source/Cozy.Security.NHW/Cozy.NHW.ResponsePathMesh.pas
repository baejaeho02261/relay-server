unit Cozy.NHW.ResponsePathMesh;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Cozy.NHW.Logging,
  Cozy.NHW.ResponsePath.Trust,
  Cozy.NHW.ResponsePath.Driver,
  Cozy.NHW.ResponsePath.Integrity,
  Cozy.NHW.ResponsePath.Dispatch;

const
  RESPONSE_VOTE_TRUST = $01;
  RESPONSE_VOTE_DRIVER = $02;
  RESPONSE_VOTE_INTEGRITY = $04;

type
  TResponsePathMesh = class
  private
    FTrust: TTrustResponsePath;
    FDriver: TDriverResponsePath;
    FIntegrity: TIntegrityResponsePath;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Observe(const Kinds: TDetectionKinds; Tick: UInt64);
    procedure SetLocalSinks(TrustSink, DriverSink, IntegritySink: TResponsePathSink);
    procedure SetSinks(TrustSink, DriverSink, IntegritySink: TResponsePathSink);
    function VoteMask(Tick: UInt64): Byte;
    function Quorum(Tick: UInt64): Boolean;
    function TrustDigest: UInt64;
    function DriverDigest: UInt64;
    function IntegrityDigest: UInt64;
    procedure ReadProducerReceipts(out Trust, Driver, Integrity: TResponsePathEvent);
  end;

function ResponsePathQuorum(VoteMask: Byte): Boolean;

implementation

function ResponsePathQuorum(VoteMask: Byte): Boolean;
var N: Integer;
begin
  N := 0;
  if (VoteMask and RESPONSE_VOTE_TRUST) <> 0 then Inc(N);
  if (VoteMask and RESPONSE_VOTE_DRIVER) <> 0 then Inc(N);
  if (VoteMask and RESPONSE_VOTE_INTEGRITY) <> 0 then Inc(N);
  Result := N >= 2;
end;

constructor TResponsePathMesh.Create;
begin
  inherited Create;
  FTrust := TTrustResponsePath.Create;
  FDriver := TDriverResponsePath.Create;
  FIntegrity := TIntegrityResponsePath.Create;
end;

destructor TResponsePathMesh.Destroy;
begin
  FIntegrity.Free;
  FDriver.Free;
  FTrust.Free;
  inherited Destroy;
end;

procedure TResponsePathMesh.Reset;
begin
  FTrust.Reset;
  FDriver.Reset;
  FIntegrity.Reset;
end;

procedure TResponsePathMesh.SetLocalSinks(TrustSink, DriverSink,
  IntegritySink: TResponsePathSink);
begin
  FTrust.SetLocalSink(TrustSink);
  FDriver.SetLocalSink(DriverSink);
  FIntegrity.SetLocalSink(IntegritySink);
end;

procedure TResponsePathMesh.SetSinks(TrustSink, DriverSink,
  IntegritySink: TResponsePathSink);
begin
  FTrust.SetSink(TrustSink);
  FDriver.SetSink(DriverSink);
  FIntegrity.SetSink(IntegritySink);
end;

procedure TResponsePathMesh.Observe(const Kinds: TDetectionKinds;
  Tick: UInt64);
begin
  FTrust.Observe(Kinds, Tick);
  FDriver.Observe(Kinds, Tick);
  FIntegrity.Observe(Kinds, Tick);
end;

function TResponsePathMesh.VoteMask(Tick: UInt64): Byte;
begin
  Result := 0;
  if FTrust.Fresh(Tick) then Result := Result or RESPONSE_VOTE_TRUST;
  if FDriver.Fresh(Tick) then Result := Result or RESPONSE_VOTE_DRIVER;
  if FIntegrity.Fresh(Tick) then Result := Result or RESPONSE_VOTE_INTEGRITY;
end;

function TResponsePathMesh.Quorum(Tick: UInt64): Boolean;
begin
  Result := ResponsePathQuorum(VoteMask(Tick));
end;

function TResponsePathMesh.TrustDigest: UInt64;
begin
  Result := FTrust.Digest;
end;

function TResponsePathMesh.DriverDigest: UInt64;
begin
  Result := FDriver.Digest;
end;

function TResponsePathMesh.IntegrityDigest: UInt64;
begin
  Result := FIntegrity.Digest;
end;

procedure TResponsePathMesh.ReadProducerReceipts(out Trust, Driver,
  Integrity: TResponsePathEvent);
begin
  Trust.Channel := rpcTrust;
  Trust.Sequence := FTrust.Sequence;
  Trust.Tick := FTrust.LastTick;
  Trust.Digest := FTrust.Digest;
  Driver.Channel := rpcDriver;
  Driver.Sequence := FDriver.Sequence;
  Driver.Tick := FDriver.LastTick;
  Driver.Digest := FDriver.Digest;
  Integrity.Channel := rpcIntegrity;
  Integrity.Sequence := FIntegrity.Sequence;
  Integrity.Tick := FIntegrity.LastTick;
  Integrity.Digest := FIntegrity.Digest;
end;

end.
