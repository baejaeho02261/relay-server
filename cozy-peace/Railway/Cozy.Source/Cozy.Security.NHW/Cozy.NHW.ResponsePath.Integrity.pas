unit Cozy.NHW.ResponsePath.Integrity;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Cozy.NHW.Logging, Cozy.NHW.ResponsePath.Dispatch;

type
  TIntegrityResponsePath = class
  private
    FSequence: UInt64;
    FLastTick: UInt64;
    FDigest: UInt64;
    FLocalSink: TResponsePathSink;
    FSink: TResponsePathSink;
  public
    constructor Create;
    procedure Reset;
    procedure Observe(const Kinds: TDetectionKinds; Tick: UInt64);
    procedure SetLocalSink(Sink: TResponsePathSink);
    procedure SetSink(Sink: TResponsePathSink);
    function Fresh(Tick: UInt64): Boolean;
    property Sequence: UInt64 read FSequence;
    property LastTick: UInt64 read FLastTick;
    property Digest: UInt64 read FDigest;
  end;

implementation

const RESPONSE_FRESH_MS = 90000;

constructor TIntegrityResponsePath.Create;
begin
  inherited Create;
  Reset;
end;

procedure TIntegrityResponsePath.Reset;
begin
  FSequence := 0;
  FLastTick := 0;
  FDigest := UInt64($94D049BB133111EB);
end;

procedure TIntegrityResponsePath.SetLocalSink(Sink: TResponsePathSink);
begin
  FLocalSink := Sink;
end;

procedure TIntegrityResponsePath.SetSink(Sink: TResponsePathSink);
begin
  FSink := Sink;
end;

procedure TIntegrityResponsePath.Observe(const Kinds: TDetectionKinds; Tick: UInt64);
var E: TResponsePathEvent;
begin
  if (Kinds * [dkCodeIntegrityPolicy, dkCodeIntegrityEventCorrelation,
      dkKernelTelemetryGap, dkSessionTrustUntrusted,
      dkDriverSignerAttestation, dkKernelDMAIOMMUTrust]) = [] then Exit;
  if (FLastTick <> 0) and (Tick <= FLastTick) then Exit;
  Inc(FSequence);
  FLastTick := Tick;
  FDigest := FDigest xor (Tick + UInt64($9E3779B97F4A7C15) +
    (FSequence shl 6) + (FSequence shr 2));
  FDigest := FDigest * UInt64($BF58476D1CE4E5B9);
  E.Channel := rpcIntegrity;
  E.Sequence := FSequence;
  E.Tick := Tick;
  E.Digest := FDigest;
  if Assigned(FLocalSink) then
    try
      FLocalSink(E);
    except
      // Local response paths are isolated from the evidence producer.
    end;
  if Assigned(FSink) then
    try
      FSink(E);
    except
      // External integration failures must not corrupt local evidence.
    end;
end;

function TIntegrityResponsePath.Fresh(Tick: UInt64): Boolean;
begin
  Result := (FLastTick <> 0) and (Tick >= FLastTick) and
    (Tick - FLastTick <= RESPONSE_FRESH_MS);
end;

end.
