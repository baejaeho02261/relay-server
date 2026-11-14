unit Cozy.NHW.ResponsePath.Driver;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Cozy.NHW.Logging, Cozy.NHW.ResponsePath.Dispatch;

type
  TDriverResponsePath = class
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

constructor TDriverResponsePath.Create;
begin
  inherited Create;
  Reset;
end;

procedure TDriverResponsePath.Reset;
begin
  FSequence := 0;
  FLastTick := 0;
  FDigest := UInt64($D6E8FEB86659FD93);
end;

procedure TDriverResponsePath.SetLocalSink(Sink: TResponsePathSink);
begin
  FLocalSink := Sink;
end;

procedure TDriverResponsePath.SetSink(Sink: TResponsePathSink);
begin
  FSink := Sink;
end;

procedure TDriverResponsePath.Observe(const Kinds: TDetectionKinds; Tick: UInt64);
var E: TResponsePathEvent;
begin
  if (Kinds * [dkVulnerableDriver, dkDriverIdentity, dkDriverCrossView,
      dkDriverTimelineKernel, dkSystemViewDisagreement,
      dkKernelMappingEvidence, dkDriverLoadProvenance,
      dkDriverSignerAttestation, dkDriverServiceTimeline]) = [] then Exit;
  if (FLastTick <> 0) and (Tick <= FLastTick) then Exit;
  Inc(FSequence);
  FLastTick := Tick;
  FDigest := (FDigest + Tick + (FSequence shl 3)) xor UInt64($A0761D6478BD642F);
  FDigest := FDigest * UInt64($E7037ED1A0B428DB);
  E.Channel := rpcDriver;
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

function TDriverResponsePath.Fresh(Tick: UInt64): Boolean;
begin
  Result := (FLastTick <> 0) and (Tick >= FLastTick) and
    (Tick - FLastTick <= RESPONSE_FRESH_MS);
end;

end.
