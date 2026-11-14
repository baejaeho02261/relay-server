unit Cozy.NHW.ResponseSink.Driver;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Cozy.NHW.ResponsePath.Dispatch;

type
  TDriverLocalResponseSink = class
  private
    FLastSequence: UInt64;
    FLastTick: UInt64;
    FLastDigest: UInt64;
    FLatched: Boolean;
  public
    procedure Reset;
    procedure Receive(const Event: TResponsePathEvent);
    function Fresh(Tick, WindowMS: UInt64): Boolean;
    property Latched: Boolean read FLatched;
    property LastSequence: UInt64 read FLastSequence;
    property LastTick: UInt64 read FLastTick;
    property LastDigest: UInt64 read FLastDigest;
  end;

implementation

procedure TDriverLocalResponseSink.Reset;
begin
  FLastSequence := 0;
  FLastTick := 0;
  FLastDigest := 0;
  FLatched := False;
end;

procedure TDriverLocalResponseSink.Receive(const Event: TResponsePathEvent);
begin
  if Event.Channel <> rpcDriver then Exit;
  if (Event.Sequence = 0) or (Event.Tick = 0) or (Event.Digest = 0) then Exit;
  if (FLastSequence <> 0) and (Event.Sequence <= FLastSequence) then Exit;
  if (FLastTick <> 0) and (Event.Tick <= FLastTick) then Exit;
  FLastSequence := Event.Sequence;
  FLastTick := Event.Tick;
  FLastDigest := Event.Digest;
  FLatched := True;
end;

function TDriverLocalResponseSink.Fresh(Tick, WindowMS: UInt64): Boolean;
begin
  Result := FLatched and (FLastTick <> 0) and (Tick >= FLastTick) and
    (Tick - FLastTick <= WindowMS);
end;

end.
